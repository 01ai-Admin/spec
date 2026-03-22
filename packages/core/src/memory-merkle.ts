/**
 * CADENCE Memory Vault Merkle Tree — tamper-detection for agent memory vaults.
 *
 * Provides a single SHA-256 Merkle root over the canonical memory entries
 * (persistentEntries + verifiedEntries) of an AgentMemoryVault. The root can be
 * embedded in both the vault file and the agent's AgentId record so that any deletion,
 * mutation, or reordering of approved memories is immediately detectable.
 *
 * Design decisions:
 *   - operationalCache is EXCLUDED — it is ephemeral session context, not part of
 *     the agent's durable identity. Only persistentEntries and verifiedEntries are
 *     covered by the tree.
 *   - Leaf hash: SHA-256 of the stable content fields of a MemoryEntry —
 *     entryId, vaultId, instanceId, layer, type, summary, fingerprint, createdAt.
 *     Mutable housekeeping fields (updatedAt, embeddingIndexKey, tags) are included
 *     so that any approved edit to a tag or reference also changes the root. If you
 *     need tags to be excluded from integrity coverage, remove them from leafFields.
 *   - Determinism: entries are sorted by entryId (UUID) before building the tree.
 *     Same set of entries in any insertion order → same root.
 *   - Tree construction: standard binary Merkle tree. If the number of leaves is odd,
 *     the last leaf is duplicated (Bitcoin-style). Empty vault → well-known empty root
 *     (SHA-256 of the empty string).
 *   - All hashes are lowercase hex strings (64 chars).
 *
 * Storage:
 *   - vault file:  AgentMemoryVault.merkleRoot (string | undefined)
 *   - AgentId record:  AgentId.memoryMerkleRoot (string | undefined) — updated each time the
 *     vault is compacted or a memory is approved/revoked, then the AgentId is re-signed.
 *
 * No external dependencies — only node:crypto.
 */

import { createHash } from "node:crypto";
import type { MemoryEntry, VerifiedMemory } from "@01ai/types";

// ─── Internal SHA-256 primitive ───────────────────────────────────────────────

function sha256hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ─── Leaf hash ────────────────────────────────────────────────────────────────

/**
 * Canonical leaf hash for a single MemoryEntry (or VerifiedMemory).
 *
 * All fields that constitute the approved content of the entry are included.
 * The serialisation is deterministic: fields are listed in alphabetical key order
 * and values are JSON-encoded, then the whole object is JSON-stringified.
 *
 * Fields covered:
 *   createdAt, dedupeFingerprint (VerifiedMemory only), entryId, fingerprint,
 *   instanceId, layer, sourceProjectRef, sourceTaskRef, summary, tags, type,
 *   updatedAt, vaultId
 *
 * Fields deliberately excluded:
 *   embeddingIndexKey — opaque runtime index handle, not content
 *   memoryUnits, verificationScore, verificationStatus, reviewerId, verifierId,
 *   approvedAt — provenance metadata, not the memory content itself
 */
export function hashMemoryLeaf(entry: MemoryEntry | VerifiedMemory): string {
  // Build a deterministic canonical object — alphabetical key order
  const canonical: Record<string, unknown> = {
    createdAt: entry.createdAt,
    entryId: entry.entryId,
    fingerprint: entry.fingerprint,
    instanceId: entry.instanceId,
    layer: entry.layer,
    sourceProjectRef: entry.sourceProjectRef ?? null,
    sourceTaskRef: entry.sourceTaskRef ?? null,
    summary: entry.summary,
    tags: [...entry.tags].sort(), // sort tags so order doesn't matter
    type: entry.type,
    updatedAt: entry.updatedAt,
    vaultId: entry.vaultId
  };

  // VerifiedMemory adds dedupeFingerprint — include it if present
  if ("dedupeFingerprint" in entry) {
    canonical["dedupeFingerprint"] = (entry as VerifiedMemory).dedupeFingerprint;
  }

  return sha256hex(JSON.stringify(canonical));
}

// ─── Tree construction ────────────────────────────────────────────────────────

/**
 * Combine two child hashes into a parent hash.
 * The two hex strings are concatenated (left then right) before hashing.
 * This matches the standard Merkle convention used in Bitcoin and similar systems.
 */
function combineHashes(left: string, right: string): string {
  return sha256hex(left + right);
}

/**
 * The canonical root returned for an empty vault — SHA-256 of the empty string.
 * Using a well-known sentinel means callers can distinguish "no entries" from
 * "one entry that happens to hash to something unexpected".
 */
export const EMPTY_MERKLE_ROOT: string = sha256hex("");

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Compute the Merkle root over a flat list of MemoryEntry / VerifiedMemory objects.
 *
 * Call this with the concatenation of vault.persistentEntries and vault.verifiedEntries:
 *
 *   const root = computeMemoryMerkleRoot([
 *     ...vault.persistentEntries,
 *     ...vault.verifiedEntries
 *   ]);
 *
 * The entries are sorted by entryId before building the tree so the result is
 * independent of the order they are stored in the vault arrays.
 *
 * Returns EMPTY_MERKLE_ROOT when the list is empty.
 */
export function computeMemoryMerkleRoot(entries: (MemoryEntry | VerifiedMemory)[]): string {
  if (entries.length === 0) {
    return EMPTY_MERKLE_ROOT;
  }

  // Sort by entryId for determinism regardless of vault insertion order
  const sorted = [...entries].sort((a, b) => a.entryId.localeCompare(b.entryId));

  // Build the initial leaf layer
  let layer: string[] = sorted.map(hashMemoryLeaf);

  // Reduce upward until a single root remains
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      // If there is no right sibling, duplicate the left leaf (odd-leaf convention)
      const right = layer[i + 1] ?? left;
      next.push(combineHashes(left, right));
    }
    layer = next;
  }

  return layer[0];
}

// ─── Merkle Proof ─────────────────────────────────────────────────────────────

/**
 * A sibling hash at each level of the tree, paired with a position flag so the
 * verifier knows whether the sibling is to the left or right of the path node.
 */
export type MerkleProofStep = {
  /** The sibling hash at this level. */
  sibling: string;
  /** Whether the sibling is to the LEFT of the current path node. */
  siblingIsLeft: boolean;
};

/**
 * A Merkle inclusion proof for a single MemoryEntry.
 *
 * Carry this alongside the entry when exporting agent bundles or when attesting
 * that a specific memory was present in the vault at the time the root was signed.
 */
export type MerkleProof = {
  /** entryId of the entry this proof is for. */
  entryId: string;
  /** The leaf hash of the entry (= hashMemoryLeaf(entry)). */
  leafHash: string;
  /** Ordered list of sibling hashes from leaf level up to (but not including) the root. */
  steps: MerkleProofStep[];
  /** The Merkle root this proof was generated against. */
  root: string;
};

/**
 * Generate a MerkleProof for a single entry from the full entry list.
 *
 * Returns `null` if the entry is not found in the list (identified by entryId).
 *
 * Usage:
 *   const proof = generateMerkleProof(entry, [...vault.persistentEntries, ...vault.verifiedEntries]);
 *   // store proof alongside the exported entry
 */
export function generateMerkleProof(
  target: MemoryEntry | VerifiedMemory,
  allEntries: (MemoryEntry | VerifiedMemory)[]
): MerkleProof | null {
  if (allEntries.length === 0) return null;

  const sorted = [...allEntries].sort((a, b) => a.entryId.localeCompare(b.entryId));
  let layer: string[] = sorted.map(hashMemoryLeaf);

  // Find the index of our target entry in the sorted order
  const targetIndex = sorted.findIndex((e) => e.entryId === target.entryId);
  if (targetIndex === -1) return null;

  const leafHash = layer[targetIndex];
  const root = computeMemoryMerkleRoot(allEntries);
  const steps: MerkleProofStep[] = [];

  let currentIndex = targetIndex;

  while (layer.length > 1) {
    const isRightChild = currentIndex % 2 === 1;
    const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;

    // If there is no right sibling at this level, the node was paired with itself
    const siblingHash = siblingIndex < layer.length ? layer[siblingIndex] : layer[currentIndex];

    steps.push({
      sibling: siblingHash,
      siblingIsLeft: isRightChild // sibling is to the left when we are a right child
    });

    // Build next layer
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] ?? layer[i];
      next.push(combineHashes(left, right));
    }

    layer = next;
    currentIndex = Math.floor(currentIndex / 2);
  }

  return { entryId: target.entryId, leafHash, steps, root };
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify that a MemoryEntry is included in the vault state represented by `root`.
 *
 * This is used in two scenarios:
 *   1. Spot-checking a single memory during a session without reloading the whole vault.
 *   2. Verifying exported agent bundles — the bundle carries the AgentId (which embeds the
 *      root) and a proof per exported memory.
 *
 * Returns `true` only if:
 *   - The entry's canonical leaf hash matches proof.leafHash.
 *   - The proof path reconstructs exactly to `root`.
 *   - The proof.root field matches the provided `root` argument.
 *
 * Any discrepancy means the entry was tampered with, was not part of the vault when
 * the root was computed, or the root itself has been forged.
 */
export function verifyMemoryEntry(
  entry: MemoryEntry | VerifiedMemory,
  proof: MerkleProof,
  root: string
): boolean {
  // Guard: the proof must be for this entry and against the root we are checking
  if (proof.entryId !== entry.entryId) return false;
  if (proof.root !== root) return false;

  // Recompute the leaf hash from the live entry and compare to the proof
  const computedLeaf = hashMemoryLeaf(entry);
  if (computedLeaf !== proof.leafHash) return false;

  // Walk up the tree using the proof steps
  let current = computedLeaf;
  for (const step of proof.steps) {
    current = step.siblingIsLeft
      ? combineHashes(step.sibling, current)
      : combineHashes(current, step.sibling);
  }

  // The reconstructed root must match exactly
  return current === root;
}

// ─── Vault-level helpers ──────────────────────────────────────────────────────

/**
 * Compute the Merkle root for an entire vault in one call.
 *
 * Combines persistentEntries and verifiedEntries; operationalCache is excluded.
 *
 * Example:
 *   const root = computeVaultMerkleRoot(vault);
 *   // store in vault.merkleRoot and in agentId.memoryMerkleRoot before re-signing
 */
export function computeVaultMerkleRoot(vault: {
  persistentEntries: MemoryEntry[];
  verifiedEntries: VerifiedMemory[];
}): string {
  return computeMemoryMerkleRoot([...vault.persistentEntries, ...vault.verifiedEntries]);
}

/**
 * Verify the stored merkleRoot field of a vault against its current entry contents.
 *
 * Returns `true` if the vault has not been tampered with since the root was recorded.
 * Returns `false` if any entry has been added, removed, or mutated, or if the stored
 * root is missing.
 */
export function verifyVaultIntegrity(vault: {
  persistentEntries: MemoryEntry[];
  verifiedEntries: VerifiedMemory[];
  merkleRoot?: string;
}): boolean {
  if (!vault.merkleRoot) return false;
  const recomputed = computeVaultMerkleRoot(vault);
  return recomputed === vault.merkleRoot;
}

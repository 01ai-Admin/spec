/**
 * CADENCE Identity Engine — cryptographic minting and verification for agent instances.
 *
 * Implements the CADENCE-AgentId-Identity-Memory-Builder-Spec:
 *   - entropy               random 32-char hex seed, unique per mint
 *   - originHash            SHA-256(templateId:editionId:mintedAt)
 *   - capabilityFingerprint SHA-256(sorted capabilities, comma-joined)
 *   - behaviorFingerprint   SHA-256(systemPrompt || sorted constraints)
 *   - integrityChecksum     SHA-256 of all non-signature AgentId fields (canonical JSON)
 *   - signature             Ed25519 signature over the integrityChecksum
 *   - signedDigest          SHA-256 of the fully signed AgentId record — first 8 chars (upper) = visible 01iD label
 *
 * Following guidance from:
 *   agents-orchestrator     — phased pipeline, quality gates before advancement
 *   agentic-identity-trust  — zero-trust default, cryptographic proof chain
 *   identity-graph-operator — deterministic canonical identity, cache before re-mint
 */

import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify
} from "node:crypto";
import type { AgentId, TrustStore, VerificationResult, MemoryMode } from "@01ai/types";

// ─── SHA-256 primitive ────────────────────────────────────────────────────────

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// ─── Entropy & Nonces ─────────────────────────────────────────────────────────

/** Generate a 32-char hex entropy seed (16 random bytes). Never reuse. */
export function generateEntropy(): string {
  return randomBytes(16).toString("hex");
}

/** Generate a 16-char hex mint nonce (8 random bytes). */
export function generateMintNonce(): string {
  return randomBytes(8).toString("hex");
}

// ─── Fingerprint Computation ──────────────────────────────────────────────────

/**
 * SHA-256 of "templateId:editionId:mintedAt".
 * Ties this instance irrevocably to its template, edition, and moment of minting.
 */
export function computeOriginHash(
  templateId: string,
  editionId: string,
  mintedAt: string
): string {
  return sha256(`${templateId}:${editionId}:${mintedAt}`);
}

/**
 * SHA-256 of alphabetically sorted capabilities, comma-joined.
 * Sort order is canonical — changing capability order after minting breaks this hash.
 */
export function computeCapabilityFingerprint(capabilities: string[]): string {
  return sha256([...capabilities].sort().join(","));
}

/**
 * SHA-256 of the system prompt concatenated with alphabetically sorted constraints.
 * Captures the behavioral contract of the agent.
 */
export function computeBehaviorFingerprint(
  systemPrompt: string,
  constraints: string[]
): string {
  const sortedConstraints = [...constraints].sort().join(";");
  return sha256(`${systemPrompt}||${sortedConstraints}`);
}

/**
 * Deterministic sub-seeds derived from entropy for trait, style, and chemistry.
 * Each seed is 16 hex chars — a labeled derivation of the master entropy.
 */
function deriveSeed(entropy: string, label: string): string {
  return sha256(`${label}:${entropy}`).slice(0, 16);
}

/**
 * SHA-256 of canonically sorted JSON of all non-signature fields.
 * This is signed by Ed25519 — any field mutation invalidates the signature.
 */
export function computeIntegrityChecksum(fields: Record<string, unknown>): string {
  const sorted = Object.fromEntries(Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)));
  return sha256(JSON.stringify(sorted));
}

/**
 * SHA-256 of the complete signed AgentId record (including signature).
 * First 8 chars uppercased = visible 01iD label shown on agent card (e.g., "01iD A3F7B291").
 */
export function computeSignedDigest(agentId: AgentId): string {
  const sorted = Object.fromEntries(Object.entries(agentId).sort(([a], [b]) => a.localeCompare(b)));
  return sha256(JSON.stringify(sorted));
}

/** Format the 8-char visible 01iD label from a signed record. */
export function formatIdentityLabel(agentId: AgentId): string {
  return `01iD ${computeSignedDigest(agentId).slice(0, 8).toUpperCase()}`;
}

// ─── Ed25519 Key Management ───────────────────────────────────────────────────

export type KeyPair = {
  publicKeyHex: string;
  privateKeyHex: string;
  signerId: string;
};

/** Generate a fresh Ed25519 keypair for workspace-local signing. */
export function generateSigningKeypair(signerId: string): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" }
  });
  return {
    publicKeyHex: (publicKey as Buffer).toString("hex"),
    privateKeyHex: (privateKey as Buffer).toString("hex"),
    signerId
  };
}

// ─── Sign / Verify ────────────────────────────────────────────────────────────

function signHex(message: string, privateKeyHex: string): string {
  const privateKeyDer = Buffer.from(privateKeyHex, "hex");
  const sig = cryptoSign(null, Buffer.from(message, "utf8"), {
    key: privateKeyDer,
    format: "der",
    type: "pkcs8"
  });
  return (sig as Buffer).toString("hex");
}

function verifyHex(message: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const publicKeyDer = Buffer.from(publicKeyHex, "hex");
    return cryptoVerify(
      null,
      Buffer.from(message, "utf8"),
      { key: publicKeyDer, format: "der", type: "spki" },
      Buffer.from(signatureHex, "hex")
    );
  } catch {
    return false;
  }
}

// ─── Minting ──────────────────────────────────────────────────────────────────

export type MintParams = {
  templateId: string;
  editionId: string;
  templateAgentId: string;
  systemPrompt: string;
  capabilities: string[];
  constraints?: string[];
  memoryMode?: MemoryMode;
  keypair: KeyPair;
};

/**
 * Mint a new 01iD record for an agent instance.
 *
 * Phase order (agents-orchestrator pattern — no phase is skipped):
 *   1. Generate entropy + nonce + timestamps
 *   2. Compute all content fingerprints
 *   3. Build the pre-signature record and compute integrityChecksum
 *   4. Sign the integrityChecksum with Ed25519
 *   5. Compute signedDigest over the complete record
 */
export function mintAgentId(params: MintParams): AgentId {
  const {
    templateId,
    editionId,
    templateAgentId,
    systemPrompt,
    capabilities,
    constraints = [],
    memoryMode = "always_on",
    keypair
  } = params;

  const entropy = generateEntropy();
  const mintNonce = generateMintNonce();
  const mintedAt = new Date().toISOString();
  const instanceId = `inst_${entropy.slice(0, 8)}_${templateAgentId}`;

  const originHash = computeOriginHash(templateId, editionId, mintedAt);
  const capabilityFingerprint = computeCapabilityFingerprint(capabilities);
  const behaviorFingerprint = computeBehaviorFingerprint(systemPrompt, constraints);
  const traitSeed = deriveSeed(entropy, "trait");
  const styleSeed = deriveSeed(entropy, "style");
  const chemistrySeed = deriveSeed(entropy, "chemistry");

  // Build pre-signature record for integrity checksum
  const preSignature: Omit<AgentId, "signature"> = {
    version: "1.0",
    namespace: "cadence",
    kind: "agent",
    templateId,
    editionId,
    instanceId,
    issuerId: "01ai",
    signerId: keypair.signerId,
    signerTrust: "workspace_local",
    createdAt: mintedAt,
    mintNonce,
    entropy,
    originHash,
    capabilityFingerprint,
    behaviorFingerprint,
    integrityChecksum: "", // filled below
    traitSeed,
    styleSeed,
    chemistrySeed,
    memoryMode,
    signatureAlgorithm: "ed25519",
    signerPublicKey: keypair.publicKeyHex,
    trustLevel: "local",
    evolutionCounter: 0,
    parentInstanceIds: [],
    parentChecksums: []
  };

  // Compute checksum over all pre-signature fields (excluding integrityChecksum itself)
  const { integrityChecksum: _skip, ...fieldsForChecksum } = preSignature;
  const integrityChecksum = computeIntegrityChecksum(
    fieldsForChecksum as Record<string, unknown>
  );

  preSignature.integrityChecksum = integrityChecksum;

  // Sign the integrityChecksum
  const signature = signHex(integrityChecksum, keypair.privateKeyHex);

  const agentIdPartial: AgentId = { ...preSignature, signature };
  const signedDigest = computeSignedDigest(agentIdPartial);
  return { ...agentIdPartial, signedDigest };
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify an AgentId record against a trust store.
 *
 * Following agentic-identity-trust's zero-trust default:
 *   - If signer is blocked → "tampered"
 *   - If signature is invalid → "tampered"
 *   - If integrityChecksum doesn't match recomputed value → "tampered"
 *   - If signer found in trustRoots → "trusted"
 *   - If signer found in trustedIntermediates → "verified"
 *   - Otherwise (workspace_local, no store entry) → "local"
 */
export function verifyIdentity(agentId: AgentId, trustStore?: TrustStore): VerificationResult {
  // Phase 1: blocklist check (identity-graph-operator: flag before resolving)
  if (trustStore?.blockedSigners.includes(agentId.signerId)) {
    return { ok: false, trustLevel: "tampered", reason: "signer is blocked" };
  }

  // Phase 2: recompute integrityChecksum and verify it matches
  const { integrityChecksum, signature, ...fieldsForChecksum } = agentId;
  const recomputed = computeIntegrityChecksum(fieldsForChecksum as Record<string, unknown>);
  if (recomputed !== integrityChecksum) {
    return { ok: false, trustLevel: "tampered", reason: "integrityChecksum mismatch" };
  }

  // Phase 3: verify Ed25519 signature — find public key in trust store
  const allEntries = [
    ...(trustStore?.trustRoots ?? []),
    ...(trustStore?.trustedIntermediates ?? [])
  ];
  const entry = allEntries.find((e) => e.signerId === agentId.signerId);

  if (entry) {
    const sigOk = verifyHex(integrityChecksum, signature, entry.publicKey);
    if (!sigOk) {
      return { ok: false, trustLevel: "tampered", reason: "signature invalid" };
    }
    const trustLevel = trustStore?.trustRoots.some((e) => e.signerId === agentId.signerId)
      ? "trusted"
      : "verified";
    return { ok: true, trustLevel };
  }

  // No entry in trust store — workspace_local signer, cannot verify externally
  // Trust level is "local" — valid for this workspace, not portable
  return { ok: true, trustLevel: "local" };
}

// ─── Self-contained verification ─────────────────────────────────────────────

/**
 * Verify an AgentId record using only the data inside the file itself.
 * No trust store, no network, no running app required.
 *
 * Two-phase check:
 *   Phase 1 — content integrity: recompute integrityChecksum from all non-signature
 *             fields and compare to the stored value. Any field edit breaks this.
 *   Phase 2 — signature validity: verify the Ed25519 signature using the public key
 *             embedded in the record itself. An attacker cannot forge a valid
 *             signature without the private key (kept in Electron secure storage).
 *
 * For bred agents, also verifies that parentChecksums has one entry per parentInstanceId.
 * Full lineage chain verification (loading parent files) is handled separately.
 */
export function verifyAgentId(agentId: AgentId): VerificationResult {
  const { integrityChecksum, signature, signerPublicKey, signedDigest, ...coreFields } = agentId;

  if (!integrityChecksum || !signature || !signerPublicKey) {
    return { ok: false, trustLevel: "tampered", reason: "missing required verification fields" };
  }

  // Phase 1: recompute checksum from all content fields
  const recomputed = computeIntegrityChecksum(coreFields as Record<string, unknown>);
  if (recomputed !== integrityChecksum) {
    return { ok: false, trustLevel: "tampered", reason: "integrityChecksum mismatch — content was modified" };
  }

  // Phase 2: verify Ed25519 signature using the embedded public key
  const sigOk = verifyHex(integrityChecksum, signature, signerPublicKey);
  if (!sigOk) {
    return { ok: false, trustLevel: "tampered", reason: "signature invalid — private key mismatch or file forged" };
  }

  // Lineage integrity check: bred agents must have matching parent arrays
  if (agentId.parentInstanceIds.length !== agentId.parentChecksums.length) {
    return { ok: false, trustLevel: "tampered", reason: "parentInstanceIds and parentChecksums length mismatch" };
  }

  return { ok: true, trustLevel: "local" };
}

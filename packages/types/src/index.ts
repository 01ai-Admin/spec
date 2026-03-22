/**
 * @01ai/types — 01 Protocol type definitions
 *
 * Zod schemas and TypeScript types for the 01 Protocol:
 * persistent AI agent identity (01iD), lifecycle state machine,
 * memory vault, and cryptographic verification.
 *
 * These are the canonical definitions. CADENCE imports from here.
 */

import { z } from "zod";

// ─── Memory Foundation ────────────────────────────────────────────────────────

export const VerificationStatusSchema = z.enum([
  "unverified",
  "pending",
  "verified",
  "rejected",
  "flagged",
  "system-verified"
]);

export const MemoryLayerSchema = z.enum([
  "operational-cache",
  "persistent-vault"
]);

export const MemoryEntryTypeSchema = z.enum([
  "summary",
  "task-context",
  "project-history",
  "decision",
  "achievement",
  "learning",
  "note"
]);

export const MemoryEntrySchema = z.object({
  entryId: z.string().min(1),
  vaultId: z.string().min(1),
  instanceId: z.string().min(1),
  layer: MemoryLayerSchema,
  type: MemoryEntryTypeSchema,
  summary: z.string().min(1),
  fingerprint: z.string().min(1),
  sourceProjectRef: z.string().optional(),
  sourceTaskRef: z.string().optional(),
  tags: z.array(z.string()).default([]),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
  embeddingIndexKey: z.string().optional()
});

export const VerifiedMemorySchema = MemoryEntrySchema.extend({
  verificationStatus: VerificationStatusSchema,
  verificationScore: z.number().min(0).max(1),
  dedupeFingerprint: z.string().min(1),
  reviewerId: z.string().optional(),
  verifierId: z.string().optional(),
  approvedAt: z.string().optional(),
  memoryUnits: z.number().int().nonnegative().default(0)
});

export const AgentMemoryVaultSchema = z.object({
  vaultId: z.string().min(1),
  instanceId: z.string().min(1),
  operationalCache: z.array(MemoryEntrySchema).default([]),
  persistentEntries: z.array(MemoryEntrySchema).default([]),
  verifiedEntries: z.array(VerifiedMemorySchema).default([]),
  memoryStats: z.object({
    totalEntries: z.number().int().nonnegative().default(0),
    verifiedEntries: z.number().int().nonnegative().default(0),
    verifiedMemoryUnits: z.number().int().nonnegative().default(0),
    dedupeCount: z.number().int().nonnegative().default(0)
  }),
  embeddingIndexKeys: z.array(z.string()).default([]),
  createdAt: z.string().min(1),
  updatedAt: z.string().min(1),
  lastCompactedAt: z.string().optional(),
  /** SHA-256 Merkle root over persistentEntries + verifiedEntries. */
  merkleRoot: z.string().optional()
});

// ─── 01iD Core Identity ───────────────────────────────────────────────────────

export const MemoryModeSchema = z.enum([
  "always_on",
  "never_on",
  "toggleable"
]);

export const TrustLevelSchema = z.enum([
  "unverified",
  "local",
  "verified",
  "trusted",
  "flagged",
  "tampered"
]);

export const SignerTrustSchema = z.enum([
  "system",
  "verified_community",
  "workspace_local",
  "unknown"
]);

/**
 * 01iD — the persistent identity record for a 01 Agent.
 * Stored as a `.01ai` file. Self-verifying: signerPublicKey embedded,
 * no external trust store required.
 */
export const AgentIdSchema = z.object({
  version: z.literal("1.0"),
  namespace: z.string().min(1),
  kind: z.literal("agent"),

  templateId: z.string().min(1),
  editionId: z.string().min(1),
  instanceId: z.string().min(1),

  issuerId: z.string().min(1),
  signerId: z.string().min(1),
  signerTrust: SignerTrustSchema,

  createdAt: z.string().min(1),
  mintNonce: z.string().min(1),
  entropy: z.string().min(1),

  originHash: z.string().min(1),
  capabilityFingerprint: z.string().min(1),
  behaviorFingerprint: z.string().min(1),
  integrityChecksum: z.string().min(1),

  traitSeed: z.string().min(1),
  styleSeed: z.string().min(1),
  chemistrySeed: z.string().min(1),

  memoryMode: MemoryModeSchema,

  signatureAlgorithm: z.literal("ed25519"),
  /** Ed25519 public key (DER/SPKI hex) — embedded for self-contained verification. */
  signerPublicKey: z.string().min(1),
  signature: z.string().min(1),

  trustLevel: TrustLevelSchema,

  evolutionCounter: z.number().int().nonnegative().default(0),
  evolutionRoot: z.string().optional(),
  /** Instance IDs of parent agents. Empty for genesis mints. */
  parentInstanceIds: z.array(z.string()).default([]),
  /** integrityChecksum of each parent at breeding time — lineage chain verification. */
  parentChecksums: z.array(z.string()).default([]),
  /** SHA-256 of the complete signed 01iD record. First 8 chars = visible identifier. */
  signedDigest: z.string().optional(),
  /** Merkle root of the agent's memory vault at last signing. */
  memoryMerkleRoot: z.string().optional()
});

export const TrustStoreEntrySchema = z.object({
  signerId: z.string().min(1),
  algorithm: z.literal("ed25519"),
  publicKey: z.string().min(1)
});

export const TrustStoreSchema = z.object({
  trustRoots: z.array(TrustStoreEntrySchema).default([]),
  trustedIntermediates: z.array(TrustStoreEntrySchema).default([]),
  blockedSigners: z.array(z.string()).default([])
});

export const VerificationResultSchema = z.object({
  ok: z.boolean(),
  trustLevel: TrustLevelSchema,
  reason: z.string().optional()
});

// ─── Lifecycle State Machine ──────────────────────────────────────────────────

export const IdentityStateSchema = z.enum([
  "UNINITIALIZED",  // Minted but not yet activated
  "ACTIVE",         // Normal operating state
  "FROZEN",         // Suspended — resumes exactly from freeze point
  "ARCHIVED",       // Read-only historical record
  "TRANSFERRING",   // In-flight ownership transfer — locked
  "DELETED"         // Terminal — cryptographic tombstone
]);

export const IdentityTransitionReasonSchema = z.enum([
  "initial_activation",
  "user_freeze",
  "system_freeze",
  "resume_from_freeze",
  "archive",
  "unarchive",
  "transfer_initiated",
  "transfer_completed",
  "transfer_cancelled",
  "deletion_requested",
  "admin_override"
]);

export const IdentityTransitionEventSchema = z.object({
  seq: z.number().int().positive(),
  fromState: IdentityStateSchema,
  toState: IdentityStateSchema,
  reason: IdentityTransitionReasonSchema,
  transitionedAt: z.string().min(1),
  authorizedBy: z.string().min(1),
  /** Hash chaining this event to the previous — reordering/deletion is detectable. */
  eventHash: z.string().min(1),
  previousEventHash: z.string().nullable(),
  meta: z.record(z.unknown()).optional()
});

export const FreezeContextSchema = z.object({
  freezeSchemaVersion: z.literal("1.0"),
  frozenAt: z.string().min(1),
  evolutionCounterAtFreeze: z.number().int().nonnegative(),
  memoryVaultChecksum: z.string().min(1),
  memoryVaultSnapshotId: z.string().min(1),
  xpAtFreeze: z.number().int().nonnegative(),
  progressChecksumAtFreeze: z.string().min(1),
  lastSessionId: z.string().nullable(),
  sessionStateChecksum: z.string().nullable(),
  frozenBySignerId: z.string().min(1),
  /** SHA-256 seal over all freeze context fields — any edit breaks this. */
  freezeContextIntegrity: z.string().min(1)
});

export const TransferContextSchema = z.object({
  transferSchemaVersion: z.literal("1.0"),
  initiatedAt: z.string().min(1),
  destinationWorkspaceId: z.string().min(1),
  sourceWorkspaceId: z.string().min(1),
  transferNonce: z.string().min(1),
  expiresAt: z.string().min(1),
  transferContextIntegrity: z.string().min(1)
});

export const DeletionReceiptSchema = z.object({
  receiptSchemaVersion: z.literal("1.0"),
  instanceId: z.string().min(1),
  /** integrityChecksum from the destroyed genesis 01iD — ties receipt to exact lineage. */
  genesisIntegrityChecksum: z.string().min(1),
  genesisSignedDigest: z.string().min(1),
  evolutionCounterAtDeletion: z.number().int().nonnegative(),
  deletedAt: z.string().min(1),
  deletedBySignerId: z.string().min(1),
  receiptSignerPublicKey: z.string().min(1),
  deletionReason: z.string().optional(),
  receiptIntegrityHash: z.string().min(1),
  receiptSignature: z.string().min(1),
  memoryVaultZeroed: z.boolean(),
  vaultChecksumAtDeletion: z.string().nullable()
});

export const IdentityEnvelopeSchema = z.object({
  envelopeSchemaVersion: z.literal("1.0"),
  /** The full immutable genesis 01iD record. NEVER mutated after minting. */
  genesis: AgentIdSchema,
  state: IdentityStateSchema,
  /** Append-only transition history. Hash-chained — reordering or deletion is detectable. */
  transitionHistory: z.array(IdentityTransitionEventSchema).default([]),
  /** Populated only when state === "FROZEN". */
  freezeContext: FreezeContextSchema.nullable().default(null),
  /** Populated only when state === "TRANSFERRING". */
  transferContext: TransferContextSchema.nullable().default(null),
  /** Populated only when state === "DELETED". This envelope becomes a tombstone. */
  deletionReceipt: DeletionReceiptSchema.nullable().default(null),
  stateChangedAt: z.string().min(1),
  stateChangedBy: z.string().min(1),
  /** SHA-256 of mutable envelope fields — separately signed, genesis.signature never touched. */
  envelopeChecksum: z.string().min(1),
  envelopeSignature: z.string().min(1),
  envelopeSignerPublicKey: z.string().min(1)
});

// ─── Type exports ─────────────────────────────────────────────────────────────

export type VerificationStatus = z.infer<typeof VerificationStatusSchema>;
export type MemoryLayer = z.infer<typeof MemoryLayerSchema>;
export type MemoryEntryType = z.infer<typeof MemoryEntryTypeSchema>;
export type MemoryEntry = z.infer<typeof MemoryEntrySchema>;
export type VerifiedMemory = z.infer<typeof VerifiedMemorySchema>;
export type AgentMemoryVault = z.infer<typeof AgentMemoryVaultSchema>;

export type MemoryMode = z.infer<typeof MemoryModeSchema>;
export type TrustLevel = z.infer<typeof TrustLevelSchema>;
export type SignerTrust = z.infer<typeof SignerTrustSchema>;
export type AgentId = z.infer<typeof AgentIdSchema>;
export type TrustStoreEntry = z.infer<typeof TrustStoreEntrySchema>;
export type TrustStore = z.infer<typeof TrustStoreSchema>;
export type VerificationResult = z.infer<typeof VerificationResultSchema>;

export type IdentityState = z.infer<typeof IdentityStateSchema>;
export type IdentityTransitionReason = z.infer<typeof IdentityTransitionReasonSchema>;
export type IdentityTransitionEvent = z.infer<typeof IdentityTransitionEventSchema>;
export type FreezeContext = z.infer<typeof FreezeContextSchema>;
export type TransferContext = z.infer<typeof TransferContextSchema>;
export type DeletionReceipt = z.infer<typeof DeletionReceiptSchema>;
export type IdentityEnvelope = z.infer<typeof IdentityEnvelopeSchema>;

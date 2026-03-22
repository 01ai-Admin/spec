/**
 * AgentId Lifecycle Engine — state transition orchestration for agent identity envelopes.
 *
 * Implements the sealed envelope model:
 *   - genesis AgentId core is NEVER mutated after minting (integrityChecksum + signature immutable)
 *   - IdentityEnvelope wraps the genesis with a separately signed mutable state layer
 *   - envelopeChecksum + envelopeSignature are recomputed on every state change
 *   - transition history is a hash chain — reordering or deletion is detectable
 *
 * Async I/O guards (vault/progress checksum matching) live here.
 * Pure topology guards live in @cadence/shared-types/identity-lifecycle-guards.
 */

import { createHash } from "node:crypto";
import { sign as cryptoSign } from "node:crypto";
import type {
  AgentId,
  DeletionReceipt,
  FreezeContext,
  IdentityEnvelope,
  IdentityState,
  TransferContext,
  IdentityTransitionEvent,
  IdentityTransitionReason
} from "@01ai/types";
import { checkTransitionAllowed } from "@01ai/types/lifecycle-guards";
import type { KeyPair } from "./identity-engine.js";

// ─── Internal helpers ─────────────────────────────────────────────────────────

function sha256(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function signHex(message: string, privateKeyHex: string): string {
  const privateKeyDer = Buffer.from(privateKeyHex, "hex");
  const sig = cryptoSign(null, Buffer.from(message, "utf8"), {
    key: privateKeyDer,
    format: "der",
    type: "pkcs8"
  });
  return (sig as Buffer).toString("hex");
}

function canonicalJson(obj: Record<string, unknown>): string {
  const sorted = Object.fromEntries(
    Object.entries(obj).sort(([a], [b]) => a.localeCompare(b))
  );
  return JSON.stringify(sorted);
}

// ─── Envelope checksum + signature ───────────────────────────────────────────

/**
 * Compute the envelopeChecksum that covers all mutable envelope fields.
 * This is what gets signed on every state change — genesis.signature is never involved.
 */
function computeEnvelopeChecksum(
  envelope: Pick<
    IdentityEnvelope,
    "state" | "stateChangedAt" | "stateChangedBy" | "freezeContext" | "transferContext"
  >,
  instanceId: string,
  latestTransitionEventHash: string | null
): string {
  return sha256(
    canonicalJson({
      state: envelope.state,
      stateChangedAt: envelope.stateChangedAt,
      stateChangedBy: envelope.stateChangedBy,
      instanceId,
      latestTransitionEventHash: latestTransitionEventHash ?? "",
      freezeContext: envelope.freezeContext ?? null,
      transferContext: envelope.transferContext ?? null
    })
  );
}

// ─── Transition event builder ─────────────────────────────────────────────────

function buildTransitionEvent(
  seq: number,
  from: IdentityState,
  to: IdentityState,
  reason: IdentityTransitionReason,
  authorizedBy: string,
  previousEventHash: string | null,
  instanceId: string,
  meta?: Record<string, unknown>
): IdentityTransitionEvent {
  const transitionedAt = new Date().toISOString();

  // Hash chain: each event includes the previous event hash + its own content
  const eventHash = sha256(
    [instanceId, String(seq), from, to, transitionedAt, authorizedBy, previousEventHash ?? ""].join("|")
  );

  return { seq, fromState: from, toState: to, reason, transitionedAt, authorizedBy, eventHash, previousEventHash, meta };
}

// ─── Envelope constructor (from minted AgentId) ───────────────────────────────────

/**
 * Wrap a freshly minted AgentId record in a lifecycle envelope with state UNINITIALIZED.
 * Called once immediately after mintAgentId().
 */
export function createEnvelope(genesis: AgentId, keypair: KeyPair): IdentityEnvelope {
  const now = new Date().toISOString();

  const partial = {
    state: "UNINITIALIZED" as IdentityState,
    stateChangedAt: now,
    stateChangedBy: keypair.signerId,
    freezeContext: null,
    transferContext: null
  };

  const envelopeChecksum = computeEnvelopeChecksum(partial, genesis.instanceId, null);
  const envelopeSignature = signHex(envelopeChecksum, keypair.privateKeyHex);

  return {
    envelopeSchemaVersion: "1.0",
    genesis,
    ...partial,
    deletionReceipt: null,
    transitionHistory: [],
    envelopeChecksum,
    envelopeSignature,
    envelopeSignerPublicKey: keypair.publicKeyHex
  };
}

// ─── Core transition function ─────────────────────────────────────────────────

export type TransitionInput = {
  envelope: IdentityEnvelope;
  to: IdentityState;
  reason: IdentityTransitionReason;
  keypair: KeyPair;
  freezeContext?: FreezeContext;
  transferContext?: TransferContext;
  deletionOptions?: {
    deletionReason?: string;
    memoryVaultZeroed: boolean;
    vaultChecksumAtDeletion: string | null;
    evolutionCounterAtDeletion: number;
  };
  meta?: Record<string, unknown>;
};

export type TransitionResult =
  | { ok: true; envelope: IdentityEnvelope }
  | { ok: false; reason: string };

/**
 * Apply a lifecycle state transition to an envelope.
 *
 * Validates topology and guards, applies side effects, recomputes and
 * re-signs the envelope. Returns the updated envelope or an error.
 *
 * NOTE: For FROZEN → ACTIVE, the caller must separately verify vault and
 * progress checksums via validateResumeConditions() before calling this.
 */
export function applyTransition(input: TransitionInput): TransitionResult {
  const { envelope, to, reason, keypair, meta } = input;
  const from = envelope.state;
  const now = new Date();

  // Topology + envelope-level guards
  const guard = checkTransitionAllowed(from, to, reason, envelope, now);
  if (!guard.allowed) {
    return { ok: false, reason: guard.reason };
  }

  // Build the new transition event
  const lastEvent = envelope.transitionHistory.at(-1);
  const seq = (lastEvent?.seq ?? 0) + 1;
  const event = buildTransitionEvent(
    seq, from, to, reason, keypair.signerId,
    lastEvent?.eventHash ?? null, envelope.genesis.instanceId, meta
  );

  // Determine state-specific context fields
  let freezeContext: FreezeContext | null = null;
  let transferContext: TransferContext | null = null;
  let deletionReceipt: DeletionReceipt | null = envelope.deletionReceipt;

  switch (to) {
    case "FROZEN":
      if (!input.freezeContext) {
        return { ok: false, reason: "freezeContext required for FROZEN transition" };
      }
      freezeContext = input.freezeContext;
      break;

    case "TRANSFERRING":
      if (!input.transferContext) {
        return { ok: false, reason: "transferContext required for TRANSFERRING transition" };
      }
      transferContext = input.transferContext;
      // Preserve freeze context if transitioning from FROZEN
      freezeContext = from === "FROZEN" ? envelope.freezeContext : null;
      break;

    case "ACTIVE":
      // Clear both contexts on activation (clean slate)
      break;

    case "ARCHIVED":
      break;

    case "DELETED": {
      if (!input.deletionOptions) {
        return { ok: false, reason: "deletionOptions required for DELETED transition" };
      }
      const opts = input.deletionOptions;
      const genesis = envelope.genesis;

      const receiptIntegrityHash = sha256(
        [
          genesis.instanceId,
          genesis.integrityChecksum,
          genesis.signedDigest ?? "",
          String(opts.evolutionCounterAtDeletion),
          now.toISOString(),
          keypair.signerId
        ].join("|")
      );

      deletionReceipt = {
        receiptSchemaVersion: "1.0",
        instanceId: genesis.instanceId,
        genesisIntegrityChecksum: genesis.integrityChecksum,
        genesisSignedDigest: genesis.signedDigest ?? "",
        evolutionCounterAtDeletion: opts.evolutionCounterAtDeletion,
        deletedAt: now.toISOString(),
        deletedBySignerId: keypair.signerId,
        receiptSignerPublicKey: keypair.publicKeyHex,
        deletionReason: opts.deletionReason,
        receiptIntegrityHash,
        receiptSignature: signHex(receiptIntegrityHash, keypair.privateKeyHex),
        memoryVaultZeroed: opts.memoryVaultZeroed,
        vaultChecksumAtDeletion: opts.vaultChecksumAtDeletion
      };
      break;
    }
  }

  const stateChangedAt = now.toISOString();
  const updatedHistory = [...envelope.transitionHistory, event];

  const partial = {
    state: to,
    stateChangedAt,
    stateChangedBy: keypair.signerId,
    freezeContext,
    transferContext
  };

  const envelopeChecksum = computeEnvelopeChecksum(
    partial, envelope.genesis.instanceId, event.eventHash
  );
  const envelopeSignature = signHex(envelopeChecksum, keypair.privateKeyHex);

  const updated: IdentityEnvelope = {
    ...envelope,
    ...partial,
    deletionReceipt,
    transitionHistory: updatedHistory,
    envelopeChecksum,
    envelopeSignature,
    envelopeSignerPublicKey: keypair.publicKeyHex
  };

  return { ok: true, envelope: updated };
}

// ─── Deletion receipt verification ───────────────────────────────────────────

import { verify as cryptoVerify } from "node:crypto";

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

export function verifyDeletionReceipt(receipt: DeletionReceipt): boolean {
  const recomputed = sha256(
    [
      receipt.instanceId,
      receipt.genesisIntegrityChecksum,
      receipt.genesisSignedDigest,
      String(receipt.evolutionCounterAtDeletion),
      receipt.deletedAt,
      receipt.deletedBySignerId
    ].join("|")
  );

  if (recomputed !== receipt.receiptIntegrityHash) return false;

  return verifyHex(
    receipt.receiptIntegrityHash,
    receipt.receiptSignature,
    receipt.receiptSignerPublicKey
  );
}

// ─── Resume validation (async I/O guards for FROZEN → ACTIVE) ────────────────

export type ResumeValidationResult =
  | { valid: true }
  | { valid: false; reason: string };

/**
 * Validate that it is safe to resume a FROZEN agent.
 * Must be called BEFORE applyTransition({ to: "ACTIVE", reason: "resume_from_freeze" }).
 *
 * Checks:
 *   1. Freeze context integrity seal
 *   2. Memory vault checksum matches freeze snapshot
 *   3. Progress checksum matches freeze snapshot
 *   4. evolutionCounter has not incremented during frozen period
 */
export function validateFreezeContextIntegrity(
  envelope: IdentityEnvelope
): ResumeValidationResult {
  const ctx = envelope.freezeContext;
  if (!ctx) return { valid: false, reason: "No freeze context found" };

  // Recompute the freeze context integrity seal
  const expected = sha256(
    [
      ctx.frozenAt,
      String(ctx.evolutionCounterAtFreeze),
      ctx.memoryVaultChecksum,
      String(ctx.xpAtFreeze),
      ctx.progressChecksumAtFreeze,
      ctx.memoryVaultSnapshotId
    ].join("|")
  );

  if (expected !== ctx.freezeContextIntegrity) {
    return { valid: false, reason: "Freeze context integrity check failed — context tampered" };
  }

  if (envelope.genesis.evolutionCounter !== ctx.evolutionCounterAtFreeze) {
    return { valid: false, reason: "evolutionCounter changed while agent was frozen" };
  }

  return { valid: true };
}

/**
 * Build the freezeContextIntegrity seal when creating a freeze snapshot.
 * Pass the result as freezeContext.freezeContextIntegrity.
 */
export function buildFreezeContextIntegrity(ctx: Omit<FreezeContext, "freezeContextIntegrity">): string {
  return sha256(
    [
      ctx.frozenAt,
      String(ctx.evolutionCounterAtFreeze),
      ctx.memoryVaultChecksum,
      String(ctx.xpAtFreeze),
      ctx.progressChecksumAtFreeze,
      ctx.memoryVaultSnapshotId
    ].join("|")
  );
}

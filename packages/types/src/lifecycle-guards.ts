/**
 * AgentId Lifecycle Transition Guards
 *
 * Pure validation logic — no I/O, no crypto. Checks whether a requested
 * state transition is topologically valid and satisfies envelope-level guards.
 *
 * Guards that require async I/O (vault checksum comparison, session lookup)
 * are handled separately in identity-lifecycle-engine.ts. These guards operate
 * only on data already present in the envelope.
 */

import type {
  IdentityEnvelope,
  IdentityState,
  IdentityTransitionReason
} from "./index.js";

export type TransitionGuardResult =
  | { allowed: true }
  | { allowed: false; reason: string };

// ─── Valid transition topology ────────────────────────────────────────────────

const VALID_TRANSITIONS = new Map<IdentityState, Set<IdentityState>>([
  ["UNINITIALIZED", new Set(["ACTIVE"])],
  ["ACTIVE",        new Set(["FROZEN", "ARCHIVED", "TRANSFERRING", "DELETED"])],
  ["FROZEN",        new Set(["ACTIVE", "ARCHIVED", "DELETED"])],
  ["ARCHIVED",      new Set(["ACTIVE", "DELETED"])],
  ["TRANSFERRING",  new Set(["ACTIVE"])], // cancel + complete both land on ACTIVE
  ["DELETED",       new Set()]            // terminal
]);

// ─── Guard function ───────────────────────────────────────────────────────────

/**
 * Check whether a state transition is allowed.
 *
 * Async I/O guards (vault/progress checksum matching) are NOT performed here —
 * the caller in identity-lifecycle-engine.ts must run those before applying the transition.
 *
 * @param from     Current state of the envelope
 * @param to       Requested target state
 * @param reason   Declared reason for the transition
 * @param envelope The full envelope (used for transfer context expiry, history consistency)
 * @param now      Current timestamp for expiry checks
 */
export function checkTransitionAllowed(
  from: IdentityState,
  to: IdentityState,
  reason: IdentityTransitionReason,
  envelope: IdentityEnvelope,
  now: Date
): TransitionGuardResult {

  // Guard 1: topology check
  if (!VALID_TRANSITIONS.get(from)?.has(to)) {
    return { allowed: false, reason: `No valid transition from ${from} to ${to}` };
  }

  // Guard 2: DELETED is terminal — belt and suspenders
  if (from === "DELETED") {
    return { allowed: false, reason: "DELETED is a terminal state — no transitions out" };
  }

  // Guard 3: TRANSFERRING → DELETED is blocked (cancel first to preserve audit trail)
  if (from === "TRANSFERRING" && to === "DELETED") {
    return {
      allowed: false,
      reason: "Cannot delete while TRANSFERRING — cancel transfer first"
    };
  }

  // Guard 4: TRANSFERRING → ACTIVE requires matching reason and non-expired context
  if (from === "TRANSFERRING" && to === "ACTIVE") {
    if (reason !== "transfer_completed" && reason !== "transfer_cancelled") {
      return {
        allowed: false,
        reason: "TRANSFERRING→ACTIVE requires reason transfer_completed or transfer_cancelled"
      };
    }
    if (reason === "transfer_completed" && envelope.transferContext) {
      if (new Date(envelope.transferContext.expiresAt) <= now) {
        return { allowed: false, reason: "Transfer has expired — cancel and re-initiate" };
      }
    }
  }

  // Guard 5: ARCHIVED → ACTIVE requires explicit unarchive intent
  if (from === "ARCHIVED" && to === "ACTIVE" && reason !== "unarchive") {
    return {
      allowed: false,
      reason: "ARCHIVED→ACTIVE requires reason=unarchive to prevent accidental reactivation"
    };
  }

  // Guard 6: FROZEN → ACTIVE requires a freeze context to exist
  if (from === "FROZEN" && to === "ACTIVE") {
    if (!envelope.freezeContext) {
      return { allowed: false, reason: "No freeze context — cannot verify safe resume" };
    }
    // Vault/progress checksum matching is done async in identity-lifecycle-engine.ts
  }

  // Guard 7: transition history consistency — last recorded toState must match current state
  const lastEvent = envelope.transitionHistory.at(-1);
  if (lastEvent && lastEvent.toState !== from) {
    return {
      allowed: false,
      reason: `History inconsistency: last toState=${lastEvent.toState} but current state=${from}`
    };
  }

  return { allowed: true };
}

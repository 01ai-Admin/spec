# 01 Protocol Specification
**Version:** 1.0.0
**Status:** Stable
**Patent:** Pending (US)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Definitions](#2-definitions)
3. [The .01ai File Format](#3-the-01ai-file-format)
4. [Canonical Serialization and Signing](#4-canonical-serialization-and-signing)
5. [Verification Algorithm](#5-verification-algorithm)
6. [Security Constraints and Input Guards](#6-security-constraints-and-input-guards)
7. [Lifecycle State Machine](#7-lifecycle-state-machine)
8. [Persistent Memory System](#8-persistent-memory-system)
9. [Memory Merkle Tree](#9-memory-merkle-tree)
10. [Platform Profiles](#10-platform-profiles)
11. [Transport Formats](#11-transport-formats)
12. [Extension Fields](#12-extension-fields)
13. [Compliance Levels](#13-compliance-levels)
14. [Test Vectors](#14-test-vectors)
15. [Changelog](#15-changelog)

---

## 1. Overview

The 01 Protocol defines a format for persistent, portable, cryptographically verifiable AI agent identity. The core artifact is the `.01ai` file — a JSON record that an agent carries across platforms, sessions, and runtimes.

### 1.1 Design Goals

- **Self-contained verification** — a `.01ai` file can be verified using only the file itself. No network call, no external registry, no trust service.
- **Platform agnosticism** — the format imposes no platform whitelist. Any system that implements this spec can instantiate and verify agents.
- **Persistent memory** — approved memory is cryptographically bound to agent identity via a Merkle root, making memory sets tamper-evident and portable.
- **Forward compatibility** — extension fields and versioning ensure files created today remain verifiable by future implementations.
- **Hostile input resistance** — all parsing requires input guards against malformed, oversized, or malicious input.

### 1.2 Core Guarantee

A `.01ai` file produced by any conforming implementation **must** verify correctly on any other conforming implementation. Verification is deterministic: given the same file, every correct verifier produces the same result.

---

## 2. Definitions

| Term | Definition |
|---|---|
| **Agent** | An AI system with a persistent 01 Protocol identity record |
| **AgentId** | The identity record — the core `.01ai` JSON object |
| **IdentityEnvelope** | The full lifecycle container wrapping an AgentId |
| **instanceId** | The agent's globally unique identifier (32-char lowercase hex) |
| **evolutionCounter** | Integer incremented on every signed update, creating a tamper-evident chain |
| **integrityChecksum** | SHA-256 hex digest of the canonical payload |
| **signature** | Ed25519 signature (128-char hex) over the integrityChecksum bytes |
| **signerPublicKey** | Ed25519 public key (64-char hex) embedded in the identity record |
| **memoryMerkleRoot** | SHA-256 Merkle root of approved memory entries, bound to agent identity |
| **lifecycle state** | The agent's current state in the lifecycle state machine |
| **platform profile** | Optional per-platform tuning hints that do not alter the signed record |
| **portable bundle** | A `.01bundle` file pairing an identity record with its memory vault |

---

## 3. The .01ai File Format

### 3.1 Required Fields

All conforming AgentId records MUST include the following fields:

| Field | Type | Constraints |
|---|---|---|
| `instanceId` | string | 32-char lowercase hex; globally unique |
| `name` | string | 1–256 chars; human-readable agent name |
| `descriptor` | string | 1–8000 chars; agent role and behavioral description |
| `lifecycleState` | string | One of the valid states (§7.1) |
| `evolutionCounter` | integer | ≥ 0; increments on every signed update |
| `createdAt` | string | ISO 8601 UTC timestamp; immutable after minting |
| `updatedAt` | string | ISO 8601 UTC timestamp; updated on every re-sign |
| `integrityChecksum` | string | 64-char lowercase hex (SHA-256 of canonical payload) |
| `signerPublicKey` | string | 64-char lowercase hex (Ed25519 public key) |
| `signature` | string | 128-char lowercase hex (Ed25519 signature over integrityChecksum bytes) |

### 3.2 Optional Fields

| Field | Type | Description |
|---|---|---|
| `memoryMerkleRoot` | string | SHA-256 Merkle root of approved memory entries; 64-char hex |
| `parentInstanceIds` | string[] | instanceIds of parent agents (max 256 entries) |
| `parentChecksums` | string[] | integrityChecksums of parent agents at transfer time (parallel array) |
| `platformProfiles` | object[] | Per-platform tuning hints (§10) |
| `formatVersion` | string | Spec version used at mint time (e.g. `"1.0.0"`) |

### 3.3 Extension Fields

Any field prefixed with `x-` is an extension field. Extension fields:
- Are preserved through verification and re-signing
- Are NOT included in the signed canonical payload
- MUST NOT conflict with required or optional field names
- Have max 64-char key names, max 8000-char string values

### 3.4 Example Record

```json
{
  "instanceId":        "a3f9c2e1b4d87650a3f9c2e1b4d87650",
  "name":              "ResearchAgent",
  "descriptor":        "Autonomous research agent specializing in technical documentation and source analysis",
  "lifecycleState":    "ACTIVE",
  "evolutionCounter":  12,
  "memoryMerkleRoot":  "8f3a1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
  "parentInstanceIds": [],
  "parentChecksums":   [],
  "createdAt":         "2026-01-14T09:00:00.000Z",
  "updatedAt":         "2026-03-01T14:22:10.000Z",
  "integrityChecksum": "<64-char sha256 hex>",
  "signerPublicKey":   "<64-char ed25519 public key hex>",
  "signature":         "<128-char ed25519 signature hex>",
  "formatVersion":     "1.0.0"
}
```

---

## 4. Canonical Serialization and Signing

### 4.1 Canonical Field Order

The canonical payload for signing uses a fixed field order. Fields MUST be included in this exact sequence:

```
1. instanceId
2. name
3. descriptor
4. lifecycleState
5. evolutionCounter
6. memoryMerkleRoot      (included as null if absent)
7. parentInstanceIds     (included as [] if absent)
8. parentChecksums       (included as [] if absent)
9. createdAt
```

Fields not in this list (optional fields, extension fields) are NOT included in the signed payload. This ensures the signature covers exactly the identity-defining fields.

### 4.2 Serialization Rules

1. Build an object containing only the canonical fields in the order above.
2. Serialize using `JSON.stringify` with no indentation and no trailing whitespace.
3. Encode as UTF-8.
4. Compute SHA-256 of the encoded bytes → this is the `integrityChecksum` (lowercase hex).
5. Sign the raw digest bytes (not the hex string) with Ed25519 → this is the `signature` (lowercase hex).

### 4.3 Signing Example (TypeScript)

```typescript
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 }  from '@noble/hashes/sha256';

function buildCanonicalPayload(agent: AgentId): Record<string, unknown> {
  return {
    instanceId:        agent.instanceId,
    name:              agent.name,
    descriptor:        agent.descriptor,
    lifecycleState:    agent.lifecycleState,
    evolutionCounter:  agent.evolutionCounter,
    memoryMerkleRoot:  agent.memoryMerkleRoot  ?? null,
    parentInstanceIds: agent.parentInstanceIds ?? [],
    parentChecksums:   agent.parentChecksums   ?? [],
    createdAt:         agent.createdAt,
  };
}

function signAgent(agent: AgentId, privateKeyBytes: Uint8Array): string {
  const payload  = JSON.stringify(buildCanonicalPayload(agent));
  const digest   = sha256(new TextEncoder().encode(payload));
  const sigBytes = ed25519.sign(digest, privateKeyBytes);
  return bytesToHex(sigBytes);
}
```

### 4.4 Re-signing on Update

Every modification to a signed field requires re-signing:

1. Apply the change (e.g. update `lifecycleState`, increment `evolutionCounter`, update `memoryMerkleRoot`).
2. Update `updatedAt` to the current UTC time.
3. Recompute the canonical payload.
4. Recompute `integrityChecksum`.
5. Recompute `signature`.

The `evolutionCounter` MUST be incremented by exactly 1 on every re-sign. Implementations that sign without incrementing the counter MUST be rejected.

---

## 5. Verification Algorithm

The verification algorithm is deterministic. Every conforming implementation MUST produce identical results for identical inputs.

### 5.1 Steps

```
Step 1: SIZE CHECK
  If byte length of input > 1,000,000: reject with TOO_LARGE

Step 2: PARSE
  Parse as JSON.
  If parse fails: reject with INVALID_JSON.
  Root value must be a plain object (not array, null, or primitive).

Step 3: DEPTH GUARD
  Recursively check JSON nesting depth.
  If any value exceeds depth 8: reject with DEPTH_EXCEEDED.

Step 4: FIELD GUARDS
  For every string value: if length > 8,000: reject with STRING_TOO_LONG.
  For every array value: if length > 256: reject with ARRAY_TOO_LONG.
  For every object value: if key count > 64: reject with TOO_MANY_KEYS.

Step 5: PROTOTYPE POLLUTION CHECK
  If any object key is __proto__, constructor, or prototype:
  reject with PROTOTYPE_POLLUTION.

Step 6: REQUIRED FIELD VALIDATION
  Verify all required fields (§3.1) are present.
  Verify field types match the schema.
  If any required field is missing or wrong type: reject.

Step 7: FORMAT VALIDATION
  instanceId:          must match /^[0-9a-f]{32}$/
  signerPublicKey:     must match /^[0-9a-f]{64}$/
  signature:           must match /^[0-9a-f]{128}$/
  integrityChecksum:   must match /^[0-9a-f]{64}$/
  evolutionCounter:    must be a non-negative integer
  createdAt, updatedAt: must be valid ISO 8601 strings
  lifecycleState:      must be one of the defined states (§7.1)

Step 8: CANONICAL PAYLOAD
  Build canonical payload per §4.1.
  Serialize and encode as UTF-8.
  Compute SHA-256 digest.

Step 9: CHECKSUM MATCH
  Compare computed digest (hex) against integrityChecksum field.
  If mismatch: reject with CHECKSUM_MISMATCH.

Step 10: SIGNATURE VERIFICATION
  Decode signerPublicKey from hex to bytes.
  Decode signature from hex to bytes.
  ed25519Verify(signatureBytes, digestBytes, publicKeyBytes)
  If verification fails: reject with SIGNATURE_INVALID.

Step 11: WARNINGS (non-fatal)
  Emit warning if: updatedAt < createdAt
  Emit warning if: createdAt more than 60 seconds in the future
  Emit warning if: evolutionCounter === 0 AND parentInstanceIds.length > 0
  Emit warning if: lifecycleState === "DELETED"

Step 12: RETURN
  { valid: true, agent: <parsed record>, warnings: string[] }
  or
  { valid: false, error: string, agent?: <partial record>, warnings: string[] }
```

### 5.2 Verification Example (TypeScript)

```typescript
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 }  from '@noble/hashes/sha256';

function verifyAgent(agent: AgentId): VerifyResult {
  const payload   = JSON.stringify(buildCanonicalPayload(agent));
  const digest    = sha256(new TextEncoder().encode(payload));
  const hexDigest = bytesToHex(digest);

  if (hexDigest !== agent.integrityChecksum) {
    return { valid: false, error: 'CHECKSUM_MISMATCH' };
  }

  const ok = ed25519.verify(
    hexToBytes(agent.signature),
    digest,
    hexToBytes(agent.signerPublicKey)
  );

  return ok
    ? { valid: true, agent, warnings: [] }
    : { valid: false, error: 'SIGNATURE_INVALID' };
}
```

---

## 6. Security Constraints and Input Guards

All conforming implementations — at any compliance level — MUST enforce the following input guards before processing any `.01ai` file:

### 6.1 Parsing Guards

| Guard | Limit | Error Code | Rationale |
|---|---|---|---|
| File size | 1,000,000 bytes | `TOO_LARGE` | Prevents memory exhaustion |
| JSON nesting depth | 8 levels | `DEPTH_EXCEEDED` | Prevents stack overflow on recursive parsers |
| String field length | 8,000 chars | `STRING_TOO_LONG` | Prevents memory abuse via large payloads |
| Array length | 256 elements | `ARRAY_TOO_LONG` | Prevents unbounded iteration |
| Object key count | 64 keys | `TOO_MANY_KEYS` | Prevents hash collision attacks |

### 6.2 Prototype Pollution Prevention

Implementations MUST reject any file containing the following keys at any depth:

- `__proto__`
- `constructor`
- `prototype`

Error code: `PROTOTYPE_POLLUTION`

### 6.3 Output Safety

Implementations that display agent identity records in a UI MUST:

- Render all field values as plain text — never as HTML, Markdown, or executable content.
- Display `instanceId` as a security fingerprint using only the first 8 hex characters. Do not display the full instanceId as a human-readable label (it is not human-meaningful and the truncated form resists Unicode homograph attacks).
- Never persist private keys to any storage — private keys are show-once at mint time only.
- Never display private keys in logs, error messages, or network responses.

### 6.4 Content Security

Implementations that serve the app over a web context MUST set strict Content Security Policy headers. Memory content is stored and rendered as structured data — never as executable code or interpreted markup.

---

## 7. Lifecycle State Machine

### 7.1 States

| State | Description |
|---|---|
| `UNINITIALIZED` | Record has been created but not yet activated |
| `ACTIVE` | Agent is operational |
| `FROZEN` | Agent is suspended; context preserved in `freezeContext` |
| `ARCHIVED` | Agent is retired but retrievable |
| `TRANSFERRING` | Agent identity is in transit to another platform or owner |
| `DELETED` | Agent has been permanently terminated (terminal state) |

### 7.2 Valid Transitions

| From | To | Valid Reasons |
|---|---|---|
| `UNINITIALIZED` | `ACTIVE` | `initial_activation` |
| `ACTIVE` | `FROZEN` | `user_freeze`, `system_freeze` |
| `ACTIVE` | `ARCHIVED` | `archive` |
| `ACTIVE` | `TRANSFERRING` | `transfer_initiated` |
| `ACTIVE` | `DELETED` | `deletion_requested`, `admin_override` |
| `FROZEN` | `ACTIVE` | `resume_from_freeze` |
| `FROZEN` | `ARCHIVED` | `archive` |
| `FROZEN` | `DELETED` | `deletion_requested`, `admin_override` |
| `ARCHIVED` | `ACTIVE` | `unarchive` |
| `ARCHIVED` | `DELETED` | `deletion_requested`, `admin_override` |
| `TRANSFERRING` | `ACTIVE` | `transfer_completed`, `transfer_cancelled` |
| `DELETED` | *(none)* | Terminal state — no outgoing transitions |

### 7.3 Transition Rules

1. `DELETED` is terminal. No transition from `DELETED` is ever valid.
2. `TRANSFERRING → DELETED` is blocked. A transfer must be completed or cancelled before deletion.
3. `TRANSFERRING → ACTIVE` requires reason `transfer_completed` or `transfer_cancelled` and a non-expired transfer context.
4. `FROZEN → ACTIVE` requires a `freezeContext` to be present in the envelope.
5. Every transition increments `evolutionCounter` and re-signs the record.
6. Transition history is append-only. The last recorded `toState` must equal the current `lifecycleState`.

### 7.4 Freeze Context

When an agent transitions to `FROZEN`, a `freezeContext` object is stored in the envelope:

| Field | Type | Description |
|---|---|---|
| `freezeSchemaVersion` | string | `"1.0"` |
| `frozenAt` | string | ISO 8601 UTC timestamp |
| `evolutionCounterAtFreeze` | integer | evolutionCounter at time of freeze |
| `memoryVaultChecksum` | string | SHA-256 of the memory vault at freeze time |
| `memoryVaultSnapshotId` | string | Identifier for the vault snapshot |
| `lastSessionId` | string \| null | Last active session identifier |
| `frozenBySignerId` | string | signerId of the entity that initiated the freeze |
| `freezeContextIntegrity` | string | SHA-256 of the freeze context fields |

### 7.5 Deletion Receipts

A `DeletionReceipt` provides cryptographic proof of authorized, intentional termination:

| Field | Type | Description |
|---|---|---|
| `receiptSchemaVersion` | string | `"1.0"` |
| `instanceId` | string | Matches the deleted agent's instanceId |
| `genesisIntegrityChecksum` | string | integrityChecksum of the original (genesis) record |
| `evolutionCounterAtDeletion` | integer | evolutionCounter at time of deletion |
| `deletedAt` | string | ISO 8601 UTC timestamp |
| `deletedBySignerId` | string | signerId of the entity that authorized deletion |
| `receiptSignerPublicKey` | string | 64-char hex Ed25519 public key |
| `memoryVaultZeroed` | boolean | Whether the memory vault was destroyed |
| `vaultChecksumAtDeletion` | string \| null | SHA-256 of vault at deletion, if not zeroed |
| `receiptIntegrityHash` | string | SHA-256 of the receipt fields |
| `receiptSignature` | string | Ed25519 signature over the receipt |

---

## 8. Persistent Memory System

### 8.1 Overview

The 01 Protocol memory system gives agents persistent, verifiable, and portable context. Memory is structured data — never executable code. All memory is inspectable, auditable, and revocable.

### 8.2 Memory Entry Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `entryId` | string | UUID format | Unique identifier for the entry |
| `vaultId` | string | UUID format | Identifier of the containing vault |
| `instanceId` | string | 32-char hex | Owner agent's instanceId |
| `layer` | string | enum | `"operational-cache"` or `"persistent-vault"` |
| `type` | string | enum | See §8.3 |
| `summary` | string | 1–8000 chars | The memory content |
| `fingerprint` | string | 64-char hex | SHA-256 of the `summary` field |
| `tags` | string[] | max 32 entries; each max 64 chars | Categorization tags |
| `createdAt` | string | ISO 8601 | Entry creation time |
| `updatedAt` | string | ISO 8601 | Last modification time |

### 8.3 Memory Types

| Type | Use Case |
|---|---|
| `summary` | High-level overview of agent capabilities or a topic area |
| `task-context` | A specific task, its goal, approach, constraints, and outcome |
| `project-history` | Accumulated knowledge about an ongoing project |
| `decision` | A specific decision and the reasoning behind it |
| `achievement` | A completed milestone or successful outcome |
| `learning` | A skill, technique, or domain insight the agent has acquired |
| `note` | A freeform annotation, preference, or contextual detail |

### 8.4 Memory Pipeline

```
Session transcript
      │
      ▼
[Extraction engine]
  Salience scoring per candidate:
  S = (α×Novelty + β×Engagement + γ×EntityWeight) × e^(−λ×t)
  α=0.4, β=0.35, γ=0.25, λ=0.5 (temporal decay)

  Novelty     = 1 − maxJaccardSimilarity(candidate, existingVault)
  Engagement  = lengthScore + questionBonus + decisionBonus + correctionBonus
  EntityWeight = properNounDensity×0.4 + numberDensity×0.3 + technicalScore×0.3

  Candidates below salience threshold are discarded.
      │
      ▼
[Candidate memory entries]
  State: pending approval
  Not injected into agent context
      │
      ▼
[Approval workflow]
  Human operator or rule-based automation.
  Approved entries move to persistentVault.
  Rejected entries are discarded.
      │
      ▼
[persistentVault]
  Durable. Survives platform changes.
  Included in Merkle root computation.
      │
      ▼
[Verification step]
  Final confirmation that entry is correct and intended.
  Moves entry to verifiedEntries.
      │
      ▼
[verifiedEntries]
  Injected into agent system prompt context at runtime.
  Included in Merkle root computation.
```

### 8.5 Memory Vault Structure

```json
{
  "vaultId":           "<uuid>",
  "instanceId":        "<32-char hex>",
  "operationalCache":  [ "...MemoryEntry[]..." ],
  "persistentEntries": [ "...MemoryEntry[]..." ],
  "verifiedEntries":   [ "...MemoryEntry[]..." ],
  "memoryStats": {
    "totalEntries":         42,
    "verifiedEntries":      18,
    "verifiedMemoryUnits":  18,
    "dedupeCount":          3
  },
  "embeddingIndexKeys": [],
  "createdAt":          "2026-01-14T09:00:00.000Z",
  "updatedAt":          "2026-03-01T14:22:10.000Z",
  "merkleRoot":         "<sha256-hex>"
}
```

### 8.6 System Prompt Injection

At runtime, a conforming platform adapter injects the agent's identity and verified memory into the system prompt:

```
[01AI IDENTITY VERIFIED]
Agent: <name> | ID: <first-8-chars-of-instanceId> | State: <lifecycleState> | Evolution: <counter>
Role: <descriptor>
Integrity: <first-8-chars-checksum>✓ | Signature: Ed25519✓

[VERIFIED MEMORY — <N> entries]
[decision] Chose PostgreSQL over MongoDB for reporting module. Revisit if write volume > 50k/min.
[project-history] Phase 1 complete. API layer stable. Moving to frontend integration.
[learning] Recursive Zod schemas require .lazy() — direct nesting causes infinite type instantiation.
```

Only `verifiedEntries` are injected. `operationalCache` and pending candidates are never injected.

---

## 9. Memory Merkle Tree

### 9.1 Construction

The memory Merkle root is a standard binary Merkle tree over the union of `persistentEntries` and `verifiedEntries`.

**Leaf hash computation** (fields in alphabetical order):

```
leaf = SHA-256(JSON.stringify({
  createdAt:   entry.createdAt,
  entryId:     entry.entryId,
  fingerprint: entry.fingerprint,
  instanceId:  entry.instanceId,
  layer:       entry.layer,
  summary:     entry.summary,
  type:        entry.type,
  vaultId:     entry.vaultId,
}))
```

**Tree construction:**

1. Compute leaf hashes for all included entries (sorted by `entryId`).
2. If zero entries: root = SHA-256(`""`) — the well-known empty root.
3. If one entry: root = the single leaf hash.
4. For N > 1: build binary tree bottom-up. If the level has an odd number of nodes, duplicate the last node to make it even.
5. Root is the SHA-256 of the concatenated left and right child hashes at each level.

### 9.2 Proof Generation and Verification

An inclusion proof for entry E in a vault with root R consists of:

```typescript
{
  entryId:  string;   // identifies the entry being proven
  leafHash: string;   // SHA-256 of the leaf
  steps:    {
    sibling:       string;   // hash of the sibling node at this level
    siblingIsLeft: boolean;  // true if sibling is to the LEFT
  }[];
  root:     string;   // the expected Merkle root
}
```

**Verification:**

```
current = leafHash
for each step in steps:
  if step.siblingIsLeft:
    current = SHA-256(step.sibling || current)
  else:
    current = SHA-256(current || step.sibling)

assert current === root
```

### 9.3 Binding to Agent Identity

```
agentId.memoryMerkleRoot = computeMemoryMerkleRoot(persistentEntries + verifiedEntries)
```

After updating the Merkle root, the agent record MUST be re-signed (incrementing `evolutionCounter`). The Merkle root is part of the canonical signed payload (§4.1), so any change to memory invalidates the existing signature.

### 9.4 Empty Vault

If an agent has no memory entries, `memoryMerkleRoot` MUST be set to the SHA-256 of the empty string:

```
EMPTY_MERKLE_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

---

## 10. Platform Profiles

Platform profiles allow per-platform tuning without modifying the signed identity record. They are stored in the optional `platformProfiles` array and are NOT included in the canonical signed payload.

### 10.1 Profile Fields

| Field | Type | Description |
|---|---|---|
| `platform` | string | Platform identifier (e.g. `"claude"`, `"openai"`, `"ollama"`) |
| `model` | string | Preferred model ID for this platform |
| `temperature` | number | Preferred temperature (0.0–2.0) |
| `maxTokens` | integer | Context window or max output tokens |
| `systemPromptTemplate` | string | Custom injection template (may include `{{identity}}` placeholder) |
| `customInstructions` | string | Additional platform-specific instructions |

### 10.2 Fallback Behavior

If no profile exists for the current platform, implementations MUST fall back to the default injection: the agent's `name`, `descriptor`, `lifecycleState`, and verified memory entries.

### 10.3 Known Platform Identifiers

`claude` · `openai` · `gemini` · `ollama` · `lm-studio` · `groq` · `mistral` · `cohere` · `huggingface` · `openrouter` · `together` · `replicate` · `perplexity` · `grok` · `jan`

Any OpenAI-compatible endpoint may use the `openai` profile as a fallback.

---

## 11. Transport Formats

### 11.1 File Transport (`.01ai`)

The canonical format. A single JSON file containing the AgentId record. File extension is `.01ai`. MIME type is `application/x-01ai-identity`.

### 11.2 Bundle Transport (`.01bundle`)

A JSON file pairing identity with memory vault:

```json
{
  "bundleVersion": "1.0",
  "bundleId":      "<uuid>",
  "createdAt":     "<ISO 8601>",
  "identity":      { "...AgentId record..." },
  "memoryVault":   { "...AgentMemoryVault record..." }
}
```

File extension is `.01bundle`. MIME type is `application/x-01ai-bundle`.

### 11.3 QR Transport

For mobile and air-gapped scenarios, a compact QR payload contains four fields:

```json
{
  "id":   "<instanceId>",
  "name": "<name>",
  "pub":  "<signerPublicKey>",
  "sig":  "<signature>"
}
```

QR payloads do not carry memory or platform profiles. They are identity-only for scanning and quick verification.

### 11.4 API Transport

For HTTP API delivery, the full AgentId record is delivered as JSON with the header:

```
Content-Type: application/x-01ai-identity
```

---

## 12. Extension Fields

Fields prefixed with `x-` are reserved for extension use by platforms and implementations.

### 12.1 Rules

- Extension field keys MUST start with `x-` and be lowercase.
- Extension field keys MUST NOT conflict with required or optional field names.
- Extension field keys MUST NOT exceed 64 characters.
- Extension field string values MUST NOT exceed 8,000 characters.
- Extension fields are preserved through re-signing but NOT included in the canonical signed payload.
- Implementations encountering unknown extension fields MUST NOT fail — they must preserve and pass them through.

### 12.2 Reserved Extension Fields

| Field | Type | Description |
|---|---|---|
| `x-serial` | string | Serial number within an edition |
| `x-total` | string | Total supply within an edition |
| `x-rarity-label` | string | Human-readable rarity or tier label |
| `x-memory-mode` | string | Memory configuration mode for this agent |

---

## 13. Compliance Levels

### 13.1 Reader

A Reader implementation:
- Parses `.01ai` files with all input guards enforced (§6)
- Displays required and optional fields
- Does NOT verify the signature
- Does NOT reject files with invalid signatures

A Reader MUST enforce all parsing guards. Parsing without guards is not compliant at any level.

### 13.2 Verifier

A Verifier implementation:
- Satisfies all Reader requirements
- Fully implements the verification algorithm (§5)
- Returns a deterministic pass/fail result
- Emits warnings for non-fatal anomalies

### 13.3 Full Implementation

A Full Implementation:
- Satisfies all Verifier requirements
- Implements lifecycle state machine (§7)
- Implements memory vault (§8)
- Implements Merkle tree construction and verification (§9)
- Supports platform profiles (§10)
- Supports `.01bundle` format (§11.2)
- Mints new agent records with Ed25519 keypair generation

---

## 14. Test Vectors

See [docs/test-vectors.md](./docs/test-vectors.md) for canonical test inputs and expected verification outputs.

All conforming verifier implementations MUST pass all test vectors in that document.

---

## 15. Changelog

See [CHANGELOG.md](./CHANGELOG.md).

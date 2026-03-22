# 01 Protocol — Agent Identity Specification

**Version**: 0.1.0-draft
**Status**: Pre-release
**Owner**: 01ai (01ai.ai)
**Format MIME type**: `application/x-01ai-identity`
**File extension**: `.01ai`

---

## 1. Purpose and Design Philosophy

The 01 Protocol defines a format for **persistent, portable, cryptographically verifiable AI agent identity**. Its single core guarantee is:

> An agent carrying a `.01ai` file can be instantiated, verified, and used on **any AI platform, any runtime, any language, anywhere** — online or offline — with no dependency on any external registry, service, or authority.

### 1.1 Ultra-Universal Compatibility

"Universal compatibility" is not a marketing claim. It is an architectural constraint embedded into the spec:

- **No platform whitelist.** There is no list of approved platforms. Every agent works everywhere.
- **No capability gate.** `platformProfiles` are optional tuning hints. Their absence is not a compatibility failure.
- **No external verification dependency.** The `signerPublicKey` is embedded in every `.01ai` file. Verification requires only the file itself.
- **No runtime-specific code paths.** The verification algorithm is defined in this document and is implementable in any language that supports Ed25519 and SHA-256.
- **No schema version lock.** Unknown fields are preserved and ignored. Forward compatibility is guaranteed by design.

### 1.2 What This Spec Is

This document defines:

1. The `.01ai` JSON file format (all required and optional fields)
2. The canonical serialization algorithm (exact field order for deterministic signing)
3. The cryptographic verification algorithm (step-by-step, any-language implementable)
4. The lifecycle state machine
5. The memory system schema
6. The platform adapter interface (how third parties integrate)
7. The embodiment adapter pattern (how agents move across AI systems)
8. Transport formats: file, bundle, QR compact payload
9. Security constraints and threat model summary
10. Reference test vectors

---

## 2. File Format

A `.01ai` file is a UTF-8 encoded JSON object. File extension: `.01ai`. MIME type: `application/x-01ai-identity`.

### 2.1 Minimal Valid Identity Record

This is the smallest valid `.01ai` file. All listed fields are **required**.

```json
{
  "instanceId": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "name": "Research Assistant",
  "descriptor": "A specialist agent for academic research, literature review, and synthesis across disciplines.",
  "lifecycleState": "ACTIVE",
  "evolutionCounter": 0,
  "integrityChecksum": "<sha256-hex-64-chars>",
  "signature": "<ed25519-sig-hex-128-chars>",
  "signerPublicKey": "<ed25519-pubkey-hex-64-chars>",
  "createdAt": "2025-01-01T00:00:00.000Z",
  "updatedAt": "2025-01-01T00:00:00.000Z"
}
```

### 2.2 Full Field Reference

#### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `instanceId` | `string` | 32-character lowercase hex. Globally unique. Generated once at mint. Never changes. |
| `name` | `string` | Human-readable role name. Max 200 chars. Displayed in UI. |
| `descriptor` | `string` | Role description / system prompt seed. Max 8,000 chars. Plain text only. |
| `lifecycleState` | `string` | One of: `UNINITIALIZED`, `ACTIVE`, `FROZEN`, `ARCHIVED`, `TRANSFERRING`, `DELETED` |
| `evolutionCounter` | `integer` | Monotonically increasing. Starts at 0. Increments on every signed update. Never decreases. |
| `integrityChecksum` | `string` | SHA-256 hex of the canonical payload (see §4). 64 lowercase hex chars. |
| `signature` | `string` | Ed25519 signature of `integrityChecksum` bytes. 128 lowercase hex chars. |
| `signerPublicKey` | `string` | Ed25519 public key corresponding to the signing key. 64 lowercase hex chars. |
| `createdAt` | `string` | ISO 8601 UTC timestamp of original creation. Never changes after mint. |
| `updatedAt` | `string` | ISO 8601 UTC timestamp of last signed update. |

#### Optional Core Fields

| Field | Type | Description |
|-------|------|-------------|
| `memoryMerkleRoot` | `string` | SHA-256 Merkle root of the agent's persistent memory vault entries. 64 hex chars. |
| `parentInstanceIds` | `string[]` | `instanceId` values of direct parent agents this was bred/derived from. |
| `parentChecksums` | `string[]` | Corresponding `integrityChecksum` values for each parent at time of derivation. |
| `platformProfiles` | `PlatformProfile[]` | Optional per-platform tuning hints. See §6. |
| `lifecycleHistory` | `TransitionEvent[]` | Ordered record of all state transitions. See §5.4. |
| `tags` | `string[]` | Free-form labels. Max 32 tags, max 64 chars each. |
| `formatVersion` | `string` | Spec version this record was written against. Semver. Default: `"0.1.0"`. |

#### Extension Fields

Any field not in the above lists is an **extension field**. Extension fields:

- MUST be preserved by any implementation that reads and re-writes a `.01ai`
- MUST NOT affect verification (they are not part of the signed digest)
- SHOULD use a namespaced key prefix: `"x-<namespace>-<fieldname>"` (e.g., `"x-acme-tier"`)
- Are never required for a file to be valid

---

## 3. Lifecycle State Machine

### 3.1 States

| State | Meaning |
|-------|---------|
| `UNINITIALIZED` | Created but not yet activated. Cannot sign memory. |
| `ACTIVE` | Fully operational. Default state after mint. |
| `FROZEN` | Temporarily suspended. Read-only. Can be unfrozen to `ACTIVE`. |
| `ARCHIVED` | Long-term storage. Can be restored to `ACTIVE`. |
| `TRANSFERRING` | In transit between platforms/owners. Locked during transfer. |
| `DELETED` | Terminal. Signed deletion receipt issued. Irreversible. |

### 3.2 Allowed Transitions

```
UNINITIALIZED ──► ACTIVE
ACTIVE        ──► FROZEN
ACTIVE        ──► ARCHIVED
ACTIVE        ──► TRANSFERRING
ACTIVE        ──► DELETED
FROZEN        ──► ACTIVE
FROZEN        ──► ARCHIVED
FROZEN        ──► DELETED
ARCHIVED      ──► ACTIVE
ARCHIVED      ──► DELETED
TRANSFERRING  ──► ACTIVE   (transfer complete)
TRANSFERRING  ──► DELETED  (transfer rejected)
DELETED       ──► (none — terminal)
```

Any transition not listed above is **invalid and MUST be rejected** by conforming implementations.

### 3.3 Transition Rules

On every valid state transition:

1. `lifecycleState` is updated to the new state
2. `evolutionCounter` is incremented by exactly 1
3. `updatedAt` is set to the current UTC ISO 8601 timestamp
4. A new `integrityChecksum` is computed over the updated canonical payload
5. A new `signature` is produced using the agent's private signing key
6. If `lifecycleHistory` is maintained, a `TransitionEvent` is appended

### 3.4 TransitionEvent Schema

```json
{
  "from": "ACTIVE",
  "to": "FROZEN",
  "at": "2025-06-01T12:00:00.000Z",
  "evolutionCounter": 3,
  "reason": "manual-pause",
  "checksum": "<integrityChecksum at time of transition>"
}
```

The `checksum` field binds the transition to a specific snapshot — forming a hash chain over lifecycle history.

### 3.5 Deletion Receipts

When an agent transitions to `DELETED`, a signed **DeletionReceipt** MUST be issued:

```json
{
  "instanceId": "<agent instanceId>",
  "deletedAt": "<ISO 8601 timestamp>",
  "finalChecksum": "<integrityChecksum at deletion>",
  "finalEvolution": 7,
  "reason": "<optional reason string>",
  "receiptSignature": "<Ed25519 signature of above fields, same signing key>",
  "signerPublicKey": "<same pubkey>"
}
```

A valid deletion receipt proves the deletion was intentional and authorized by the key holder.

---

## 4. Canonical Serialization and Signing

This is the most security-critical section. All implementations MUST follow this exactly.

### 4.1 Signed Payload Fields

The following fields, and ONLY these fields, are included in the signed digest. They MUST appear in exactly this order in the JSON serialization:

```
instanceId
name
descriptor
lifecycleState
evolutionCounter
memoryMerkleRoot
parentInstanceIds
parentChecksums
createdAt
```

### 4.2 Default Values for Omitted Optional Fields

When computing the digest, optional fields that are absent from the record are treated as follows:

| Field | Absent default |
|-------|----------------|
| `memoryMerkleRoot` | `null` |
| `parentInstanceIds` | `[]` (empty array) |
| `parentChecksums` | `[]` (empty array) |

### 4.3 Canonical Serialization Algorithm

```
canonical_payload = JSON.stringify({
  instanceId:        record.instanceId,
  name:              record.name,
  descriptor:        record.descriptor,
  lifecycleState:    record.lifecycleState,
  evolutionCounter:  record.evolutionCounter,
  memoryMerkleRoot:  record.memoryMerkleRoot ?? null,
  parentInstanceIds: record.parentInstanceIds ?? [],
  parentChecksums:   record.parentChecksums ?? [],
  createdAt:         record.createdAt
})
```

Rules:
- JSON key order is fixed as listed above
- No trailing whitespace or newlines in the JSON string
- `JSON.stringify` with no spacing arguments (compact — no spaces after `:` or `,`)
- UTF-8 encoding
- Unicode characters are NOT normalized (stored as-is in JSON)
- Boolean, number, and null values use JSON canonical forms (`true`/`false`/`null`)

### 4.4 Digest Computation

```
digest = SHA-256(UTF-8(canonical_payload))
integrityChecksum = hex(digest)   // 64 lowercase hex chars
```

### 4.5 Signature

```
signature = Ed25519.sign(message=digest, privateKey=signingKey)
// 64-byte signature → 128 lowercase hex chars
```

Note: `Ed25519.sign` operates on the raw 32-byte SHA-256 digest, not on the text payload.

### 4.6 Reference Test Vector

**Input record** (before signing):
```json
{
  "instanceId": "00000000000000000000000000000001",
  "name": "Test Agent",
  "descriptor": "A test agent for spec validation.",
  "lifecycleState": "ACTIVE",
  "evolutionCounter": 0,
  "createdAt": "2025-01-01T00:00:00.000Z",
  "updatedAt": "2025-01-01T00:00:00.000Z",
  "signerPublicKey": "<pubkey>",
  "signature": "<sig>",
  "integrityChecksum": "<checksum>"
}
```

**Canonical payload** (what is hashed):
```
{"instanceId":"00000000000000000000000000000001","name":"Test Agent","descriptor":"A test agent for spec validation.","lifecycleState":"ACTIVE","evolutionCounter":0,"memoryMerkleRoot":null,"parentInstanceIds":[],"parentChecksums":[],"createdAt":"2025-01-01T00:00:00.000Z"}
```

Implementations MUST pass a test vector suite with known keypairs, canonical payloads, and expected checksums. The test vector suite is maintained in `packages/core/test-vectors/`.

---

## 5. Verification Algorithm

Any conforming verifier — in any language, on any platform — MUST implement these steps in order and MUST return the same result as every other conforming verifier (P0-2 of the security spec).

### Step 1: Parse

Parse the input as UTF-8 JSON. If parsing fails: **INVALID**.

Apply hostile-input guards:
- File size ≤ 1,000,000 bytes
- JSON nesting depth ≤ 8
- No string field longer than 8,000 characters
- No array with more than 256 elements
- No object with more than 64 keys
- Reject keys: `__proto__`, `constructor`, `prototype`
- Root value must be a JSON object (not array, string, number, null)

If any guard fails: **INVALID** with error code from parse guard layer.

### Step 2: Required Field Presence

Verify all required fields exist and are non-null. If any is missing: **INVALID**.

### Step 3: Type Validation

| Field | Expected |
|-------|----------|
| `instanceId` | string matching `/^[0-9a-f]{32}$/i` |
| `lifecycleState` | string in known state list (unknown values WARN, do not fail) |
| `evolutionCounter` | non-negative integer |
| `integrityChecksum` | string matching `/^[0-9a-f]{64}$/i` |
| `signature` | string matching `/^[0-9a-f]{128}$/i` |
| `signerPublicKey` | string matching `/^[0-9a-f]{64}$/i` |
| `createdAt`, `updatedAt` | parseable ISO 8601 timestamp |

If any type check fails: **INVALID**.

### Step 4: Consistency Checks (produce warnings, not failures)

- `updatedAt` < `createdAt` → WARN: timestamp inconsistency
- `createdAt` more than 60 seconds in the future → WARN: clock skew or forgery
- `evolutionCounter === 0` AND `parentInstanceIds.length > 0` → WARN: possible rollback
- `lifecycleState === "DELETED"` → WARN: terminal state

### Step 5: Checksum Verification

Compute canonical payload (§4.3). Compute SHA-256 digest (§4.4). Compare hex to `integrityChecksum`. If mismatch: **INVALID** — file has been modified since signing.

### Step 6: Signature Verification

Decode `signature` and `signerPublicKey` from hex. Call:
```
Ed25519.verify(signature=sigBytes, message=digestBytes, publicKey=pubBytes)
```
If verification returns false or throws: **INVALID**.

### Step 7: Result

Return `{ valid: true, agent, warnings }` or `{ valid: false, error, warnings }`.

**Critical**: "valid" means integrity verified, NOT content trusted. Implementations MUST communicate this distinction to users (see §9).

---

## 6. Platform Adapter Interface

### 6.1 Design Principle

Every `.01ai` agent works on every platform. `platformProfiles` are tuning hints only. An agent with zero platform profiles is fully compatible with all platforms — implementations MUST NOT treat absent profiles as incompatibility.

### 6.2 PlatformProfile Schema

```json
{
  "platform": "claude",
  "model": "claude-opus-4-6",
  "systemPromptOverride": "You are...",
  "contextWindowBudget": 150000,
  "maxOutputTokens": 8096,
  "temperature": 0.7,
  "customInstructions": "...",
  "x-acme-extra": "any extension field"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `platform` | `string` | YES | Platform identifier. See §6.3 for known values. Case-insensitive. |
| `model` | `string` | NO | Preferred model for this platform. Adapter falls back to its own default. |
| `systemPromptOverride` | `string` | NO | Replaces default system prompt injection for this platform. |
| `contextWindowBudget` | `integer` | NO | Preferred max tokens to use. Adapter may ignore if platform differs. |
| `maxOutputTokens` | `integer` | NO | Preferred output token ceiling. |
| `temperature` | `number` | NO | Preferred sampling temperature. 0–2. |
| `customInstructions` | `string` | NO | Additional platform-specific instructions appended to system prompt. |

Extension fields allowed via `x-` prefix.

### 6.3 Known Platform Identifiers

These are registry values. New platforms may use any string.

| Value | Platform |
|-------|---------|
| `claude` | Anthropic Claude (any model) |
| `openai` | OpenAI API (GPT models) |
| `gemini` | Google Gemini |
| `ollama` | Ollama local runner |
| `llama` | Meta LLaMA (any runner) |
| `mistral` | Mistral API |
| `groq` | Groq API |
| `cohere` | Cohere API |
| `huggingface` | HuggingFace Inference |
| `lmstudio` | LM Studio local |
| `openrouter` | OpenRouter multi-model proxy |
| `together` | Together AI |
| `replicate` | Replicate |
| `perplexity` | Perplexity AI |
| `grok` | xAI Grok |
| `cadence` | CADENCE desktop (01ai native) |

**Any unlisted platform identifier is valid.** The list above is informational, not restrictive.

### 6.4 Adapter Resolution

When an adapter loads an agent, it MUST use this resolution order:

```
1. Look for a platformProfile matching this platform (case-insensitive)
2. If found: use profile fields as tuning hints (supplement, don't gate)
3. If not found: use agent.descriptor as system prompt seed
4. Always inject: agent name, descriptor, instanceId fingerprint, lifecycleState
5. Never reject agent for missing profile
```

---

## 7. Embodiment Adapter Protocol

An **embodiment adapter** is any code layer that takes a `.01ai` agent and instantiates it on a specific AI platform. This section defines the interface adapters MUST implement.

### 7.1 Adapter Interface (TypeScript reference)

```typescript
interface EmbodimentAdapter {
  /** Unique platform identifier. Matches platformProfile.platform */
  readonly platform: string;

  /**
   * Instantiate an agent on this platform.
   * MUST work for any valid AgentId, with or without a matching platformProfile.
   */
  instantiate(agent: AgentId, options?: AdapterOptions): Promise<AgentSession>;

  /**
   * Verify the adapter can reach its target platform.
   * Returns false without throwing if platform is unreachable.
   */
  healthCheck(): Promise<boolean>;
}

interface AdapterOptions {
  /** Override model (takes precedence over platformProfile.model) */
  model?: string;
  /** Override system prompt (takes precedence over platformProfile.systemPromptOverride) */
  systemPromptOverride?: string;
  /** Additional context to prepend to system prompt */
  additionalContext?: string;
}

interface AgentSession {
  /** Send a message and receive a response */
  send(message: string): Promise<string>;
  /** Terminate the session */
  close(): Promise<void>;
  /** Platform-specific session metadata */
  metadata: Record<string, unknown>;
}
```

### 7.2 System Prompt Injection Template

When embodying an agent, adapters MUST inject identity context into the system prompt. The minimum required injection is:

```
You are {agent.name} (#{agent.instanceId.slice(0, 8)}).

{agent.descriptor}

Your identity is persistent. You carry a cryptographically verified record of who you are
across every session and every platform. Your evolution counter is {agent.evolutionCounter}.
Your current state is {agent.lifecycleState}.
```

Adapters MAY append additional content after this block.
Adapters MUST NOT place user-controlled content before this block.
Adapters MUST NOT interpret `agent.descriptor` as executable instructions — it is injected as data.

### 7.3 Memory Injection

If the agent has a memory vault, adapters SHOULD inject approved persistent memories into the system prompt after the identity block:

```
## What you know (from verified memory)

{for each persistentEntry in vault}
- {entry.content}   [confidence: {entry.confidence}, verified: {entry.isVerified}]
{end}
```

Memory injection MUST:
- Only include entries with `approvalState === "approved"` or `"verified"`
- Never inject entries with `approvalState === "candidate"`, `"disputed"`, `"revoked"`, or `"quarantined"`
- Separate memory from system instructions clearly
- Label entries as data, not instructions

---

## 8. Memory System

### 8.1 Memory State Machine

Memory entries move through a controlled approval flow before becoming durable:

```
candidate → approved → verified
candidate → disputed
candidate → rejected (not stored)
approved  → revoked
approved  → quarantined
verified  → disputed
```

**Only `approved` and `verified` entries may enter the persistent vault.**
Candidates, rejected, revoked, quarantined, disputed entries MUST NOT be injected into agent prompts.

### 8.2 MemoryEntry Schema

```json
{
  "id": "<uuid>",
  "content": "The user prefers concise responses under 200 words.",
  "approvalState": "approved",
  "confidence": 0.85,
  "isVerified": false,
  "createdAt": "2025-01-01T00:00:00.000Z",
  "sourceSessionHash": "<sha256 of session that produced this>",
  "proposedBy": "extraction-pipeline",
  "approvedBy": "user:explicit-click",
  "approvedAt": "2025-01-01T00:01:00.000Z",
  "trustClass": "preference",
  "contentSafetyClass": "benign",
  "tags": ["user-preference", "output-format"],
  "salience": 0.72,
  "checksum": "<sha256 of content field>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | YES | UUID v4 |
| `content` | YES | Plain text. Max 2,000 chars. |
| `approvalState` | YES | See §8.1 |
| `confidence` | YES | 0.0–1.0 |
| `isVerified` | YES | Cross-session confirmed |
| `createdAt` | YES | ISO 8601 |
| `sourceSessionHash` | YES | Provenance — which session produced this |
| `proposedBy` | YES | Who/what proposed this memory |
| `approvedBy` | YES | Actor who approved. `"auto"` only allowed for pre-approved classes. |
| `approvedAt` | YES | Timestamp of approval action |
| `trustClass` | YES | `preference` / `fact` / `relationship` / `decision` / `instruction` |
| `contentSafetyClass` | YES | `benign` / `sensitive` / `suspect` / `quarantined` |
| `checksum` | YES | SHA-256 of `content` field — per-entry tamper evidence (P1-11) |
| `salience` | NO | Computed score: `(α·Novelty + β·Engagement + γ·EntityWeight) × e^(-λt)` |
| `tags` | NO | Free-form labels |
| `dependencies` | NO | `id[]` of other entries this relies on |

### 8.3 Memory Vault Schema

```json
{
  "agentInstanceId": "<instanceId>",
  "schemaVersion": "0.1.0",
  "merkleRoot": "<sha256 merkle root of all approved entries>",
  "persistentEntries": [...],
  "verifiedEntries": [...],
  "createdAt": "...",
  "updatedAt": "..."
}
```

The `merkleRoot` MUST match the `memoryMerkleRoot` embedded in the agent's `.01ai` file. If they differ, the vault has been tampered with independently of the identity record.

### 8.4 Merkle Root Computation

```
leaves = persistentEntries.concat(verifiedEntries)
leaves = sortBy(leaves, e => e.id)   // deterministic ordering by UUID
leafHashes = leaves.map(e => sha256(e.checksum))
merkleRoot = binaryMerkleTree(leafHashes)  // SHA-256 at each internal node
```

---

## 9. Security Constraints

Implementors MUST adhere to the following from the 01ai Security Spec.

### 9.1 What "Integrity Verified" Means (P1-6)

Implementations MUST communicate to users:

> **Integrity verified** means the file has not been modified since it was signed. It does not confirm the content is true, safe, or from a trustworthy source.

The badge or label MUST say "Integrity verified" — not bare "Verified" or "Trusted".

### 9.2 Key Security Rules

- **Private keys MUST NEVER appear in a `.01ai` file or portable bundle**
- **Private keys MUST NEVER be logged, exported in debug output, or transmitted**
- **Every `.01ai` import MUST be treated as hostile input** — apply §5 Step 1 guards
- **Memory MUST NOT be persisted without an explicit user approval event** (no silent write-back)
- **Memory entries MUST be stored as data, not executable instructions** — content fields are never evaluated

### 9.3 Rollback Detection (P0-4)

Implementations that track agents over time MUST:
- Warn when `evolutionCounter` is lower than the last seen value
- Warn when an envelope's checksum differs from the last known good checksum for that `instanceId`
- Never silently accept a rollback as the new state

### 9.4 Hostile Input Guards (P0-3)

Minimum required input validation before any parsing or verification:

| Check | Limit |
|-------|-------|
| Input size | ≤ 1,000,000 bytes |
| JSON nesting depth | ≤ 8 |
| Any string length | ≤ 8,000 chars |
| Array length | ≤ 256 items |
| Object keys | ≤ 64 keys |
| Banned keys | `__proto__`, `constructor`, `prototype` |

---

## 10. Transport Formats

### 10.1 File Transport

Standard form: a single `.01ai` file containing the JSON identity record. This is the canonical transport for human-facing sharing and storage.

### 10.2 Bundle Transport

A **01 Bundle** packages identity + memory vault as a portable archive:

```
bundle.01bundle  (JSON)
{
  "bundleVersion": "0.1.0",
  "bundleId": "<uuid>",
  "createdAt": "<ISO 8601>",
  "identity": { ... },        // full AgentId record
  "memoryVault": { ... },     // AgentMemoryVault (optional)
  "bundleSignature": "<Ed25519 signature over bundleId + identity.integrityChecksum + vault.merkleRoot>"
}
```

**Security**: Private key MUST NOT be included in a bundle. Bundle export is identity portability, not signing authority portability.

### 10.3 QR Compact Payload

For mobile scanning and quick verification, a minimal 4-field payload:

```json
{ "i": "<instanceId>", "c": "<integrityChecksum>", "s": "<signature>", "k": "<signerPublicKey>" }
```

QR verification MUST clearly state:
- Only cryptographic integrity was checked (checksum + signature)
- Full identity fields were NOT verified from this payload
- The user should load the full `.01ai` for complete verification

### 10.4 API Transport

When transmitted over HTTP/API:

```http
Content-Type: application/x-01ai-identity
```

No special encoding required beyond UTF-8 JSON. May be base64-encoded when embedded in systems that cannot carry arbitrary JSON.

---

## 11. Third-Party Integration Guide

### 11.1 Minimal Verifier Implementation

Any system wanting to verify a `.01ai` file needs only:

1. A JSON parser
2. SHA-256 hash function
3. Ed25519 signature verification

No SDK required. No network calls. No registry lookup. Steps 1–6 of §5 are the complete algorithm.

Reference implementations:
- **Node.js / TypeScript**: `@01ai/core` (uses `@noble/curves`)
- **Browser**: `@01ai/verify` (uses `@noble/curves` — pure JS, no WASM)
- **React Native / Expo**: `@01ai/verify` (same package, same algorithm)

### 11.2 Minimal Reader Implementation

To display a `.01ai` agent (without verification):

```
1. Parse JSON
2. Apply hostile-input guards (§9.4)
3. Display: name, descriptor, lifecycleState, evolutionCounter, createdAt
4. Display fingerprint: instanceId.slice(0, 8).toUpperCase()
5. Do NOT evaluate or execute any field content
```

### 11.3 Minimal Embodiment Implementation

To instantiate a `.01ai` agent on any AI platform:

```
1. Verify the record (§5)
2. Find matching platformProfile for this platform, or use descriptor directly
3. Build system prompt using injection template (§7.2)
4. If memory vault available, inject approved memories (§7.3)
5. Initialize session with platform API
6. Never inject candidiate or unapproved memory entries
```

### 11.4 SDK Package Index

| Package | Purpose | Runtime |
|---------|---------|---------|
| `@01ai/types` | Zod schemas for all record types | Node, Browser, React Native |
| `@01ai/core` | Full identity engine, lifecycle, memory Merkle | Node, Electron |
| `@01ai/verify` | Offline verifier only (no signing) | Node, Browser, React Native |
| `@01ai/adapters` | Claude, OpenAI, Ollama, Gemini adapters | Node, Electron |

---

## 12. Format Versioning

The `.01ai` format uses the optional `formatVersion` field (semver string).

Rules for conforming implementations:

- If `formatVersion` is absent, treat as `"0.1.0"`
- If `formatVersion` major version is higher than what the implementation supports: warn, do not fail
- If `formatVersion` is unrecognized: preserve the file as-is, warn, still attempt verification
- Unknown fields MUST be preserved on round-trip write
- Downgrade rejection: an implementation that wrote a higher format version MUST warn if importing a lower-version file that may have lost fields

---

## 13. Compliance Levels

Third-party implementations may claim one of three compliance levels:

### Level 1: Reader

Can parse and display `.01ai` files. Applies hostile-input guards. Displays fingerprint beside name.

**Required**: §2, §9.3 (hostile input guards), name fingerprint display.

### Level 2: Verifier

Implements the full offline verification algorithm.

**Required**: Level 1 + §4 (canonical serialization), §5 (verification algorithm), §9.1 (integrity verified language).

### Level 3: Full Implementation

Implements lifecycle management, memory system, and platform adapters.

**Required**: Level 2 + §3 (lifecycle), §8 (memory), §6–7 (adapters), §10 (transport), §12 (versioning).

---

## 14. Interoperability Pledge

Any `.01ai` file created by any conforming implementation:

- Will be verifiable by any other conforming verifier
- Will be displayable by any conforming reader
- Will be embody-able on any AI platform with any conforming adapter
- Will survive storage in any system that preserves UTF-8 JSON

This is the universal compatibility guarantee of the 01 Protocol.

---

*Specification maintained by 01ai (01ai.ai). Filed under the 01 Protocol provisional patent.*
*Reference implementation: `github.com/01ai/01-protocol`*

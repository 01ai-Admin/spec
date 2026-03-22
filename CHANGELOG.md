# Changelog

All notable changes to the 01 Protocol specification are documented here.

Format: [Semantic Versioning](https://semver.org/). Breaking changes increment the major version.

---

## [1.0.0] — 2026-03-22

### Initial stable release

**Identity Record (AgentId)**
- Required fields: `instanceId`, `name`, `descriptor`, `lifecycleState`, `evolutionCounter`, `createdAt`, `updatedAt`, `integrityChecksum`, `signerPublicKey`, `signature`
- Optional fields: `memoryMerkleRoot`, `parentInstanceIds`, `parentChecksums`, `platformProfiles`, `formatVersion`
- Extension field namespace: `x-` prefix

**Canonical Serialization**
- Fixed field order for signing: `instanceId`, `name`, `descriptor`, `lifecycleState`, `evolutionCounter`, `memoryMerkleRoot`, `parentInstanceIds`, `parentChecksums`, `createdAt`
- SHA-256 of UTF-8 encoded JSON.stringify (no indentation)
- Ed25519 signature over raw digest bytes

**Verification Algorithm**
- 12-step deterministic verification with input guards applied before any parsing
- Non-fatal warnings for: timestamps out of order, future-dated records, evolution counter anomalies, DELETED state

**Input Guards**
- Max file size: 1,000,000 bytes
- Max JSON nesting: 8 levels
- Max string length: 8,000 chars
- Max array length: 256 elements
- Max object keys: 64
- Prototype pollution rejection: `__proto__`, `constructor`, `prototype`

**Lifecycle State Machine**
- States: UNINITIALIZED, ACTIVE, FROZEN, ARCHIVED, TRANSFERRING, DELETED
- Full transition topology with reason codes
- DELETED as terminal state
- Freeze context with integrity seal
- Deletion receipts with cryptographic proof of authorized termination

**Persistent Memory System**
- Three-layer vault: `operationalCache`, `persistentEntries`, `verifiedEntries`
- Memory pipeline: extraction → salience scoring → approval → persistence → verification → injection
- Salience formula: `S = (α×Novelty + β×Engagement + γ×EntityWeight) × e^(−λ×t)`
- Memory types: `summary`, `task-context`, `project-history`, `decision`, `achievement`, `learning`, `note`
- System prompt injection format for verified entries

**Memory Merkle Tree**
- Binary Merkle tree over `persistentEntries` + `verifiedEntries`
- Leaf hash: SHA-256 of alphabetically-ordered entry fields
- Empty vault well-known root: SHA-256 of empty string
- Merkle root included in canonical signed payload — memory tampering invalidates signature
- Inclusion proof format with sibling path

**Transport Formats**
- `.01ai` — canonical single-record file
- `.01bundle` — identity + memory vault bundle
- QR — compact 4-field payload for mobile
- API — `application/x-01ai-identity` MIME type

**Platform Profiles**
- Optional, not included in signed payload
- Fields: `platform`, `model`, `temperature`, `maxTokens`, `systemPromptTemplate`, `customInstructions`
- Fallback behavior defined for missing profiles

**Compliance Levels**
- Reader: parse + display with input guards
- Verifier: full cryptographic verification
- Full Implementation: lifecycle + memory + bundles + minting

# 01 Protocol

**Open standard for portable, persistent, cryptographically verifiable AI agent identity.**

[![Spec Version](https://img.shields.io/badge/spec-v1.0.0-black)](./SPEC.md)
[![License](https://img.shields.io/badge/license-MIT-black)](./LICENSE)
[![Patent](https://img.shields.io/badge/patent-pending%20(US)-black)](#)
[![App](https://img.shields.io/badge/app-01ai.ai-black)](https://01ai.ai)

---

## The Problem

AI agents have no persistent identity. Every session starts from zero. Switch platforms and your agent loses everything — its history, its learned context, its verified record of decisions made. There is no standard that lets an agent carry who it is across runtimes, and no cryptographic way to prove that an agent is what it claims to be.

## The Solution

The 01 Protocol defines a single portable file format — `.01ai` — that gives any AI agent:

| Capability | How |
|---|---|
| **Persistent identity** | Durable `instanceId`, name, descriptor, lifecycle state |
| **Cryptographic verification** | Ed25519 signature over SHA-256 canonical digest |
| **No central registry** | Verification requires only the file and standard crypto primitives |
| **Persistent memory** | Three-layer memory vault with Merkle root bound to identity |
| **Lifecycle management** | Signed state machine: UNINITIALIZED → ACTIVE → FROZEN/ARCHIVED/DELETED |
| **Platform agnosticism** | Works with every major AI platform — no whitelist, no integration required |
| **Forward compatibility** | Files created today verify correctly on any future conforming implementation |

> **The specification is patent pending (US).** Not to restrict it — to protect it. No single corporation will be able to lock this standard down or fragment the interoperability it guarantees.

---

## The .01ai File

```json
{
  "instanceId":          "a3f9c2e1b4d87650a3f9c2e1b4d87650",
  "name":                "ResearchAgent",
  "descriptor":          "Autonomous research agent specializing in technical documentation",
  "lifecycleState":      "ACTIVE",
  "evolutionCounter":    12,
  "memoryMerkleRoot":    "sha256:8f3a1b2c...",
  "parentInstanceIds":   [],
  "parentChecksums":     [],
  "createdAt":           "2026-01-14T09:00:00.000Z",
  "updatedAt":           "2026-03-01T14:22:10.000Z",
  "integrityChecksum":   "<sha256-hex-64-chars>",
  "signerPublicKey":     "<ed25519-public-key-hex-64-chars>",
  "signature":           "<ed25519-signature-hex-128-chars>"
}
```

The file is self-contained. Verification requires no network call, no external service, no registry lookup — only the file itself and ~20 lines of standard cryptographic code.

---

## Persistent Memory

Memory is the most important capability the 01 Protocol adds beyond identity. Agents do not start from zero.

### Three-Layer Memory Model

```
operationalCache   — working memory for the current session (not signed)
persistentVault    — long-term entries, approved by the operator
verifiedEntries    — cryptographically confirmed, injected at runtime
```

### The Memory Pipeline

```
session transcript
      ↓
[extraction engine: salience scoring]
      ↓
candidateMemory (not yet trusted)
      ↓
[approval workflow — human or rule-based]
      ↓
persistentVault
      ↓
[verification step]
      ↓
verifiedEntries → injected into agent context at runtime
```

### Memory Salience Scoring

The extraction engine scores each candidate memory entry before it enters the pipeline:

```
S = (α × Novelty + β × Engagement + γ × EntityWeight) × e^(−λ × t)

α = 0.4   (novelty weight)
β = 0.35  (engagement weight)
γ = 0.25  (entity weight)
λ = 0.5   (temporal decay rate)
```

Only entries above the salience threshold proceed to the approval workflow.

### Memory Types

| Type | Description |
|---|---|
| `summary` | High-level summary of a topic, project, or agent capability |
| `task-context` | Specific task, its goal, approach, and outcome |
| `project-history` | Ongoing project context and accumulated knowledge |
| `decision` | A specific decision made and the reasoning behind it |
| `achievement` | A completed goal or milestone |
| `learning` | A skill, technique, or domain insight acquired |
| `note` | Freeform annotation or preference |

### Merkle-Bound Memory

Approved memory entries are hashed into a binary Merkle tree. The root hash is signed into the agent's identity record — making the complete memory set cryptographically verifiable.

```
agentId.memoryMerkleRoot = merkleRoot(persistent + verified entries)
agentId.signature = ed25519Sign(computeSignedDigest(agentId))
```

Any modification to any memory entry — adding, removing, or altering — changes the Merkle root and invalidates the agent's signature. Tampering is mathematically detectable.

### Portable Bundles

A `.01bundle` file packages identity and memory vault together for transport:

```json
{
  "bundleVersion":  "1.0",
  "bundleId":       "<uuid>",
  "createdAt":      "<ISO 8601>",
  "identity":       { "...01ai record..." },
  "memoryVault":    { "...vault contents..." }
}
```

---

## Verification

### Algorithm (any language, ~20 lines)

```
1. Read file, enforce size limit (≤ 1 MB)
2. Parse JSON with nesting depth guard (≤ 8 levels)
3. Enforce field limits: strings ≤ 8,000 chars, arrays ≤ 256 elements, keys ≤ 64 per object
4. Reject banned keys: __proto__, constructor, prototype
5. Validate required fields are present and correctly typed
6. Validate instanceId format: 32-char lowercase hex
7. Validate signerPublicKey: 64-char hex (Ed25519 public key)
8. Validate signature: 128-char hex (Ed25519 signature)
9. Validate integrityChecksum: 64-char hex (SHA-256 digest)
10. Validate lifecycleState is one of the known states
11. Build canonical payload — fields in this exact order:
    instanceId, name, descriptor, lifecycleState, evolutionCounter,
    memoryMerkleRoot, parentInstanceIds, parentChecksums, createdAt
12. SHA-256 hash the UTF-8 encoded canonical payload
13. ed25519Verify(signature, digest, signerPublicKey)
14. Return verified result with any warnings
```

### Security Constraints

| Constraint | Value | Reason |
|---|---|---|
| Max file size | 1 MB | Prevents memory exhaustion |
| Max JSON nesting | 8 levels | Prevents stack overflow |
| Max string length | 8,000 chars | Prevents memory abuse |
| Max array length | 256 elements | Prevents unbounded iteration |
| Max keys per object | 64 | Prevents hash collision attacks |
| Banned keys | `__proto__`, `constructor`, `prototype` | Prevents prototype pollution |
| Canonical field order | Fixed | Ensures deterministic verification across implementations |

### Compliance Levels

| Level | What it means |
|---|---|
| **Reader** | Parse and display `.01ai` files with input validation |
| **Verifier** | Full Ed25519 + SHA-256 verification with all security guards |
| **Full Implementation** | Lifecycle management, memory Merkle, platform adapters, bundle support |

---

## Lifecycle State Machine

```
UNINITIALIZED
      ↓ initial_activation
    ACTIVE ──────────────────────────────────────────────┐
      │                                                   │
      ├──[user_freeze / system_freeze]──→ FROZEN          │
      │         │                          │              │
      │         │ [resume_from_freeze]      │              │
      │         └──────────────────────────┘              │
      │                                                   │
      ├──[archive]──→ ARCHIVED ──[unarchive]──→ ACTIVE    │
      │                                                   │
      ├──[transfer_initiated]──→ TRANSFERRING             │
      │         │                    │                    │
      │         │ [transfer_completed│/ transfer_cancelled]│
      │         └────────────────────┘                    │
      │                                                   │
      └──[deletion_requested]──→ DELETED ◀────────────────┘
                                   ║
                             (terminal — no
                              outgoing transitions)
```

Every state transition is re-signed with the agent's private key. The `evolutionCounter` increments with each signed update, creating a tamper-evident chain.

---

## Platform Compatibility

01 Protocol works with every platform that accepts a system prompt — which is all of them.

**Hosted:** Claude · OpenAI / GPT · Gemini · Groq · Mistral · Cohere · Perplexity · Grok / xAI

**Local:** Ollama · LM Studio · Jan.ai · any llama.cpp server

**Routers & Hubs:** OpenRouter · Together AI · Replicate · HuggingFace Inference · any OpenAI-compatible endpoint

**Frameworks:** LangChain · CrewAI · AutoGen · Open WebUI · AnythingLLM · any framework that accepts a system prompt

**Converting an existing agent** takes under 2 minutes. No API changes required from the platform. See [01ai.ai](https://01ai.ai) → Create.

---

## Quickstart

### Install the TypeScript reference implementation

```bash
npm install @01ai/core
```

### Mint a new agent

```typescript
import { mintAgentId, generateSigningKeypair } from '@01ai/core';

const keypair = generateSigningKeypair('my-signer-id');

const agent = await mintAgentId({
  templateId:   'research-v1',
  editionId:    'edition-001',
  templateAgentId: '<parent-template-id>',
  systemPrompt: 'You are a research assistant...',
  capabilities: ['research', 'summarization'],
  keypair,
});

// agent is a signed .01ai record — save it, share it, verify it anywhere
```

### Verify an agent

```typescript
import { verifyAgentId } from '@01ai/core';

const result = verifyAgentId(agent);
// { ok: true } or { ok: false, reason: string }
```

### Try it without code

**[→ Create or verify an agent in your browser](https://01ai.ai)** — 100% offline, no account required.

---

## Repository Structure

```
spec/
├── SPEC.md                    ← The canonical specification
├── CHANGELOG.md               ← Version history
├── CONTRIBUTING.md            ← How to contribute
├── SECURITY.md                ← Vulnerability reporting
├── docs/
│   ├── test-vectors.md        ← Canonical test inputs/outputs for verifier compliance
│   └── implementations.md    ← Community verifier implementations by language
└── packages/                  ← Reference implementation (TypeScript/Node.js)
    ├── core/                  ← Identity engine, lifecycle, memory, platform adapters
    └── types/                 ← Zod schemas and TypeScript types
```

---

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md). The highest-value contributions are:

1. **Verifier implementations** in languages beyond TypeScript — Python, Go, Rust, Java
2. **Spec feedback** — ambiguities, edge cases, or missing constraints
3. **Test vector additions** — new cases that existing implementations should handle
4. **Platform adapter documentation** — how to inject identity on specific platforms

Open a [Discussion](../../discussions) before submitting a PR that changes the spec.

---

## License

MIT. See [LICENSE](./LICENSE).

The 01 Protocol specification is patent pending (US). The patent is held to protect the open standard from proprietary enclosure — not to restrict use. Implementations of this spec are covered under the MIT license.

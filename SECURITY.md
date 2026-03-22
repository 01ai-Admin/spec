# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Yes |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by emailing: **info@01ai.ai**

Include in your report:
- A clear description of the issue
- Which component is affected (spec, reference implementation, app)
- Steps to reproduce (if applicable)
- Your assessment of severity and impact
- Whether you are willing to be credited in the disclosure

You will receive an acknowledgement within 72 hours. We aim to assess and communicate a resolution timeline within 7 days.

---

## Scope

### In Scope

- **Specification vulnerabilities** — errors in the spec that could cause conforming implementations to be insecure (e.g. a verification step that can be bypassed)
- **Reference implementation bugs** — vulnerabilities in `@01ai/core` or `@01ai/types` packages
- **App vulnerabilities** — issues in the 01AI browser app that could compromise verification integrity, expose private keys, or allow injection attacks
- **Input guard bypasses** — any input that passes the parse guards but causes incorrect behavior in a conforming implementation

### Out of Scope

- Issues in third-party dependencies (report to those projects directly)
- Denial-of-service via legitimate large inputs that are within spec limits
- Social engineering attacks
- Physical access scenarios
- Issues in demonstration agents (e.g. `john-01ai-guru.01ai`) — these are examples only

---

## Security Properties of the 01 Protocol

Understanding what the protocol does and does not guarantee:

### What the spec guarantees

- **Integrity** — a `.01ai` file that passes verification has not been tampered with since it was signed
- **Origin** — the file was signed by the holder of the Ed25519 private key embedded in the record
- **Determinism** — any correct verifier produces the same result for the same file

### What the spec does not guarantee

- **Key custody** — the spec does not define how private keys are stored or protected. Key custody is the responsibility of the implementation and the operator.
- **Identity of the human or organization behind an agent** — the spec verifies that a file was signed by a specific keypair. It does not verify who controls that keypair.
- **Prevention of copying** — a `.01ai` file can be copied. The spec proves integrity of the file, not exclusive possession of it.
- **Authorization** — who is permitted to use or act on an agent's behalf is above the identity layer and is the responsibility of the application.

---

## Implementation Security Notes

If you are implementing the 01 Protocol, these are the most important security considerations:

1. **Enforce all input guards** before any parsing. Never skip size, depth, or field length checks.
2. **Use a constant-time Ed25519 library.** Do not implement signature verification yourself. Use an audited, well-maintained library (e.g. `@noble/curves`).
3. **Never log or store private keys.** Private keys are show-once at mint time. After the user saves theirs, your implementation must not retain it.
4. **Render agent content as plain text.** The `descriptor` and memory entry fields can contain arbitrary user-supplied strings. Never render them as HTML or Markdown without sanitization.
5. **Validate field formats before using them.** Always check `instanceId`, `signerPublicKey`, `signature`, and `integrityChecksum` format before passing to crypto functions.
6. **Do not trust `lifecycleState` for access control.** Lifecycle state is informational. It tells you the agent's last recorded state — not whether an actor is currently authorized to use the agent.

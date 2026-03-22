# Community Implementations

This page lists known implementations of the 01 Protocol verification algorithm across languages and frameworks.

To add your implementation, open a pull request updating this file.

---

## Submission Requirements

An implementation must:

1. Pass all test vectors in [test-vectors.md](./test-vectors.md)
2. Enforce all input guards (SPEC.md §6)
3. Be publicly available (open source preferred)
4. Include documentation on how to run the test vectors

---

## Compliance Level Key

| Symbol | Level |
|---|---|
| R | Reader — parse and display |
| V | Verifier — full cryptographic verification |
| F | Full Implementation — lifecycle + memory + minting |

---

## Reference Implementation

| Language | Repo | Level | Notes |
|---|---|---|---|
| TypeScript / Node.js | [01-protocol/spec](https://github.com/01-protocol/spec) | F | Canonical reference implementation — `@01ai/core` |

---

## Community Implementations

*None yet. Be the first.*

If you implement a verifier in Python, Go, Rust, Java, Swift, Kotlin, C#, or any other language, submit a PR to add it here.

The verification algorithm is fully specified in SPEC.md §5 and takes approximately 20–40 lines of code in most languages using standard Ed25519 and SHA-256 libraries.

---

## Implementation Notes

### Recommended Crypto Libraries

These are well-audited, widely used libraries. Use your own judgment — the spec does not mandate a specific library.

| Language | Ed25519 Library | SHA-256 Library |
|---|---|---|
| TypeScript/JS | `@noble/curves` | `@noble/hashes` |
| Python | `cryptography` or `PyNaCl` | `hashlib` (stdlib) |
| Go | `crypto/ed25519` (stdlib) | `crypto/sha256` (stdlib) |
| Rust | `ed25519-dalek` | `sha2` |
| Java | `java.security` (stdlib) | `java.security.MessageDigest` (stdlib) |
| Swift | `CryptoKit` (stdlib) | `CryptoKit` (stdlib) |
| C# | `System.Security.Cryptography` (stdlib) | `System.Security.Cryptography` (stdlib) |

### Common Mistakes

1. **Wrong canonical field order** — fields must be in the fixed order from SPEC.md §4.1, not alphabetical.
2. **Signing the hex string instead of the digest bytes** — sign the raw SHA-256 digest bytes, not the hex representation.
3. **Skipping input guards** — all guards must run before JSON parsing, not after.
4. **Including extension fields in the canonical payload** — `x-` fields are not signed.
5. **Case sensitivity** — all hex values must be lowercase. Verify that your library outputs lowercase hex or normalize before comparison.

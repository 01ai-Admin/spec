# Contributing to 01 Protocol

Thank you for your interest in contributing. This is an open specification project — contributions that improve clarity, correctness, and ecosystem reach are welcome.

---

## Types of Contributions

### 1. Verifier Implementations (Highest Value)

Implementations of the verification algorithm in languages beyond TypeScript are the most valuable contributions. See [docs/implementations.md](./docs/implementations.md) for the current list and what's needed.

A compliant verifier must:
- Pass all test vectors in [docs/test-vectors.md](./docs/test-vectors.md)
- Implement all input guards (§6 of SPEC.md)
- Return deterministic pass/fail results
- Be submitted with tests demonstrating test vector compliance

### 2. Spec Feedback

If you find an ambiguity, contradiction, or missing constraint in SPEC.md, open an issue using the **Spec Issue** template. Include:
- The specific section and paragraph
- What the spec says
- Why it is ambiguous or incorrect
- What you believe the correct behavior should be

### 3. Test Vector Additions

Additional test vectors improve the reliability of all implementations. See [docs/test-vectors.md](./docs/test-vectors.md) for the format. Good candidates include:
- Edge cases in field validation (boundary values, Unicode, empty strings)
- Lifecycle state edge cases
- Memory Merkle tree edge cases (empty vault, single entry, odd-length entry sets)

### 4. RFC — Spec Change Proposals

Significant changes to the specification (new fields, changed behavior, new transport formats) require an RFC. Use the **RFC** issue template. RFCs are discussed in GitHub Discussions before a PR is submitted.

---

## What We Do Not Accept

- Changes to the canonical field order (§4.1) — this breaks all existing signed records
- Changes to the cryptographic algorithm choices — Ed25519 and SHA-256 are fixed
- Addition of required fields — new required fields break all existing implementations
- Input guard relaxation — the guards exist for security reasons and cannot be weakened

---

## Workflow

1. Open an issue or discussion before writing code for anything non-trivial
2. Fork the repo and create a feature branch
3. Make your changes with clear commits
4. Submit a pull request using the PR template
5. Respond to review feedback

For spec changes: the PR will not be merged until the corresponding test vectors are added and all existing test vectors still pass.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). Be direct, be respectful, stay on topic.

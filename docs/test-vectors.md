# Test Vectors

Conforming verifier implementations MUST produce the results specified in this document for the given inputs. All test vectors use the same cryptographic algorithm: Ed25519 + SHA-256.

---

## How to Use These Vectors

1. Implement the verification algorithm per SPEC.md §5.
2. For each vector, feed the input to your verifier.
3. Assert the output matches `expectedResult`.
4. Emit the warnings listed in `expectedWarnings` (order does not matter).

All hex values are lowercase. Timestamps are ISO 8601 UTC.

---

## Vector Format

```
id:              unique identifier for this test case
description:     what this vector tests
input:           the raw JSON string to feed to the verifier
expectedResult:  "valid" or "invalid"
expectedError:   error code if invalid (omit if valid)
expectedWarnings: list of warning strings (may be empty)
```

---

## Section 1: Input Guard Vectors

### TV-GUARD-001 — File too large

```
id:             TV-GUARD-001
description:    Input exceeds 1,000,000 byte limit
input:          A JSON string padded to 1,000,001 bytes (e.g. valid record + large x-padding field)
expectedResult: invalid
expectedError:  TOO_LARGE
```

### TV-GUARD-002 — Invalid JSON

```
id:             TV-GUARD-002
description:    Input is not valid JSON
input:          "{ instanceId: 'not json' }"
expectedResult: invalid
expectedError:  INVALID_JSON
```

### TV-GUARD-003 — JSON root is array

```
id:             TV-GUARD-003
description:    Root JSON value is an array, not an object
input:          "[1, 2, 3]"
expectedResult: invalid
expectedError:  BAD_ROOT
```

### TV-GUARD-004 — Nesting depth exceeded

```
id:             TV-GUARD-004
description:    JSON nesting depth exceeds 8 levels
input:          Valid record with one field containing a 9-deep nested object
expectedResult: invalid
expectedError:  DEPTH_EXCEEDED
```

### TV-GUARD-005 — String field too long

```
id:             TV-GUARD-005
description:    The descriptor field exceeds 8,000 characters
input:          Valid record with descriptor field set to a string of 8,001 chars
expectedResult: invalid
expectedError:  STRING_TOO_LONG
```

### TV-GUARD-006 — Prototype pollution via __proto__

```
id:             TV-GUARD-006
description:    Input contains __proto__ key
input:          { "instanceId": "...", "__proto__": { "isAdmin": true }, ...other required fields }
expectedResult: invalid
expectedError:  PROTOTYPE_POLLUTION
```

### TV-GUARD-007 — Prototype pollution via constructor

```
id:             TV-GUARD-007
description:    Input contains constructor key at nested level
input:          Valid record with one extension field containing { "constructor": { "name": "Object" } }
expectedResult: invalid
expectedError:  PROTOTYPE_POLLUTION
```

---

## Section 2: Field Validation Vectors

### TV-FIELD-001 — Missing required field (instanceId)

```
id:             TV-FIELD-001
description:    instanceId field is absent
input:          Valid record minus the instanceId field
expectedResult: invalid
expectedError:  MISSING_REQUIRED_FIELD
```

### TV-FIELD-002 — instanceId wrong format (not 32-char hex)

```
id:             TV-FIELD-002
description:    instanceId is 31 characters
input:          Valid record with instanceId set to "a3f9c2e1b4d87650a3f9c2e1b4d876" (31 chars)
expectedResult: invalid
expectedError:  INVALID_FIELD_FORMAT
```

### TV-FIELD-003 — evolutionCounter is negative

```
id:             TV-FIELD-003
description:    evolutionCounter is -1
input:          Valid record with evolutionCounter: -1
expectedResult: invalid
expectedError:  INVALID_FIELD_VALUE
```

### TV-FIELD-004 — evolutionCounter is a float

```
id:             TV-FIELD-004
description:    evolutionCounter is 1.5
input:          Valid record with evolutionCounter: 1.5
expectedResult: invalid
expectedError:  INVALID_FIELD_VALUE
```

### TV-FIELD-005 — lifecycleState is unrecognized

```
id:             TV-FIELD-005
description:    lifecycleState is "SUSPENDED" (not a valid state)
input:          Valid record with lifecycleState: "SUSPENDED"
expectedResult: invalid
expectedError:  INVALID_FIELD_VALUE
```

### TV-FIELD-006 — signature is wrong length

```
id:             TV-FIELD-006
description:    signature is 126 chars (should be 128)
input:          Valid record with signature trimmed to 126 hex chars
expectedResult: invalid
expectedError:  INVALID_FIELD_FORMAT
```

---

## Section 3: Cryptographic Verification Vectors

### TV-CRYPTO-001 — Tampered descriptor

```
id:             TV-CRYPTO-001
description:    A valid signed record with the descriptor field modified after signing
expectedResult: invalid
expectedError:  CHECKSUM_MISMATCH (or SIGNATURE_INVALID, depending on implementation order)
```

### TV-CRYPTO-002 — Tampered lifecycleState

```
id:             TV-CRYPTO-002
description:    A valid signed record with lifecycleState changed from ACTIVE to FROZEN after signing
expectedResult: invalid
expectedError:  CHECKSUM_MISMATCH
```

### TV-CRYPTO-003 — Tampered evolutionCounter

```
id:             TV-CRYPTO-003
description:    A valid signed record with evolutionCounter incremented from 1 to 2 after signing
expectedResult: invalid
expectedError:  CHECKSUM_MISMATCH
```

### TV-CRYPTO-004 — Wrong signature (different key)

```
id:             TV-CRYPTO-004
description:    A valid record whose signature was produced by a different Ed25519 keypair
                than the one in signerPublicKey
expectedResult: invalid
expectedError:  SIGNATURE_INVALID
```

### TV-CRYPTO-005 — Signature over wrong canonical order

```
id:             TV-CRYPTO-005
description:    A record signed using alphabetically sorted keys instead of the fixed canonical
                order defined in SPEC.md §4.1
expectedResult: invalid
expectedError:  SIGNATURE_INVALID
```

---

## Section 4: Warning Vectors

### TV-WARN-001 — updatedAt before createdAt

```
id:               TV-WARN-001
description:      updatedAt is earlier than createdAt (signature is still valid)
expectedResult:   valid
expectedWarnings: ["updatedAt is earlier than createdAt"]
```

### TV-WARN-002 — Future-dated createdAt

```
id:               TV-WARN-002
description:      createdAt is more than 60 seconds in the future (signature still valid)
expectedResult:   valid
expectedWarnings: ["createdAt is more than 60 seconds in the future"]
```

### TV-WARN-003 — DELETED state

```
id:               TV-WARN-003
description:      lifecycleState is DELETED (signature is valid)
expectedResult:   valid
expectedWarnings: ["agent lifecycle state is DELETED"]
```

### TV-WARN-004 — evolutionCounter 0 with parents

```
id:               TV-WARN-004
description:      evolutionCounter is 0 but parentInstanceIds is non-empty (signature valid)
expectedResult:   valid
expectedWarnings: ["evolutionCounter is 0 but parentInstanceIds is non-empty"]
```

---

## Section 5: Memory Merkle Vectors

### TV-MERKLE-001 — Empty vault root

```
id:          TV-MERKLE-001
description: An agent with no memory entries
             memoryMerkleRoot must equal the SHA-256 of the empty string
expected:    memoryMerkleRoot = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

### TV-MERKLE-002 — Tampered memory entry

```
id:             TV-MERKLE-002
description:    An agent record with a valid memoryMerkleRoot, where one memory entry in
                the vault has been altered after the root was computed and signed
expectedResult: The Merkle proof for the altered entry will fail verification.
                The agent's own signature remains valid (the signed record is unmodified),
                but the vault integrity check fails.
```

---

## Adding New Vectors

Submit test vector additions via pull request. Each vector must include:

1. A unique `id` following the existing `TV-CATEGORY-NNN` format
2. A clear `description` of what edge case is being tested
3. Enough detail to reproduce the input (or a canonical JSON example)
4. The `expectedResult` and, if invalid, the `expectedError`
5. Any `expectedWarnings`

Vectors that reveal a gap in the spec should also include a reference to the spec section being clarified.

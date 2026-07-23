# MGM — Multilinear Galois Mode AEAD (RFC 9058)

This document describes the MGM AEAD mode implemented by `package mgm`: what it
is, its specification, the notable points of this implementation, and the test
vectors that pin it. For the public API and a usage example see the
[package README](README.md).

## What it is

MGM (Multilinear Galois Mode) is a nonce-based AEAD block-cipher mode of
operation standardized in **RFC 9058** and in the Russian recommendation
**R 1323565.1.026-2019** ("Information technology. Cryptographic data
security. Authenticated encryption block cipher operation modes"). It is the
GOST analogue of AES-GCM: a single pass produces a CTR-style ciphertext plus a
polynomial (Galois-field) authentication tag computed over the additional data
and the ciphertext.

MGM is defined for both GOST block sizes:

- `n = 128` bits (16 bytes) — Kuznyechik / "Grasshopper" (GOST R 34.12-2015).
- `n = 64` bits (8 bytes) — Magma (GOST R 34.12-2015 64-bit).

### Where this module uses it

MGM is **not wired into any TLS suite, OID, or handshake path** in this
module. The implementation lives in `mgm/mgm.go`; the TLS GOST AEAD path in
production is MGM's cousin, Kuznyechik/Magma-CTR-ACPKM + OMAC (RFC 9189 suites
`0xC100`/`0xC101` — see [`../ctracpkm/DESIGN.md`](../ctracpkm/DESIGN.md) and
[`../omac/DESIGN.md`](../omac/DESIGN.md)). MGM is provided as a standalone
AEAD for callers that want the RFC 9058 construction directly, over either
[`../kuznyechik/DESIGN.md`](../kuznyechik/DESIGN.md) or
[`../magma/DESIGN.md`](../magma/DESIGN.md).

## Specification

All section references are to RFC 9058 unless noted. MGM is parameterized by a
block cipher `E_K` with block size `n` bits (`n ∈ {64, 128}`), a key `K`, and a
tag length `S` bits.

### Sizes and parameters

| Parameter | Kuznyechik (n=128) | Magma (n=64) |
|---|---|---|
| Block size | 16 bytes | 8 bytes |
| Key size | 32 bytes | 32 bytes |
| Nonce / ICN size | 16 bytes | 8 bytes |
| Tag size `S` (bytes) | 4 … 16 | 4 … 8 |
| Max data per **field** | `2^(n/2-3) − 1` bytes | same |
| Combined bound (§4.1) | `\|A\| + \|P\| < 2^(n/2)` bits | same |

Tag-size bound (§4: `32 ≤ S ≤ n` bits) is enforced in bytes by `NewMGM`
(`4 ≤ tagSize ≤ blockSize`, else an error).

Per-field length cap: `2^(n/2-3) − 1` bytes — for Magma (n=64) that is
`2^29 − 1` bytes (~512 MiB). Exceeding this would silently truncate the length
block and forge a wrong tag, so `Seal`/`Open` reject it instead.

The RFC's combined bound `|A| + |P| < 2^(n/2)` bits is checked separately from
the per-field cap. For Magma this additionally rules out two ~512 MiB fields
used together (their sum would reach `2^32` bits); for Kuznyechik the
per-field cap already implies compliance on any in-memory buffer.

> **32-bit portability.** On 32-bit platforms (`GOARCH=386`/`arm`) the
> Kuznyechik shift amount `n/2-3 = 61` does not fit a signed platform `int`.
> The field-length cap computation detects this by comparing the shift
> against `bits.UintSize-1` and falls back to the maximum representable `int`
> — effectively unbounded for any buffer that fits in memory — instead of
> silently returning a negative cap.

### Nonce / ICN constraint (§3, §4.1)

The nonce is the **Initial Counter Nonce (ICN)**, exactly `n` bits. Its most
significant bit MUST be 0 — that bit is reserved as a domain-separation prefix
(`0` for the encryption counter, `1` for the MAC counter). The mode forms two
counters by prepending one bit to the ICN:

- Encryption counter seed: `Y_1 = E_K(0¹ ‖ ICN)`
- MAC counter seed: `Z_1 = E_K(1¹ ‖ ICN)`

In a byte-oriented implementation, "prepend a bit" is realized by forcing the
top bit of byte 0: clear it (`&0x7F`) for the encryption pass, set it
(`|0x80`) for the MAC pass.

### Counter increments (§3)

The block is split into two halves `A = L ‖ R`, each `n/2` bits.

- `incr_r(A) = L ‖ Vec_{n/2}(Int_{n/2}(R) + 1)` — increment the **right**
  (low) half. Used for the encryption counter `Y`.
- `incr_l(A) = Vec_{n/2}(Int_{n/2}(L) + 1) ‖ R` — increment the **left**
  (high) half. Used for the MAC counter `Z`.

Both increments are big-endian over their half: the integer is taken MSB-first
across the half, incremented modulo `2^(n/2)`, with carry propagating toward
the more-significant bytes within that half only — it never crosses into the
other half.

### Encryption pass (§4.1)

Plaintext `P = P_1 ‖ … ‖ P_q` (last block may be partial, length `p` bytes).

```
Y_1 = E_K(0¹ || ICN)
for i = 1 … q:
    C_i = P_i XOR E_K(Y_i)          # last block: XOR with MSB_p(E_K(Y_q))
    Y_{i+1} = incr_r(Y_i)
```

A new keystream block `E_K(Y_i)` is produced for every plaintext block; `Y` is
advanced by `incr_r` after each. The partial final block XORs only the
leading `p` bytes.

> **Two levels of encryption — do not conflate them.** `Y_1` is itself the
> cipher output of the (masked) nonce: `Y_1 = E_K(0¹ ‖ ICN)`. The per-block
> keystream is then a *second* application, `E_K(Y_i)`. So the first
> plaintext block is masked with `E_K(E_K(0¹ ‖ ICN))` — the nonce is
> encrypted twice for block 1. Setting `Y_1` directly to the masked ICN
> (skipping that first encryption) is a common bug and produces a
> wrong ciphertext.

### Authentication pass (§4.1)

Inputs to the MAC are the **additional data** `A = A_1 … A_h` and the
**ciphertext** `C = C_1 … C_q` — the MAC runs over ciphertext, not plaintext
(encrypt-then-MAC). `sum` starts at 0.

```
Z_1 = E_K(1¹ || ICN)
# additional data
for i = 1 … h:
    H_i = E_K(Z_i)
    sum = sum XOR ( H_i  ⊗  A_i )       # A_h padded with zeros on the right
    Z_{i+1} = incr_l(Z_i)
# ciphertext
for j = 1 … q:
    H_{h+j} = E_K(Z_{h+j})
    sum = sum XOR ( H_{h+j}  ⊗  C_j )   # C_q padded with zeros on the right
    Z_{h+j+1} = incr_l(Z_{h+j})
# length block
H_{h+q+1} = E_K(Z_{h+q+1})
sum = sum XOR ( H_{h+q+1}  ⊗  ( len(A) || len(C) ) )
T   = MSB_S( E_K(sum) )
```

`⊗` is multiplication in `GF(2^n)`. `len(A)` and `len(C)` are the **bit**
lengths of the additional data and ciphertext, each encoded as an `n/2`-bit
big-endian integer, concatenated into one `n`-bit block.

Key contract details:

- Every full or partial block consumes one fresh `H_i = E_K(Z_i)`, then
  advances `Z` by `incr_l`. AD blocks and ciphertext blocks share the
  **same** `Z` sequence — there is no reset between AD and ciphertext, `Z`
  keeps climbing across the whole MAC.
- Partial AD / ciphertext blocks are zero-padded to a full block on the
  **right** (least-significant end) before multiplication.
- The length block consumes the next `H` after the last data block.
- The final tag is `E_K(sum)` truncated to the `S` most-significant bytes
  (`MSB_S`) — the **first** `S` bytes of the cipher output.

### GF(2^n) multiplication and reduction polynomials (§3)

The field is `GF(2^n)` with:

- `n = 64`: `f(w) = w^64 + w^4 + w^3 + w + 1` → reduction constant **`0x1b`**.
- `n = 128`: `f(w) = w^128 + w^7 + w^2 + w + 1` → reduction constant **`0x87`**.

Multiplication is the schoolbook shift-and-add (XOR) algorithm over the
field. The byte string is interpreted **big-endian**: the first byte holds
the most significant coefficients. On each step the accumulator is XORed with
the running shifted operand when the corresponding bit of the other operand
is set; the operand is shifted left by one (toward more-significant) and
reduced by XOR-ing the reduction constant into the low byte whenever the top
bit overflowed.

## Implementation notes

Points where a naive reading diverges from the standard; each is exercised by
a test vector below.

1. **Endianness of the GF operands is BIG-endian — the surprising part.**
   GOST is little-endian in many other places (key scalars, curve points), but
   MGM's field elements are big-endian byte strings: the first byte of a
   block is the most-significant field coefficient. A reimplementation
   working purely with `[]byte` and `encoding/binary.BigEndian` needs no
   byte-swap — the bytes are already in field order.

2. **Two distinct counters with two distinct increments.** The single most
   common bug is using one counter, or incrementing the wrong half. `Y`
   (encryption) advances with `incr_r` (low half); `Z` (MAC) advances with
   `incr_l` (high half). They are seeded from the same ICN but with different
   domain bits (`0` vs `1` in the MSB).

3. **The MSB-must-be-0 nonce rule is enforced by rejection, not masking.**
   `validateNonce` panics if the caller supplies a nonce with the top bit set
   (`mgm.go:validateNonce`), matching the reference-implementation convention
   of surfacing this as a caller bug rather than silently masking it.

4. **The length block is BIT length, big-endian, split n/2 + n/2.** `len(A)`
   and `len(C)` are bit lengths (`bytes * 8`), each an `n/2`-bit big-endian
   field, concatenated MSB-first. For `n=128` that is two `BigEndian.PutUint64`
   halves; for `n=64` it is two `BigEndian.PutUint32` halves. A
   reimplementation must multiply by 8 before encoding, and must not encode
   the byte length directly.

5. **The MAC runs over ciphertext, not plaintext (encrypt-then-MAC).** `Seal`
   first runs the encryption pass to produce ciphertext, then authenticates
   the ciphertext. `Open` authenticates the received ciphertext first,
   compares the tag in constant time, and only then decrypts — plaintext is
   never released before verification succeeds.

6. **Partial-block zero padding is on the right (low/least-significant end).**
   Both AD and data partial blocks are right-zero-padded to a full block
   before the GF multiply. The keystream XOR for a partial final encryption
   block touches only the real `p` bytes, not the padded ones.

7. **The GF(2^128) multiply is a Horner-form accumulator shift, not a
   shift-the-multiplicand loop.** Some reference implementations (e.g.
   gogost, gost-engine) compute the 128-bit product as a 64+63-iteration
   split plus a trailing conditional XOR — an artifact of shifting the
   *multiplicand* rather than the accumulator, which needs a special-cased
   final step to avoid an extra shift. This implementation instead scans the
   second operand MSB-first and, from the second iteration on, shifts the
   *accumulator* left by one (reducing on overflow) before conditionally
   XOR-ing in the first operand. That formulation is naturally correct for
   both block sizes with no special-casing and no off-by-one to track, and it
   produces bit-identical results to the split-loop form.

8. **A single `*MGM` value is reusable across messages but is not
   goroutine-safe.** `Seal`/`Open` overwrite the internal nonce copy and reset
   the running GF accumulator on every call, so the same value can process
   many messages sequentially — but its scratch buffers (`yi`, `zi`, `ek`,
   `sum`, …) are shared mutable state, so concurrent calls on one `*MGM` race.

9. **No S-box or key-meshing divergences apply to MGM.** The known
   divergences between independent GOST reference implementations — GOST
   28147-89 S-box row order, GOST R 34.11-94 empty-input finalization, and
   CryptoPro key meshing — are all specific to other primitives (a hash
   function's internal step, and GOST 28147 IMIT's re-keying). MGM never
   hashes and does no key meshing of its own; its correctness depends only on
   the underlying Kuznyechik/Magma block ciphers being correct, which is
   verified independently in their own packages.

## Test vectors

### Kuznyechik (n=128), tag = 16 bytes

```
K     = 8899aabbccddeeff0011223344556677 fedcba98765432100123456789abcdef   (32 bytes)
ICN   = 1122334455667700ffeeddccbbaa9988                                    (16 bytes, top bit of byte 0 clear)
A     = 02020202020202020101010101010101
        04040404040404040303030303030303
        ea0505050505050505                                                  (41 bytes)
P     = 1122334455667700ffeeddccbbaa9988
        00112233445566778899aabbcceeff0a
        112233445566778899aabbcceeff0a00
        2233445566778899aabbcceeff0a0011
        aabbcc                                                              (67 bytes)

C     = a9757b8147956e9055b8a33de89f42fc
        8075d2212bf9fd5bd3f7069aadc16b39
        497ab15915a6ba85936b5d0ea9f6851c
        c60c14d4d3f883d0ab94420695c76deb
        2c7552                                                              (67 bytes)
T     = cf5d656f40c34f5c46e8bb0e29fcdb4c                                    (16 bytes)
```

`Seal(nil, ICN, P, A)` must return `C ‖ T`. `Open` of `C ‖ T` returns `P`.
`len(A) = 41*8 = 328` bits, `len(C) = 67*8 = 536` bits; the length block is
`BigEndian64(328) ‖ BigEndian64(536)` = `00000000000001480000000000000218`.

### Magma (n=64), tag = 8 bytes

```
K     = ffeeddccbbaa99887766554433221100 f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
ICN   = 12def06b3c130a59
A     = 0101010101010101020202020202020203030303030303030404040404040404
        0505050505050505ea                                                 (41 bytes)
P     = ffeeddccbbaa99881122334455667700
        8899aabbcceeff0a0011223344556677
        99aabbcceeff0a001122334455667788
        aabbcceeff0a00112233445566778899
        aabbcc                                                             (67 bytes)
C     = c795066c5f9ea03b85113342459185ae
        1f2e00d6bf2b785d940470b8bb9c8e7d
        9a5dd3731f7ddc70ec27cb0ace6fa576
        70f65c646abb75d547aa37c3bcb5c34e
        03bb9c
T     = a7928069aa10fd10
```

These are the canonical R 1323565.1.026-2019 §A worked examples; both are
pinned as known-answer tests in `mgm/mgm_test.go`.

## Conformance testing

The in-package tests (`mgm/mgm_test.go`, `mgm/mgm_internal_test.go`) anchor
the two fixed vectors above, including round-trip and tamper-detection checks
(a single flipped ciphertext or tag byte must make `Open` fail).

In addition, a differential fuzz harness compares this implementation against
an independent reference over random keys, nonces, and additional-data /
plaintext lengths, for both the 64-bit (Magma) and 128-bit (Kuznyechik) block
sizes — asserting `Open(Seal(...)) == plaintext` and that `Seal`'s
`ciphertext ‖ tag` matches the reference byte-for-byte.

```sh
go test ./mgm/
```

## References

- **[RFC 9058](rfc/rfc9058.txt)** — "Multilinear Galois Mode (MGM)".
  - §3 — Basic terms: `MSB_i`, `incr_l`, `incr_r`, the GF(2^64)/GF(2^128) field
    polynomials (`w^64+w^4+w^3+w+1` → `0x1b`; `w^128+w^7+w^2+w+1` → `0x87`).
  - §4 / §4.1 — MGM encryption and tag generation: `Y_1=E_K(0¹‖ICN)`,
    `Z_1=E_K(1¹‖ICN)`, `H_i=E_K(Z_i)`, the `sum`/`T=MSB_S(E_K(sum))`
    recurrence, the `len(A)‖len(C)` block, tag-size bound `32 ≤ S ≤ n` bits.
- **[R 1323565.1.026-2019](rfc/R1323565.1.026-2019.pdf)** — Russian
  recommendation defining MGM and the two worked KATs reproduced above
  (Kuznyechik §A, Magma §A).
- **[RFC 7801](../kuznyechik/rfc/rfc7801.txt)** / **[RFC 8891](../magma/rfc/rfc8891.txt)**
  — the Kuznyechik and Magma block ciphers that MGM drives.

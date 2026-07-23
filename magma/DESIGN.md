# Magma — GOST R 34.12-2015 64-bit block cipher

This document describes the Magma block cipher implemented by `package
magma`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

Magma is the 64-bit-block / 256-bit-key block cipher standardised in **GOST R
34.12-2015** and republished as **RFC 8891**. Cryptographically it is the
**GOST 28147-89 core** (the sibling `gost28147` package; see
[`../gost28147/DESIGN.md`](../gost28147/DESIGN.md)) with two things pinned
down:

1. a single **fixed S-box** — the tc26 param-Z set (`id-tc26-gost-28147-param-Z`,
   OID `1.2.643.7.1.2.5.1.1`); GOST 28147-89 leaves the S-box as a parameter,
   Magma fixes it, and
2. a **byte/word-order flip** relative to legacy 28147-89: RFC 8891 numbers
   bits big-endian / MSB-first, whereas the legacy 28147-89 core is
   little-endian. This flip is why Magma needs its own wrapper instead of
   being a bare alias for 28147-89.

Everything else — the Feistel structure, the round function (mod-2³² key
addition → S-box substitution → 11-bit cyclic left rotate), and the 32-round
schedule (`K1..K8` three times forward, then `K8..K1` reverse) — is identical
to the legacy 28147-89 core.

There is **no GF(2) polynomial reduction** anywhere in Magma. The
linear-mixing GF(2⁸) multiply-and-reduce step belongs to **Kuznyechik**, GOST
R 34.12-2015's 128-bit cipher — a structurally different algorithm implemented
in the sibling `kuznyechik` package.

### Where this module uses it

- The root facade (`gostcrypto.NewMagmaCipher`, `gostcrypto.MagmaEncrypt` /
  `MagmaDecrypt`) wraps this package's `Cipher` as the module's stable
  `[]byte`-in/`[]byte`-out Magma entry point.
- **kexp15** constructs a Magma `cipher.Block` directly
  (`kexp15.go`: `newBlk: func(k []byte) cipher.Block { return magma.NewCipher(k) }`)
  for the Magma leg of GOST TLS key export.
- **ctracpkm**, **omac**, and **mgm** each exercise Magma as one of the two
  supported block ciphers (alongside Kuznyechik) in their test suites,
  covering CTR-ACPKM keystream generation, CMAC, and MGM AEAD over the
  64-bit block.
- TLS suite **0xC101** `GOST2012-MAGMA-MAGMAOMAC` ([RFC 9367](../kuznyechik/rfc/rfc9367.txt)
  §4.3 / [RFC 9189](../gost28147cnt/rfc/rfc9189.txt) §4.4) uses Magma in CTR
  mode plus OMAC; this is the primitive's main real-world consumer.

**Dimensions**

| Quantity | Value | Source |
|---|---|---|
| Block size | 8 bytes (64 bit) | `BlockSize` |
| Key size | 32 bytes (256 bit) | `KeySize` |
| Subkeys | 8 × 32-bit | derived directly from the key in `NewCipher` |
| Rounds (enc/dec) | 32 | `seqEncrypt` / `seqDecrypt` |
| S-box | tc26 param-Z, fixed | `sboxTC26Z` |

## Specification

RFC 8891 defines Magma over bit strings indexed **MSB-first** (big-endian).
The standard never mentions GOST 28147-89; it is a self-contained restatement
whose internals coincide with the 28147-89 core under a byte-order flip. This
implementation reverses to big-endian at the boundary, runs the 28147-89 core,
and reverses back.

### 1. Sizes (RFC 8891 §1)

> "block length of n=64 bits and key length of k=256 bits"

Block = 8 octets, key = 32 octets — same as 28147-89.

### 2. The fixed S-box π (RFC 8891 §4.1)

RFC 8891 §4.1 gives the substitution as eight 16-entry nibble permutations
`Pi'_0 … Pi'_7`, where (in the RFC's big-endian convention) `Pi'_7`
substitutes the **most-significant** nibble and `Pi'_0` the least. Verbatim
from the RFC:

```
Pi'_0 = (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7,  0,  3, 15,  1)
Pi'_1 = ( 6, 8, 2, 3,  9,10,  5,12,  1,14,  4, 7, 11, 13,  0, 15)
Pi'_2 = (11, 3, 5, 8,  2,15, 10,13, 14, 1,  7, 4, 12,  9,  6,  0)
Pi'_3 = (12, 8, 2, 1, 13, 4, 15, 6,  7, 0, 10, 5,  3, 14,  9, 11)
Pi'_4 = ( 7,15, 5,10,  8, 1,  6,13,  0, 9,  3,14, 11,  4,  2, 12)
Pi'_5 = ( 5,13,15, 6,  9, 2, 12,10, 11, 7,  8, 1,  4,  3, 14,  0)
Pi'_6 = ( 8,14, 2, 5,  6, 9,  1,12, 15, 4, 11, 0, 13, 10,  3,  7)
Pi'_7 = ( 1, 7,14,13,  0, 5,  8, 3,  4,15, 10, 6,  9, 12, 11,  2)
```

This is **byte-for-byte the tc26 param-Z S-box** — the same set the
`gost28147` package exposes as `SboxTC26Z`. `package magma` stores the table
in the low-nibble-first convention `s[0..7]`, where `s[i] == Pi'_i` with no
transposition needed:

```
s[0] = {12,4, 6, 2,10, 5,11, 9,14, 8,13, 7, 0, 3,15, 1}   // == RFC Pi'_0
s[1] = {6, 8, 2, 3, 9,10, 5,12, 1,14, 4, 7,11,13, 0,15}   // == RFC Pi'_1
s[2] = {11,3, 5, 8, 2,15,10,13,14, 1, 7, 4,12, 9, 6, 0}   // == RFC Pi'_2
s[3] = {12,8, 2, 1,13, 4,15, 6, 7, 0,10, 5, 3,14, 9,11}   // == RFC Pi'_3
s[4] = {7,15, 5,10, 8, 1, 6,13, 0, 9, 3,14,11, 4, 2,12}   // == RFC Pi'_4
s[5] = {5,13,15, 6, 9, 2,12,10,11, 7, 8, 1, 4, 3,14, 0}   // == RFC Pi'_5
s[6] = {8,14, 2, 5, 6, 9, 1,12,15, 4,11, 0,13,10, 3, 7}   // == RFC Pi'_6
s[7] = {1, 7,14,13, 0, 5, 8, 3, 4,15,10, 6, 9,12,11, 2}   // == RFC Pi'_7
```

This pairing holds because the whole-block byte reversal (below) lands each
RFC `Pi'_i` back on the nibble this low-nibble-first table numbers `i` — the
rows are the literal RFC rows, not to be reversed when transcribing.

### 3. The round function g (RFC 8891 §4.2)

RFC 8891 §4.2 defines, for round key `k`:

> `g[k](a) = (t(Vec32(Int32(a) [+] Int32(k)))) <<<_11`

Read as three steps on a 32-bit half `a`:

1. **Key addition mod 2³²:** `a' = (a + k) mod 2^32`.
2. **Substitution `t`:** split `a'` into eight nibbles and substitute each
   through its π row — `t(a') = Pi'_7(n7) || … || Pi'_0(n0)`.
3. **11-bit cyclic left rotate:** `<<<_11` rotates the 32-bit result left by
   11 bit positions.

This is identical to the 28147-89 round function: same mod-2³² add, same
nibble substitution, same `rotl32(·, 11)`. Magma changes *which* S-box is used
and the *byte order in which `a` is assembled*, nothing in the round function
itself.

### 4. Feistel structure & round schedule (RFC 8891 §4.3)

The 256-bit key splits into eight 32-bit words, big-endian:

```
K1 = k_255..k_224   (most-significant 32 bits)
K2 = k_223..k_192
...
K8 = k_31 ..k_0     (least-significant 32 bits)
```

32 rounds, round-key order:

```
Rounds  1– 8:  K1 K2 K3 K4 K5 K6 K7 K8     (forward)
Rounds  9–16:  K1 K2 K3 K4 K5 K6 K7 K8     (forward)
Rounds 17–24:  K1 K2 K3 K4 K5 K6 K7 K8     (forward)
Rounds 25–32:  K8 K7 K6 K5 K4 K3 K2 K1     (reverse)
```

i.e. **K1..K8 forward 24 rounds, then K8..K1 reverse 8 rounds** — identical to
28147-89's encrypt schedule. Each round is the standard Feistel step
`(L, R) ← (R, L ⊕ g[k](R))`, implemented in `xcrypt` by swapping the operand
*names* each round rather than the underlying data. Decryption uses the
reverse schedule: `K1..K8` forward 8 rounds, then `K8..K1` reverse 24 rounds.

### 5. Mapping a Magma block onto the 28147-89 core

**Key (`NewCipher`):** each 32-bit subkey is read directly as a big-endian word
from the key (`binary.BigEndian.Uint32(key[4*i:4*i+4])`). Reading big-endian
here reproduces RFC 8891 §4.3's `K1 = k_255..k_224` split without a separate
reversal pass — the equivalent of reversing each word and then reading it
little-endian, done in one step.

**Block (`Encrypt`/`Decrypt`, via `crypt`):** reverse all 8 input bytes, split
the reversed buffer little-endian into `N1` (low word) and `N2` (high word),
run the 32-round Feistel core, write the result back with a half-swap
(`N2` to bytes 0-3, `N1` to bytes 4-7), then reverse all 8 bytes again:

```
tmp[j]   = src[7-j]                for j in 0..7      // whole-block reversal in
N1, N2   = LE32(tmp[0:4]), LE32(tmp[4:8])
N1, N2   = 32-round Feistel(N1, N2)
tmp[0:4], tmp[4:8] = LE32(N2), LE32(N1)                // output half-swap
dst[j]   = tmp[7-j]                for j in 0..7      // whole-block reversal out
```

The full-block reversal makes the little-endian core reproduce Magma's
big-endian numbering. Encrypt and Decrypt differ only in which subkey
schedule (`seqEncrypt` vs `seqDecrypt`) is threaded through the same wrapper.

## Implementation notes

Points where a naive reading of the standard is easy to get wrong; each is
exercised by a test vector below.

1. **No S-box parameter.** Unlike `gost28147.NewCipher`, which takes an
   explicit `SBox` argument, `magma.NewCipher` takes only a key — the tc26-Z
   S-box is hardcoded. A reimplementation must not expose an S-box choice on
   the Magma API.

2. **Key reversal is folded into a single big-endian read.** RFC 8891 splits
   the key big-endian; the 28147-89 core historically reads key words
   little-endian. Rather than reversing bytes and then reading little-endian,
   `NewCipher` reads each subkey word directly with `binary.BigEndian.Uint32`
   — same result, fewer steps. Getting this backwards (reading little-endian)
   produces a cipher that runs but matches no Magma test vector.

3. **Whole-block byte reversal, not a per-word reversal.** All 8 bytes of the
   block are reversed together on input and again on output — not reversed
   per 32-bit half. Combined with the key handling above, this reversal is
   the entire structural difference between Magma and a tc26-Z-keyed
   28147-89 core.

4. **Output half-swap.** After the 32-round loop, the low half of the
   pre-reversal buffer holds `N2` and the high half holds `N1` (not `N1`,
   `N2` in round order) — the standard Feistel "final swap" familiar from
   28147-89, applied before the output byte reversal.

5. **No GF reduction.** Magma's only non-linear step is the 4-bit S-box; its
   only diffusion is the 11-bit rotate. There is no GF(2⁸) multiply or
   polynomial reduction anywhere in this package — that belongs to the
   unrelated Kuznyechik linear transform. A reimplementation that pulls in a
   GF-reduction step has confused the two ciphers.

6. **Panic contract.** `NewCipher` panics unless the key is exactly `KeySize`
   (32) bytes; `Encrypt`/`Decrypt` panic if `src` or `dst` is shorter than
   `BlockSize` (8) bytes. Both `Encrypt` and `Decrypt` are safe to call
   in-place (`Encrypt(buf, buf)`) — `crypt` stages through a local 8-byte
   array before writing `dst`.

## Test vectors

### V1. RFC 8891 Appendix A single-block KAT

Verbatim from RFC 8891 Appendix A.3–A.4. Pinned by `TestRFC8891KAT`
(`magma_test.go`) and `TestEncryptDecryptInPlace` (`guard_test.go`).

```
key (32B):        ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
plaintext (8B):   fedcba9876543210
ciphertext (8B):  4ee901e5c2d8ca3d
```

`Encrypt(key, fedcba9876543210)` must produce `4ee901e5c2d8ca3d`, and
`Decrypt(key, 4ee901e5c2d8ca3d)` must recover `fedcba9876543210`.

### V2. Multi-block ECB (GOST R 34.13-2015 §A.2.1)

Pinned by `TestECB_A21` (`magma_test.go`). Exercises cipher-instance reuse
across four 8-byte blocks in ECB mode, both encrypt and decrypt.

```
key: ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
pt:  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
ct:  2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb
```

### V3. Magma ACPKM key meshing (cross-package)

Meshing derives the next key by encrypting the 32-byte `ACPKM_D_const`
(`0x80, 0x81, …, 0x9f`) block-by-block under the current key. Pinned in
`ctracpkm/ctracpkm_test.go`.

```
initialKey: 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
wantK2:     863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0
```

### V4. Property coverage

`FuzzRoundTrip` (`magma_cov_test.go`) checks two algebraic properties over
arbitrary 8-byte blocks, seeded with the RFC 8891 plaintext, the all-zero
block, and the all-ones block:

- `Decrypt(Encrypt(p)) == p` for all inputs.
- In-place `Encrypt(buf, buf)` produces the same ciphertext as out-of-place
  `Encrypt(ct, p)`.

`TestRoundTrip` (`magma_test.go`) additionally checks 10,000 random
key/plaintext round-trips, and `TestSboxPermutation` verifies every S-box row
is a permutation of `0..15`.

## Conformance testing

The in-package tests (`magma/magma_test.go`, `magma/guard_test.go`,
`magma/magma_cov_test.go`) anchor the fixed vectors above, the panic
contract, and in-place operation. In addition, a differential fuzz harness
compares this implementation against an independent reference implementation
over random keys and blocks — the strongest external correctness signal for
the raw cipher. Mode-level interoperability (CTR, OMAC, MGM, ACPKM built on
top of this block cipher) is anchored against real GOST TLS suites
(`GOST2012-MAGMA-MAGMAOMAC`, `0xC101`) in the `ctracpkm`, `omac`, and `mgm`
test suites.

```sh
go test ./magma/
```

## References

- **[RFC 8891](rfc/rfc8891.txt)** — *GOST R 34.12-2015: Block Cipher "Magma".*
  §1 sizes, §4.1 π S-box, §4.2 round function `g`/`t`/`<<<_11`, §4.3 key
  schedule & 32-round order, Appendix A test vectors.
- **GOST R 34.12-2015** — Russian Federal Standard, block ciphers Magma
  (64-bit) and Kuznyechik (128-bit). Magma is the normative source
  republished as RFC 8891.
- **GOST R 34.13-2015** — modes of operation (ECB/CTR/CBC/OMAC/MGM) over
  Magma; source of the §A.2.1 multi-block ECB vector (V2).
- **[RFC 5830](../gost28147/rfc/rfc5830.txt)** — GOST 28147-89, the legacy
  core Magma is built on (little-endian numbering); see
  [`../gost28147/DESIGN.md`](../gost28147/DESIGN.md).
- **[RFC 4357](../gost28147/rfc/rfc4357.txt)** — S-box parameter sets and
  OIDs (tc26-Z = `1.2.643.7.1.2.5.1.1`).
- **[RFC 9189](../gost28147cnt/rfc/rfc9189.txt)** §4.4 — GOST cipher suites
  for TLS 1.2; the Magma-CTR-OMAC suite.
- **[RFC 9367](../kuznyechik/rfc/rfc9367.txt)** — GOST cipher suites for TLS
  1.2 (additional). Suite `0xC101` `GOST2012-MAGMA-MAGMAOMAC`, GOST18 key
  transport, ACPKM.

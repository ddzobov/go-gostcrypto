# CTR mode + ACPKM key meshing — GOST R 34.13-2015 / RFC 8645

This document describes the CTR and CTR-ACPKM modes implemented by `package
ctracpkm`: what they are, their specification, the notable points of this
implementation, and the test vectors that pin them. For the public API and a
usage example see the [package README](README.md).

## What it is

GOST R 34.13-2015 **CTR (gamma counter) mode** (§5.3) turns a block cipher
into a stream cipher: each plaintext byte is XORed with a keystream ("gamma")
byte, and the gamma is produced by encrypting a monotonically increasing
counter block.

**ACPKM** ("Advanced Cryptographic Prolongation of Key Material", RFC 8645 =
draft-irtf-cfrg-re-keying) is an *internal re-keying* mechanism layered on top
of CTR: after every `N` bytes of keystream (one "section"), the cipher key is
transformed into a fresh key by encrypting a fixed public constant `D` under
the current key. The counter is **not** reset by ACPKM — only the key
changes. This bounds the amount of data processed under any single key
without renewing the master key out-of-band.

### Where this module uses it

- **Exported constants** `SectionKuznyechik` (4096) and `SectionMagma` (1024)
  document the TLS per-suite section sizes (RFC 9367 suites `0xC100`/
  `0xC101`). The sibling `gostls` TLS module uses `NewCTRACPKM` once per TLS
  record for both the plaintext keystream and the OMAC-tag keystream.
- **Plain CTR (no ACPKM)** is consumed by `kexp15` (KExp15 key export, RFC
  9189 §8.2.1) to encrypt the shared key and its CMAC tag as one contiguous
  keystream, and by the root `gostcrypto` facade's `NewCTR`/`NewCTRACPKM`
  wrappers (which add Go-idiomatic `error` returns over this package's
  panic-on-bad-input constructors).

## Specification

### Sizes

| Quantity            | Kuznyechik (GOST 34.12 "Кузнечик") | Magma (GOST 34.12 "Магма") |
|---------------------|------------------------------------|----------------------------|
| Block size `n`      | 16 bytes (128 bit)                 | 8 bytes (64 bit)           |
| Key size `k`        | 32 bytes (256 bit)                 | 32 bytes (256 bit)         |
| CTR counter block   | 16 bytes                           | 8 bytes                    |
| TLS record IV/nonce | 8 bytes (= `n/2`)                  | 4 bytes (= `n/2`)          |
| ACPKM section `N`   | 4096 bytes (TLS) / per-protocol    | 1024 bytes (TLS)           |
| `D` length          | 32 bytes (= `k`)                   | 32 bytes (= `k`)           |
| `J` = `k/n`         | 2 encrypts per rekey               | 4 encrypts per rekey       |

### CTR mode (GOST R 34.13-2015 §5.3)

CTR produces gamma block `Γ_i = E_K(CTR_i)`, then `C_i = P_i ⊕ MSB(Γ_i)`. The
counter starts at an initial value and increments by 1 per block.

Counter layout for a fresh CTR stream: the IV occupies the **high half** of
the counter block (`n/2` bytes) and the low half is the running counter
starting at zero:

```
CTR_0 = IV(n/2 bytes) || 0x00 * (n/2)
```

The full `n`-byte counter is supplied to `NewCTR`/`NewCTRACPKM` already
assembled (high half = nonce, low half = zeros); the caller is responsible
for building it from a shorter protocol-level nonce.

**Increment is big-endian**: the counter is treated as a single big-endian
integer over the whole block, incremented from the last byte upward with the
carry propagating toward the low-indexed (high-order) bytes. RFC 8645 and the
GOST standard both describe the counter this way.

### ACPKM transformation (RFC 8645 §6.2.1)

Normative formula (RFC 8645 §6.2.1):

> `K^{i+1} = ACPKM(K^i) = MSB_k( E_{K^i}(D_1) | ... | E_{K^i}(D_J) )`
> where `J = ceil(k/n)`.

The constant `D` is the public 1024-bit string
`D = (80 | 81 | 82 | ... | fe | ff)` (sequential bytes `0x80`…`0xFF`). Each
`D_j` is the `j`-th `n`-byte block of `D`. Because here `k = 32` bytes, only
the **first 32 bytes** of `D` are ever used (`0x80`…`0x9F`):

```
D (32 bytes used) =
  80 81 82 83 84 85 86 87  88 89 8a 8b 8c 8d 8e 8f
  90 91 92 93 94 95 96 97  98 99 9a 9b 9c 9d 9e 9f
```

- Kuznyechik (`n=16`, `J=2`): new key = `E(D[0:16]) || E(D[16:32])`.
- Magma (`n=8`, `J=4`): new key =
  `E(D[0:8]) || E(D[8:16]) || E(D[16:24]) || E(D[24:32])`.

All `E(...)` use the **current** section key (the one being retired), and the
concatenation of the `J` ciphertext blocks (exactly 32 bytes) becomes the
next section key. `MSB_k` is a no-op here because the concatenation is
already exactly `k = 32` bytes. The same constant `D` is used for both
Kuznyechik and Magma.

### ACPKM re-keying schedule (RFC 8645 §2 / §6.2.1)

The section size `N` MUST be a multiple of the block size `n` (RFC 8645
§6.2.1: "The section size N MUST be divisible by the block size n").
Plaintext is split into sections of `N` bytes. Section 1 is encrypted under
the initial key `K^1 = K`; before encrypting section `i+1` the key is
advanced `K^{i+1} = ACPKM(K^i)`. The counter keeps running across section
boundaries (it is **never** reset by ACPKM).

`sectionSize % blockSize == 0` is required; `sectionSize == 0` disables ACPKM
entirely, degrading to plain CTR — `NewCTRACPKM(..., 0)` is equivalent to
`NewCTR`.

### ACPKM-Master (RFC 8645 §6.3.1) — informational

For deriving multiple keys (not used by the TLS suites, but exercised by the
"master" KAT below):

> `K[1] | ... | K[l] = ACPKM-Master(T*, K, d, l) = CTR-ACPKM-Encrypt(T*, K, 1^{n/2}, 0^{d*l})`

i.e. run CTR-ACPKM with section size `T*` over a zero buffer of length `d*l`
bits, starting counter `1^{n/2}` (high half all-ones).

## Implementation notes

Points where a naive reading of the RFC diverges from what this
implementation does; each is exercised by a test vector below.

1. **Counter byte order is big-endian over the whole block, but the IV sits
   in the HIGH half.** RFC 8645 §6 writes counters as `1^{n/2}` etc. — the
   non-zero/initial part is the most-significant half, and the counter runs
   in the least-significant half. A reimplementer who places the nonce in the
   low bytes (little-endian intuition — GOST is little-endian in *many*
   other places, e.g. key/curve scalars) gets the wrong gamma from block 2
   onward. `NewCTR`/`NewCTRACPKM` take the full n-byte counter already
   assembled this way.

2. **ACPKM rekeys BEFORE generating the first block of the new section, not
   after the last block of the old one**, and the threshold is `>=`,
   evaluated at block boundaries: the per-section byte counter is checked
   against `sectionSize` just before encrypting the next gamma block, not
   just after. Getting this off-by-one wrong (rekeying after, or using `>`)
   shifts every section boundary and silently corrupts everything past the
   first section.

3. **ACPKM does NOT reset the counter.** RFC 8645 §6.2.1 advances only the
   key; the counter is continuous across sections. A reimplementer who
   re-zeros the counter on rekey diverges after the first section.

4. **The retiring key encrypts `D`, and `E` is always the cipher's ENCRYPT
   direction**, for both encrypt and decrypt of the stream and for the ACPKM
   transform itself. CTR is a stream cipher — decryption is the same XOR
   with the same gamma — so the block cipher is used in *encrypt* mode
   throughout, never `Decrypt`.

5. **This is RFC 8645 ACPKM, NOT CryptoPro RFC 4357 key meshing.** They are
   different mechanisms that both amount to "re-key every so many bytes" and
   are easy to conflate. CryptoPro meshing (used by the legacy IMIT/CNT GOST
   28147 modes — see [`../gost28147imit/DESIGN.md`](../gost28147imit/DESIGN.md))
   ECB-*decrypts* the key against a different constant; ACPKM *encrypts* a
   public constant. They have no shared code path in this module.

6. **Section size is per-suite and protocol-defined, not a single
   constant.** RFC 8645 §6.2.1 leaves `N` to the protocol; this package takes
   it as a parameter (`sectionSize`) rather than hard-coding it. The exported
   `SectionKuznyechik`/`SectionMagma` constants document only the RFC 9367
   TLS values (4096/1024); other protocols and contexts (e.g. CMS) use
   different section sizes.

7. **Batched keystream generation is a pure optimisation, not a semantic
   change.** When the underlying block cipher additionally implements
   `EncryptBlocks(dst, src []byte)` (Kuznyechik does; Magma does not), full
   whole-block runs are generated in one batched call instead of block by
   block; a cipher that also implements a fused `CTRXORBlocks(dst, src, iv
   []byte)` (the experimental SIMD Kuznyechik build) is preferred over
   `EncryptBlocks` when present, since it avoids materialising the
   intermediate counter blocks. Either path is bounded to the current ACPKM
   section so a batch never spans a rekey, and produces byte-for-byte the
   same output and carries the same state as the per-block loop — ciphers
   without these methods simply take the per-block path.

## Test vectors

### Inline runnable vector (Kuznyechik CTR-ACPKM, section size 32)

Section size 32 forces 3 rekeys over 112 bytes — a complete end-to-end ACPKM
exercise.

```
key (32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
IV  (16B): 1234567890abcef0 0000000000000000   (8-byte nonce, zero-padded)
section N: 32 bytes

plaintext (112B):
  1122334455667700ffeeddccbbaa9988
  00112233445566778899aabbcceeff0a
  112233445566778899aabbcceeff0a00
  2233445566778899aabbcceeff0a0011
  33445566778899aabbcceeff0a001122
  445566778899aabbcceeff0a00112233
  5566778899aabbcceeff0a0011223344

ciphertext (112B):
  f195d8bec10ed1dbd57b5fa240bda1b8
  85eee733f6a13e5df33ce4b33c45dee4
  4bceeb8f646f4c55001706275e85e800
  587c4df568d094393e4834afd0805046
  cf30f57686aeece11cfc6c316b8a896e
  dffd07ec813636460c4f3b743423163e
  6409a9c282fac8d469d221e7fbd6de5d
```

Note the first 32 bytes equal the plain Kuznyechik CTR KAT (GOST R
34.13-2015 A.1.2) because the first section uses the unmeshed key — see the
plain-CTR KAT below, whose first 32 bytes are `f195d8be...3c45dee4`.

### Magma ACPKM key-meshing KAT (K2)

Verifies one ACPKM transform in isolation:

```
K  (32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
ACPKM(K) = E_K(D[0:8])||E_K(D[8:16])||E_K(D[16:24])||E_K(D[24:32]) with Magma:
K2 (32B): 863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0
```

### Plain CTR KATs (no ACPKM)

- Kuznyechik CTR, GOST R 34.13-2015 A.1.2 (Table A.2). Same key/plaintext as
  above (the first 64 plaintext bytes); expected ciphertext (64 bytes, all
  four blocks from the standard):
  ```
  f195d8bec10ed1dbd57b5fa240bda1b8
  85eee733f6a13e5df33ce4b33c45dee4
  a5eae88be6356ed3d5e877f13564a3a5
  cb91fab1f20cbab6d1c6d15820bdba73
  ```
- Magma CTR, GOST R 34.13-2015 A.2.2:
  ```
  key:        ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  IV (8B):    1234567800000000   (4-byte nonce zero-padded)
  plaintext:  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
  ciphertext: 4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d
  ```

### ACPKM-Master vector

The official R 1323565.1.017-2018 Appendix A.1 Magma CTR-ACPKM end-to-end KAT
(section size 16, 56 bytes, 3 rekeys) and a Kuznyechik ACPKM-Master vector
(144 zero bytes, IV = 8 bytes of `0xFF`, section size 96) are both anchored
in-package; see the source citations below.

### Property coverage

The test suite also pins: big-endian counter increment across a wrap;
split-write `XORKeyStream` calls producing the same output as one-shot;
encrypt/decrypt round-trip across multiple sections for both ciphers; and
`NewCTRACPKM(..., 0)` matching plain `NewCTR` byte-for-byte.

## Conformance testing

The in-package tests (`ctracpkm/ctracpkm_test.go`, `ctracpkm/guard_test.go`,
`ctracpkm/ctracpkm_batch_test.go`, `ctracpkm/ctracpkm_c5_test.go`) anchor the
fixed vectors above and the construction-time panic guards (bad key/IV
length, non-dividing block size, negative or non-multiple section size,
short destination, invalid buffer overlap).

This primitive has no upstream reference implementation to diff against in
the usual sense — no widely available pure-Go GOST library ships a CTR-ACPKM
implementation — so the differential strategy instead compares against an
independent reference implementation built from the same public
specification, plus the pinned hex vectors above as the primary anchor.
Because CTR is a stream cipher, the cheapest invariant for fuzzing is
**encrypt/decrypt round-trip** (the same gamma decrypts what it encrypted);
a differential fuzz harness additionally compares keystream output directly
against the independent reference over random keys, IVs, section sizes, and
message lengths, seeded from the KATs above and driving small section sizes
so a few hundred fuzzed bytes already cross several ACPKM rekeys.

```sh
go test ./ctracpkm/
```

## References

- **RFC 8645** — "Re-keying Mechanisms for Symmetric Keys".
  - §2 — re-keying overview (internal vs external).
  - §6.2.1 — ACPKM transformation `K^{i+1} = MSB_k(E_{K^i}(D_1)|...|E_{K^i}(D_J))`,
    constant `D = (80|81|...|fe|ff)`, "section size N MUST be divisible by
    the block size n".
  - §6.3.1 — ACPKM-Master `= CTR-ACPKM-Encrypt(T*, K, 1^{n/2}, 0^{d*l})`.
- **[GOST R 34.13-2015](rfc/GOST_R_34.13-2015.pdf)** — block cipher operation
  modes. §5.3 — CTR (gamma counter) mode. Test vectors: A.1.2 (Kuznyechik
  CTR), A.2.2 (Magma CTR).
- **GOST R 34.12-2015** — Kuznyechik (128-bit) and Magma (64-bit) block
  ciphers; see [`../kuznyechik/DESIGN.md`](../kuznyechik/DESIGN.md) and
  [`../magma/DESIGN.md`](../magma/DESIGN.md).
- **[R 1323565.1.017-2018](rfc/R1323565.1.017-2018.pdf)** — TC26
  cryptographic mechanisms; source of the ACPKM `D` constant and TLS
  section-size choices (Kuznyechik 4096, Magma 1024). Appendix A.1 (Magma
  CTR-ACPKM end-to-end vector) and A.4.2 (ACPKM-Master vector).
- **[RFC 9367](rfc/rfc9367.txt)** — GOST cipher suites for TLS 1.2 (suites
  `0xC100`/`0xC101`); consumer of this primitive in the record layer.
- **[RFC 4357](rfc/rfc4357.txt)** — CryptoPro cryptographic algorithms;
  defines the unrelated CryptoPro key-meshing scheme discussed for contrast
  in Implementation notes.

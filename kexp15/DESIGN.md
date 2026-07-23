# KExp15 / KImp15 key export wrapping (R 1323565.1.017-2018)

This document describes the GOST key-transport envelope implemented by
`package kexp15`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

KExp15 is the GOST **key-transport envelope**: it wraps a secret key `S`
(typically a 32-byte pre-master / session key) so it can be carried over the
wire authenticated and encrypted under two independent export keys. KImp15 is
the exact inverse (decrypt, then verify the MAC). This package implements the
export (wrap) direction only; the import/unwrap direction is intentionally out
of scope.

The construction is **OMAC-then-CTR**:

```
CEK_MAC = OMAC(K_Exp_MAC, IV || S)            (truncated to mac_len)
SExp    = CTR-Encrypt(K_Exp_ENC, IV_full, S || CEK_MAC)
```

- Standard identity: **R 1323565.1.017-2018** (the Russian TC26 export-key
  recommendation). Referenced normatively by:
  - **[RFC 9189](rfc/rfc9189.txt) §8.2.1** ("KExp15 and KImp15 algorithms"),
    which defines the construction for the GOST 2012 TLS 1.2 cipher suites
    `0xC100` and `0xC101`.
  - **[RFC 9367](rfc/rfc9367.txt)** is the GOST TLS **1.3** specification (MGM
    AEAD key-share); it does **not** use KExp15 or key transport envelopes —
    its suites are `0xC103`–`0xC106`.
- Block-cipher variants (R 34.12-2015):
  - **Kuznyechik** — 128-bit block. `iv_len = 8`, `mac_len = 16`, `block = 16`.
    RFC 9189 suite `0xC100` (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`).
  - **Magma** — 64-bit block. `iv_len = 4`, `mac_len = 8`, `block = 8`.
    RFC 9189 suite `0xC101` (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`).

## Where this module uses it

`Kexp15(variant, sharedKey, cipherKey, macKey, iv)` and the `KexpVariant` enum
(`KexpKuznyechik`, `KexpMagma`) are consumed by the sibling `gostls` TLS
module's GOST 2018 key exchange: the 64-byte output of KEG2012_256
(VKO + KDFTREE) is split into `mac_key = expkeys[:32]` (`K_Exp_MAC`) and
`cipher_key = expkeys[32:]` (`K_Exp_ENC`), and the IV is a slice of the
handshake's UKM. The wrapped output becomes the `psexp` field of the
`PSKeyTransport_gost` ASN.1 structure sent in `ClientKeyExchange`. These are
RFC 9189 suites `0xC100` (Kuznyechik-CTR-OMAC) and `0xC101` (Magma-CTR-OMAC).

This package sits on top of two other packages in this module:

- [`omac`](../omac/DESIGN.md) — OMAC1/CMAC over the block cipher; see that
  document for the full subkey-derivation and padding specification.
- [`ctracpkm`](../ctracpkm) — the CTR keystream (plain CTR, no ACPKM rekeying,
  via `ctracpkm.NewCTR`).

## Specification

### Inputs and sizes

| name        | meaning                       | Kuznyechik | Magma |
|-------------|-------------------------------|------------|-------|
| `S`         | shared/secret key to wrap     | any len ≥ 1 (32 in TLS) | any len ≥ 1 (32 in TLS) |
| `K_Exp_ENC` | CTR encryption key            | 32 bytes   | 32 bytes |
| `K_Exp_MAC` | OMAC authentication key       | 32 bytes   | 32 bytes |
| `IV`        | half-block IV                 | 8 bytes    | 4 bytes |
| block size  | cipher block                  | 16 bytes   | 8 bytes |
| `mac_len`   | MAC truncation length         | 16 bytes   | 8 bytes |
| output      | `len(S) + mac_len`            | len(S)+16  | len(S)+8 |

The IV is **half a block** (`iv_len = block/2`). This is the key sizing quirk:
the wire IV is short, but the CTR mode needs a full-block counter.

### Algorithm (RFC 9189 §8.2.1)

[RFC 9189](rfc/rfc9189.txt) §8.2.1 states the algorithm verbatim:

> KExp15:
> 1. `CEK_MAC = OMAC(K_Exp_MAC, IV | S)`
> 2. `SExp = CTR-Encrypt(K_Exp_ENC, IV, S | CEK_MAC)`

> KImp15:
> 1. `S | CEK_MAC = CTR-Decrypt(K_Exp_ENC, IV, SExp)`
> 2. `If CEK_MAC = OMAC(K_Exp_MAC, IV | S) then return S; else return FAIL`

> "The keys K_Exp_MAC and K_Exp_ENC MUST be independent. For every pair of
> keys, the IV values MUST be unique."

The RFC uses CTR with full block size (`s = n`, i.e. CTR-128 for Kuznyechik,
CTR-64 for Magma — no truncated gamma).

Step by step, as implemented (`kexp15.go:100-153`):

1. **Build the full counter from the half-IV.** Allocate `iv_full = block`
   zero bytes, copy `IV` into the **front** (low indices), leave the back
   zero. So Kuznyechik `iv_full = IV(8) || 00·8`, Magma
   `iv_full = IV(4) || 00·4`.

2. **Compute the MAC over `IV || S`** with `K_Exp_MAC`, using OMAC1/CMAC of
   the block cipher, then truncate to the leftmost `mac_len` bytes
   (`kexp15.go:127-139`: `omac.New(macBlock, p.macLen)` → `Write(iv)` →
   `Write(sharedKey)` → `Sum(nil)`). Truncation is plain leftmost-bytes of the
   full CMAC tag — no big/little-endian reordering.

3. **CTR-encrypt `S || CEK_MAC`** with `K_Exp_ENC` and `iv_full`
   (`kexp15.go:141-151`): the code concatenates `S || CEK_MAC` into one
   plaintext buffer and XORs it with a single continuous CTR stream. Output
   length is exactly `len(S) + mac_len`.

### OMAC / CMAC subkeys (R 34.13-2015 / RFC 4493)

OMAC here is RFC 4493 CMAC over the GOST block cipher — see
[`omac/DESIGN.md`](../omac/DESIGN.md) for the full derivation. Summary:

- `L = E_K(0^block)`.
- `K1 = (L << 1) XOR (Rb if MSB(L)==1)`, `K2 = (K1 << 1) XOR (Rb if MSB(K1)==1)`.
- Reduction constant `Rb`:
  - Kuznyechik (128-bit): `0x87` (`x^128 + x^7 + x^2 + x + 1`) — [RFC 4493](rfc/rfc4493.txt) §2.3.
  - Magma (64-bit): `0x1b` (`x^64 + x^4 + x^3 + x + 1`) — [RFC 8645](rfc/rfc8645.txt) §4.1.1.
- Final block: if exactly one full block of unprocessed data remains, XOR with
  `K1`; otherwise pad with `0x80 00…` and XOR with `K2`, then run one more CBC
  step. The leftmost `mac_len` bytes of the resulting chain value are the tag.

For TLS the MAC input is `IV || S` = 36 bytes (Magma, IV=4 + S=32) or 40 bytes
(Kuznyechik, IV=8 + S=32), i.e. a non-block-multiple → always the `K2` /
`0x80`-pad path.

### CTR counter (R 34.13-2015)

- Counter is the full block, **big-endian increment**: the last byte
  increments first, carry propagates toward index 0
  (see [`ctracpkm`](../ctracpkm)).
- The keystream block `i` is `E_K(counter)`; counter is incremented **after**
  each block is generated.
- **No ACPKM** in kexp15: the wrapped payload (≤ 48 bytes) never crosses a
  rekey section. The code uses plain `ctracpkm.NewCTR`, not `NewCTRACPKM`.

## Implementation notes

Points where a naive reading of the RFC diverges from what this package (and
the reference gost-engine implementation it was cross-checked against) does;
each is exercised by a test vector below.

1. **IV occupies the LOW bytes of the counter, remainder zero — not centered,
   not high.** RFC 9189 §8.2.1 says "IV" without specifying its placement in
   the CTR counter block; the placement used here (IV first, zeros after,
   `kexp15.go:122-125`) matches the reference gost-engine implementation.
   Getting this backwards (zeros first) is the most common reimplementation
   bug and produces a completely different keystream.

2. **MAC is over `IV || S`, encryption is over `S || CEK_MAC` — the IV is NOT
   encrypted and the order differs between the two layers.** RFC 9189 §8.2.1
   step 1 hashes `IV | S`; step 2 encrypts `S | CEK_MAC`. The IV appears only
   as MAC prefix; it is never part of the ciphertext (it travels separately,
   in TLS as part of the UKM). See `kexp15.go:127-151`.

3. **`K_Exp_MAC` keys the MAC, `K_Exp_ENC` keys the CTR — the two are never
   swapped.** Each is fed to a separate block-cipher instance: `macBlock` from
   `macKey`, `ctrBlock` from `cipherKey` (`kexp15.go:128,148`). In the TLS call
   site the 64-byte KEG output is split `expkeys[:32]=mac_key`,
   `expkeys[32:]=cipher_key`; swapping them passes no test and fails the live
   handshake.

4. **MAC truncation is leftmost bytes of the full CMAC tag — no endianness
   flip.** It does not reverse byte order on truncation (unlike some GOST
   contexts where values are little-endian). Magma keeps the leftmost 8 of the
   8-byte tag (i.e. the whole tag); Kuznyechik keeps the leftmost 16 of 16
   (whole tag) — so in *both* TLS variants `mac_len == block`, meaning no
   actual truncation happens at the TLS call. Truncation logic still matters
   if the primitive is reused with a shorter `mac_len`.

5. **OMAC's `Sum` is finalize-on-copy and non-destructive** (see
   [`omac/DESIGN.md`](../omac/DESIGN.md) point 6): it snapshots state and does
   not mutate the receiver. This matters if the MAC is built incrementally and
   the context reused. For kexp15 it is a single `Write, Write, Sum`, so the
   gotcha does not bite here, but a naive reimplementation that mutates state
   in `Sum` would break if the call site were extended.

6. **No CryptoPro key meshing, no ACPKM in kexp15.** Key meshing (re-keying
   every 1024 bytes of GOST 28147-89-family ciphers) does not apply here: the
   MAC processes ≤ 40 bytes and the CTR processes ≤ 48 bytes, both far below
   the 1024-byte mesh threshold and below any ACPKM section size (4096
   Kuznyechik / 1024 Magma). The implementation uses the *raw* OMAC and *raw*
   CTR (no meshing, no rekeying).

7. **CTR is a single continuous stream across the `S` | `MAC` boundary.** The
   plaintext buffer `S || CEK_MAC` is XORed with one continuous CTR stream
   (`kexp15.go:141-151`); the counter is not reinitialized at the boundary
   between `S` and the MAC bytes.

8. **Counter increment is big-endian (last byte first).** RFC 9189 leaves
   "CTR-Encrypt" to R 34.13-2015, which increments the full block big-endian
   (see [`ctracpkm`](../ctracpkm)). A little-endian increment desyncs from
   block 2 onward — invisible on a 16-byte payload (single block), but Magma's
   40-byte output spans 5 blocks and Kuznyechik's 48-byte output spans 3, so a
   wrong increment is caught by the Magma test vector below.

## Test vectors

Tests live in `kexp15/kexp15_test.go` (no build tags required):

- `TestKexp15_Magma_EngineEtalon` — an authoritative Magma known-answer
  vector, cross-checked against an independent reference implementation.
- `TestKexp15_Magma_RFC9189` — the published Magma vector from RFC 9189
  Appendix A.1.3.1 (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`).
- `TestKexp15_Kuznyechik_RFC9189` — the published Kuznyechik vector from
  RFC 9189 Appendix A.1.3.2 (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`).
- `TestKexp15_Kuznyechik_Smoke` — output length and determinism for the
  Kuznyechik path with distinct input.
- `TestKexp15_ErrorCases` — input validation (empty `S`, wrong key/IV
  lengths, bad variant).

### Complete Magma KAT

Variant = Magma (`iv_len=4, mac_len=8, block=8`).

```
S  (shared_key, 32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
K_Exp_ENC (magma_key): 202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637
K_Exp_MAC (mac key):   08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f
IV (4B):               67bed654

KExp15(Magma, S, K_Exp_ENC, K_Exp_MAC, IV) =  (40 bytes)
  cfd5a12d5b81b6e1 e99c916d07900c6a c12703fb3abded55 567bf3742c899c75 5dafe7b42e3a8bd9
```

Intermediate (derivable, useful for stepwise debugging):
- `iv_full = 67bed654 00000000` (IV in low 4 bytes, zero pad).
- The last 8 bytes of the output (`5dafe7b42e3a8bd9`) are `CTR-Encrypt` of
  `CEK_MAC = OMAC(K_Exp_MAC, IV||S)[:8]`; the first 32 bytes are
  `CTR-Encrypt(S)`.

To run:
```sh
go test -run TestKexp15_Magma_EngineEtalon ./kexp15/ -v
```

### RFC 9189 Kuznyechik vector (Appendix A.1.3.2)

```
S  (shared_key, 32B): a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d
K_Exp_MAC:             7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1
K_Exp_ENC:             1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24
IV (8B):               214a6a298e99e325

KExp15(Kuznyechik, S, K_Exp_ENC, K_Exp_MAC, IV) = (48 bytes)
  250d1b67a270ab04d3f65418e1d380b4cb945f0a3dca51500cf3a1bef37f76c07341a9839ccf6cba7189da61eb67176c
```

### RFC 9189 Magma vector (Appendix A.1.3.1)

Same PMS as the Kuznyechik vector above, corroborating the
`K_Exp_MAC | K_Exp_ENC` key ordering used to read the RFC's combined blob.

```
S  (shared_key, 32B): a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d
K_Exp_MAC:             2d8ba8c84cb232ff41f10c3ad924134223254f71e5696d3d29c3e4c9daa6b293
K_Exp_ENC:             849eb6340bffae6928a3c3e4ff92eccb1e8f0cf7a188368e6b748e52ea378b0c
IV (4B):               214a6a29

KExp15(Magma, S, K_Exp_ENC, K_Exp_MAC, IV) = (40 bytes)
  d7f0f0422367867b25fa4233a954f58bde92e9c9bbfb8816c99f15e6398722a0b2b7bfe8493e9a5c
```

## Conformance testing

This primitive has no upstream Go equivalent to compare against directly — it
composes the block cipher, OMAC, and CTR packages in this module. The
implementation is validated by:

1. **Pinned KATs** in `kexp15/kexp15_test.go`: a gost-engine-derived Magma
   etalon, and the published RFC 9189 Appendix A.1.3.1 (Magma) and A.1.3.2
   (Kuznyechik) vectors.
2. **A differential fuzz harness** that compares this implementation against
   an independent reference implementation over both variants, arbitrary-length
   `S`, and variant-sized IVs — including the boundary behavior between the
   wrapped secret and the truncated MAC.

```sh
go test -run TestKexp15 ./kexp15/ -v
```

## References

- **R 1323565.1.017-2018** — TC26 recommendation defining KExp15 / KImp15.
  [Local copy](rfc/R1323565.1.017-2018.pdf).
- **[RFC 9189](rfc/rfc9189.txt)** — "GOST Cipher Suites for TLS Protocol
  Version 1.2", §8.1 (TLSTREE) and **§8.2.1** (KExp15 / KImp15 algorithms);
  assigns suites `0xC100` (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`) and
  `0xC101` (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`).
- **[RFC 9367](rfc/rfc9367.txt)** — "GOST Cipher Suites for Transport Layer
  Security (TLS) Protocol Version 1.3"; suites `0xC103`–`0xC106` use MGM AEAD
  (not KExp15).
- **[RFC 4493](rfc/rfc4493.txt)** — "The AES-CMAC Algorithm" — CMAC subkeys
  and `Rb = 0x87`.
- **[RFC 8645](rfc/rfc8645.txt)** — "Re-keying Mechanisms for Symmetric Keys"
  — `Rb = 0x1b` for the 64-bit block; ACPKM background.
- **GOST R 34.12-2015** — Kuznyechik (128-bit) and Magma (64-bit) block
  ciphers; see [`kuznyechik/DESIGN.md`](../kuznyechik/DESIGN.md).
- **GOST R 34.13-2015** — block cipher operation modes (CTR, OMAC/CMAC) and
  their KATs; see [`omac/DESIGN.md`](../omac/DESIGN.md).

Key source citations:
- `kexp15/kexp15.go:100-153` — the `Kexp15` envelope.
- `kexp15/kexp15.go:72-91` — variant parameters.
- `kexp15/kexp15_test.go` — KATs (Magma engine etalon, RFC 9189 A.1.3.1, A.1.3.2).

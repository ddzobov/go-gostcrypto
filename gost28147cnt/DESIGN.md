# GOST 28147-89 CNT — Counter/Gamma Stream Mode

This document describes the GOST 28147-89 CNT mode implemented by `package
gost28147cnt`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

GOST 28147-89 CNT is the *gammirovaniye* (counter/gamma) stream mode of the
GOST 28147-89 64-bit block cipher, republished as **RFC 5830 §6** ("Counter
Mode"). A keystream ("gamma") is produced by ECB-encrypting a counter that is
advanced by two fixed additive constants between blocks; the gamma is XORed
with the plaintext. Encryption and decryption are the same operation.

In TLS, this mode is used together with the CryptoPro key-meshing extension
(**RFC 4357 §2.3.2**), which re-keys the cipher every 1024 bytes of
keystream, and is always paired with the GOST 28147-89 IMIT MAC — the
record-layer seal is `CNT.encrypt(plaintext || IMIT)`.

| Quantity | Value |
|---|---|
| Block size | 8 bytes |
| Key size | 32 bytes |
| IV ("synchro", `S`) size | 8 bytes (one block) |
| Output | same length as input (stream) |

### Where this module uses it

This package borrows only the single-block ECB transform `E_K` from the
sibling [`gost28147`](../gost28147) block cipher — see
[`../gost28147/DESIGN.md`](../gost28147/DESIGN.md) for the cipher itself
(key schedule, round function, S-boxes). CNT treats it as a black box:
an 8-byte-in/8-byte-out function under a 32-byte key and a chosen S-box.

- The root `gostcrypto` facade exposes this mode as `NewGOST28147_CNT(key, iv
  []byte) (cipher.Stream, error)`, fixed to the CryptoPro-A S-box.
- The pure-Go TLS client (the sibling `gostls` TLS module) constructs one
  `*CNT` per connection and calls `XORKeyStream` on successive records for
  the GOST cipher suites:
  - `0x0081` GOST2001-GOST89-GOST89 — CryptoPro-A S-box.
  - `0xFF85` GOST2012-GOST8912-GOST8912 (IANA alias `0xC102`) — tc26-Z S-box.

  The record layer relies on this package precisely because it carries
  partial-block gamma and meshing state correctly across calls — see
  Implementation note 4 below.

## Specification

### CNT keystream algorithm (RFC 5830 §6)

RFC 5830 §6.1 specifies the gamma generation. Quoting the normative steps:

> "The initialisation vector S = (S1, S2, ..., S64)" is loaded into registers
> N1 and N2, then "encrypted in the electronic codebook mode in accordance
> with the requirements from section 5.1." The result A(S) = (Y0, Z0) is
> transferred to N3 and N4.
>
> "The filling of register N4 is added modulo (2^32-1) ... to the 32-bit
> constant C1"; "the filling of register N3 is added modulo 2^32 ... with the
> 32-bit constant C2."

Per RFC 5830 Appendix A, the constants are:

- **C1 = 0x01010104** — applied to the *upper* half, modulo 2^32 − 1.
- **C2 = 0x01010101** — applied to the *lower* half, modulo 2^32.

Concrete algorithm:

1. **Init.** Take the 8-byte IV (synchro `S`). Compute `iv0 = E_K(IV)`. This
   encrypted value is the initial counter state.
2. **Per gamma block** (each block produces 8 keystream bytes):
   - If this is the very first block, the working counter `buf` is `iv0`
     (the encrypted IV). For every subsequent block, `buf` is the *current*
     counter state carried over from the previous step.
   - **Lower half** `g = LE_u32(buf[0:4])`; `g = (g + C2) mod 2^32`; write
     back little-endian to `buf[0:4]`.
   - **Upper half** `h = LE_u32(buf[4:8])`; `h = (h + C1) mod (2^32 - 1)`;
     write back little-endian to `buf[4:8]`. The mod-(2^32−1) reduction is a
     32-bit add with end-around carry: `old = h; h += C1; if old > h: h++`.
   - Store `buf` back as the new counter state (`iv`).
   - **Gamma block** `G = E_K(buf)`.
3. **XOR** each byte of `G` with the corresponding plaintext byte. Leftover
   gamma bytes (when input is not a multiple of 8) are retained for the next
   call (streaming).

Decryption is identical: the same `G` is XORed with ciphertext (RFC 5830 §6.2).

### CryptoPro key meshing (RFC 4357 §2.3.2) — TLS-mandatory

In the TLS GOST suites the CNT state additionally performs CryptoPro key
meshing every 1024 bytes of keystream. Without it, long records produce a
wrong keystream after the first 1024 bytes.

A processed-byte counter `count` starts at 0 and increments by 8 per gamma
block (`count = count mod 1024 + 8`). When `count == 1024`, **before**
generating the next block:

1. Derive a new key: ECB-**decrypt** the 32-byte constant
   `CryptoProKeyMeshingKey` (below) under the *current* key, four 8-byte
   blocks, producing the new 32-byte key.
2. Re-key the cipher with that new key (same S-box).
3. Re-encrypt the current counter under the new key: `iv = E_{newK}(iv)`, and
   use that as the counter for the next block (`count` is **not** reset to
   zero by this step).

`CryptoProKeyMeshingKey` (32 bytes, RFC 4357 §2.3.2):

```
69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
```

### S-box selection

The CNT mode itself is S-box-agnostic; the S-box is a parameter of `E_K`
(supplied via the `*gost28147.Cipher`). TLS selects it by suite:

- `0x0081` (GOST2001) → **CryptoPro-A** S-box (`gost28147.SboxCryptoProA`).
- `0xFF85` / `0xC102` (GOST2012) → **tc26-Z** S-box (`gost28147.SboxTC26Z`).

See [`../gost28147/README.md`](../gost28147/README.md) for the S-box tables
themselves.

## Implementation notes

Points where a naive reading diverges from the standard; each is exercised by
a test vector below.

1. **The two counter halves are little-endian, and which half gets which
   constant is easy to get backwards.** The C2-incremented half lives in
   counter bytes `[0:4]`; the C1-incremented half lives in bytes `[4:8]`.
   RFC 5830 describes the halves as N3/N4 abstractly without spelling out the
   byte mapping — do not byte-swap or treat the counter as one 64-bit
   big-endian integer.

2. **`mod (2^32 − 1)` is an end-around-carry add, not a special-cased
   reduction.** The upper half is incremented as a 32-bit wraparound add plus
   one if it overflowed (`old = h; h += C1; if old > h: h++`); the all-ones
   value is never specially normalised. The lower half uses plain `mod 2^32`
   with no carry fix-up.

3. **The first gamma block uses `E_K(IV)`; later blocks do not re-encrypt the
   IV before incrementing.** RFC 5830 §6.1 ECB-encrypts the IV once to seed
   the counter; the seeded value is then incremented and the incremented
   value re-encrypted to form each subsequent gamma block. Re-encrypting the
   IV on every block, or never encrypting it, both yield a keystream that is
   wrong from the first block onward.

4. **A naive one-shot CTR construction cannot be reused for streaming TLS
   records.** Incrementing the counter once per call — rather than tracking
   the exact byte offset — over-counts on block-aligned input, since the
   increment must happen only once per 8 consumed bytes, not once per call.
   Discarding any leftover partial-block gamma between calls also corrupts
   the next call's keystream when a record length is not a multiple of 8.
   `CNT` avoids both pitfalls by carrying the incremented counter and the
   partial-gamma offset (`num`) in the receiver across `XORKeyStream` calls.

5. **Key meshing fires at exactly 1024 processed keystream bytes, before that
   block is generated, and `count` is not reset to zero afterward** — it
   continues advancing as `count mod 1024 + 8`. The new key is derived by
   **decrypting** (not encrypting) the meshing constant under the current
   key, and the counter is re-encrypted under the new key before being used.
   Because the threshold is 1024 bytes, a bug here is invisible during a TLS
   handshake (small records) and only manifests on large application-data
   records.

6. **State is persistent across TLS records.** The counter, the meshing byte
   count, and the partial-block offset are not reset per record — the same
   `*CNT` instance carries them across every record on a connection,
   matching typical `EVP_CIPHER_CTX`-style reuse. A per-record reset would
   desync the keystream after the first record.

7. **No padding.** CNT is a stream mode: output length equals input length.
   The record-layer seal feeds `plaintext || 4-byte-IMIT` through the same
   stream.

## Test vectors

### Existing tests in this package

Tests live in `cnt_test.go`, `guard_test.go`, `engine_vector_test.go`, and
`fuzz_test.go`.

- **`TestKAT_FirstBlocks`** — pins the first 32-byte keystream for zero
  key/IV under both S-boxes.
- **`TestKAT_KeyMeshing`** — pins bytes `[1016:1040]` straddling the
  1024-byte CryptoPro meshing boundary for both S-boxes.
- **`TestKAT_EngineEncTry`** — pins a reference `enc.try`-style vector
  (CryptoPro-A, 21-byte plaintext, real key/IV).
- **`TestCNT_Engine4K_CarryAndMeshing`** — loads a 4096-byte keystream from
  `testdata/engine-cnt-cryptoproa-4096.hex` (CryptoPro-A, real key/IV). 512
  blocks force at least one end-around carry and cross the meshing boundary
  three times. Both one-shot and split-write variants are checked.
- **`TestInvolution`** — encrypt-then-decrypt round-trip for twelve lengths
  and both S-boxes, including mesh-crossing lengths.
- **`TestStreamingEqualsOneShot`** — split-call streaming invariant for
  tc26-Z over 1100 bytes at six split schedules.
- **`TestNewCNT_PanicsOnBadIVLength`** / **`TestXORKeyStream_PanicsOnShortDst`**
  — guard tests for the promised panic contracts.
- **`FuzzSplitInvariance`** — oracle-free: chunked `XORKeyStream` output must
  equal one-shot output for arbitrary key/IV/split. The seed corpus reaches
  2 KiB to exercise meshing.

### First-gamma-block vector (no meshing, both S-boxes)

This vector isolates the "encrypt IV → +C2/+C1 → encrypt → XOR" steps with no
meshing (input below 1024 bytes):

```
Key (hex): all-zero, 32 bytes
IV  (hex): 0000000000000000   (8-byte synchro, all zero)
Plaintext: all-zero            (output IS the raw gamma keystream)
```

**tc26-Z** (suites `0xFF85` / `0xC102`):

```
G0  keystream[0:8]   = 8671cdbf3c1aae3f
G1  keystream[8:16]  = 637fa5cfaa0cb42f
G2  keystream[16:24] = a5a47a133d73b9f2
G3  keystream[24:32] = c0b04f8ca25552f8
```

**CryptoPro-A** (suite `0x0081`):

```
G0  keystream[0:8]   = 7f775ae1edb7082b
G1  keystream[8:16]  = 95a46f38e46d4026
G2  keystream[16:24] = d74593cd0a8874dc
G3  keystream[24:32] = 202d705df54f7899
```

Given a correct `E_K`, the gamma block is fully determined by the algorithm
above, so a mismatch localises to either the block cipher (S-box order,
key schedule) or the counter arithmetic.

### Key-meshing vector (over 1024 bytes)

Encrypting 1040 zero bytes under the same all-zero key/IV crosses the
1024-byte CryptoPro key-meshing boundary. Re-keying happens at exactly byte
1024, so a non-meshing implementation matches bytes `[0:1024]` and diverges
at offset 1024 and nowhere earlier:

```
tc26-Z      keystream[1016:1024] (pre-mesh)  = d0db6a6941467fc7
tc26-Z      keystream[1024:1032] (post-mesh) = 5184cd1d30f1544d
tc26-Z      keystream[1032:1040] (post-mesh) = 3d115a61239b6d9c

CryptoPro-A keystream[1016:1024] (pre-mesh)  = 7b9ef231641fa725
CryptoPro-A keystream[1024:1032] (post-mesh) = 56f45eab8381b608
CryptoPro-A keystream[1032:1040] (post-mesh) = 4399badbc168977d
```

## Conformance testing

The clean-room implementation is tested at three levels:

1. **In-package known-answer tests** (`cnt_test.go`, `engine_vector_test.go`):
   the pinned keystream bytes above for both S-boxes, covering the
   first-block, mesh-boundary, and 4096-byte (carry + 3 meshes) cases.

2. **In-package fuzz** (`fuzz_test.go`): `FuzzSplitInvariance` is
   oracle-free — any split of the input through a single `CNT` instance must
   produce the same bytes as a one-shot call. Input lengths up to 4 KiB
   ensure the fuzzer crosses the meshing boundary.

3. **Cross-module differential testing**: a differential fuzz harness
   compares this implementation against an independent reference
   implementation over random keys and IVs, both S-boxes, including
   non-block-aligned splits. Because that reference implementation's own CTR
   construction cannot stream (Implementation note 4), the comparison is
   restricted to the oracle's valid regime (zero key/IV, below the meshing
   threshold) for the general differential test, plus a dedicated test that
   locks in that this package and the oracle agree pre-mesh and diverge
   post-mesh — confirming the divergence is meshing, not a bug.

```sh
go test ./gost28147cnt/
go test -fuzz=FuzzSplitInvariance -fuzztime=30s ./gost28147cnt/
```

## References

- **[RFC 5830](rfc/rfc5830.txt)** — "GOST 28147-89 Cipher Modes". §5 (ECB
  block transform), **§6 (Counter/gamma mode)**, Appendix A (constants
  C1 = 0x01010104, C2 = 0x01010101).
- **[RFC 4357](rfc/rfc4357.txt)** — "Additional Cryptographic Algorithms for
  GOST". §2.3.2 (CryptoPro key meshing, 1024-byte threshold, meshing
  constant).
- **[RFC 9189](rfc/rfc9189.txt)** — "GOST Cipher Suites for TLS 1.2". §4
  (28147 CNT+IMIT suites, 4-byte MAC).
- **GOST 28147-89** — Soviet/Russian block cipher standard (gamma mode).
  Superseded for new work by GOST R 34.12/34.13-2015 but still mandated by
  the TLS GOST suites.
- [`../gost28147/DESIGN.md`](../gost28147/DESIGN.md) — the block cipher this
  mode is built over.
- [`../gost28147imit/DESIGN.md`](../gost28147imit/DESIGN.md) — the paired
  IMIT MAC used alongside CNT in the TLS record layer.

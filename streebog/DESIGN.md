# Streebog — GOST R 34.11-2012 hash function

This document describes the Streebog hash function implemented by `package
streebog`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

Streebog is the Russian national cryptographic hash function standardised as
**GOST R 34.11-2012** and republished in English as **RFC 6986** ("GOST R
34.11-2012: Hash Function"). It produces either a 256-bit or a 512-bit
digest. The two variants share the *entire* compression machinery and differ
in only two places: the initialization vector (IV) and a final truncation.

| Quantity        | Value                                                        |
|-----------------|-------------------------------------------------------------|
| Block size      | 64 bytes (512 bits)                                          |
| Internal state  | three 512-bit vectors: `h` (hash), `N` (bit counter), `Σ` (checksum) |
| Output (256)    | 32 bytes; IV = `0x01` repeated 64 times                     |
| Output (512)    | 64 bytes; IV = `0x00` repeated 64 times                     |
| Rounds in E()   | 13 key-additions / 12 round constants `C_1..C_12`           |
| S-box           | π, a single 256-entry byte permutation (RFC 6986 §6, Table 1) |
| Permutation     | τ (Tau), 64-entry byte permutation (RFC 6986 §6, Table 2)   |
| Linear map      | l / L, multiplication by a fixed 64×64 GF(2) matrix (RFC 6986 §6) |

### Where this module uses Streebog

- **TLS PRF for the GOST 2012 suites** (RFC 9189): the sibling `gostls` TLS
  module uses `HMAC-Streebog-256` for the record-layer PRF and key export.
- **`kdftree`** — `KDF_GOSTR3411_2012_256`, a tree-mode KDF built on
  `HMAC_Streebog256`. See [`../kdftree/DESIGN.md`](../kdftree/DESIGN.md).
- **`tlstree`** — `KDF_GOSTR3411_2012_256(K, label, seed)`, also built on
  `HMAC_Streebog256`. See [`../tlstree/DESIGN.md`](../tlstree/DESIGN.md).
- **`vko`** — `KEK2012256`/`KEK2012512` compute VKO GOST R 34.10-2012 key
  export with a Streebog-256 or Streebog-512 KDF. See
  [`../vko/DESIGN.md`](../vko/DESIGN.md).
- **`x509gost`** — certificate signature verification selects
  `NewStreebog256Hash()` for `id-tc26-gost3410-12-256` signatures and
  `NewStreebog512Hash()` for `id-tc26-gost3410-12-512`; the TBS bytes are
  hashed before the GOST R 34.10-2012 signature check.
- **OIDs**: Streebog-256 = `1.2.643.7.1.1.2.2`, Streebog-512 =
  `1.2.643.7.1.1.2.3`.
- The root `github.com/tarantool/go-gostcrypto` package re-exports this
  package as `NewStreebog256Hash`/`NewStreebog512Hash` (streaming) and
  `Streebog256`/`Streebog512` (one-shot).

## Specification

### The three primitive transformations (RFC 6986 §7)

RFC 6986 numbers the 64 bytes of a 512-bit vector **MSB-first**: `a =
a_63 || a_62 || ... || a_0`, where `a_63` is the most significant byte. This
implementation instead holds every 512-bit vector as a **little-endian** byte
buffer (`h[0]` is the least-significant byte `a_0`) — keep the two numberings
straight, since the RFC prose and the in-memory representation are mirror
images of each other.

- **`X[k](a) = k ⊕ a`** — bytewise XOR with a fixed 512-bit `k` (RFC 6986 §7,
  `X[k](a) = k (xor) a`).
- **S (substitution)**: `S(a) = π(a_63) || ... || π(a_0)` — apply the byte
  S-box π independently to every byte (RFC 6986 §7).
- **P (permutation)**: `P(a) = a_{τ(63)} || ... || a_{τ(0)}` — reorder the 64
  bytes by the fixed permutation τ (RFC 6986 §7).
- **L (linear)**: `L(a) = l(a_7) || ... || l(a_0)` — split into eight 64-bit
  words; each word is multiplied (over GF(2)) by the fixed binary matrix
  `A` (the function `l`). RFC 6986 §6 lists the 64 row constants of `A`.

The combined `LPS` (i.e. `L(P(S(a)))` — substitute, permute, linear-map) is
what this implementation precomputes as an XOR-decomposable byte-lookup
table; see [Implementation notes](#implementation-notes) below.

### Compression function g_N (RFC 6986 §8)

The keyed permutation E built from 13 round keys:

> `E(K, m) = X[K_13]·L·P·S · X[K_12]·L·P·S · ... · X[K_2]·L·P·S · X[K_1](m)`

Round keys are derived from `K = K_1`:

> K_1 = K, and for i = 2..13: K_i = L·P·S( K_{i-1} ⊕ C_{i-1} )

i.e. each subsequent key is `LPS` applied to the previous key XORed with the
round constant `C_{i-1}` (RFC 6986 §8, "K_{i+1} = LPS(K_i ⊕ C_i)").

The compression function (RFC 6986 §8):

> **g_N(h, m) = E( LPS(h ⊕ N), m ) ⊕ h ⊕ m**

So: form the first round key as `LPS(h ⊕ N)`, run the 12-round cipher `E` on
message block `m` with that key schedule, then XOR back `h` and `m`.

### Round constants C_1..C_12 (RFC 6986 §6.5, Iteration Constants)

Twelve 512-bit constants. RFC 6986 §6.5 prints each constant MSB-first; this
implementation stores them byte-reversed into the little-endian working
representation, which is the form XORed directly into the state during the
key schedule. `C_1` in that little-endian form (the exact bytes as stored in
`roundConstants[0]`):

```
07 45 a6 f2 59 65 80 dd 23 4d 74 cc 36 74 76 05
15 d3 60 a4 08 2a 42 a2 01 69 67 92 91 e0 7c 4b
fc c4 85 75 8d b8 4e 71 16 d0 45 2e 43 76 6a 2f
1f 7c 65 c0 81 2f cb eb e9 da ca 1e da 5b 08 b1
```

The RFC MSB-first rendering of the same constant is the exact byte-reverse,
`b1 08 5b da 1e ca da e9 ...` — do not XOR that form into a little-endian
state. All twelve constants are transcribed verbatim in
`streebog.go`'s `roundConstants` table and pinned by the known-answer test
vectors below.

### The hashing procedure (RFC 6986 §9)

Three vectors of state: `h`, `N` (message bit-length counter), `Σ` (the
512-bit checksum).

**Stage 1 — initialise** (RFC 6986 §9 "Step 1"):
- `h := IV` — `0x01·64` for the 256-bit variant, `0x00·64` for 512-bit.
- `N := 0^512`
- `Σ := 0^512`

**Stage 2 — process each full 512-bit block** (RFC 6986 §9 "Step 2"). For
every complete 64-byte block `m`:
- `h := g_N(h, m)`
- `N := (N + 512) mod 2^512`
- `Σ := (Σ + m) mod 2^512`

**Stage 3 — finalisation** (RFC 6986 §9 "Step 3"). Let the final partial
buffer hold `|M|` bits (`0 ≤ |M| < 512`), and `m` be the padded last block:
- **Pad**: `m := 0^(511-|M|) || 1 || M`. In MSB-first RFC notation a single
  `1` bit sits immediately above the message; in byte-oriented code this is
  "append a `0x01` byte right after the message bytes, zero-fill the rest".
- `h := g_N(h, m)` (compress the padded block at the *current* `N`)
- `N := (N + |M|) mod 2^512` (add the **bit** length of the real tail, not 512)
- `Σ := (Σ + m) mod 2^512`
- `h := g_0(h, N)` (compress with N = 0, feeding the bit-counter as the block)
- `h := g_0(h, Σ)` (compress with N = 0, feeding the checksum as the block)

**Output** (RFC 6986 §9 Step 3.6):
- 512-bit: return all 64 bytes of `h`.
- 256-bit: return `MSB_256(h)` — the most-significant 256 bits. In the
  little-endian working buffer that is the **upper half**, `h[32:64]`.

## Implementation notes

Points where the concrete implementation makes a specific, deliberate choice;
each is exercised by a test vector below.

1. **Endianness — the buffer is the reverse of RFC byte order.** RFC 6986
   numbers bytes MSB-first (`a_63 ... a_0`); this implementation stores the
   512-bit vectors as **little-endian** byte buffers, `a[0]` being the
   least-significant byte `a_0`. The `LPS` precompute table (`lpTable`) is
   indexed by raw little-endian bytes, and the 256-bit truncation takes the
   upper half of the LE buffer (`h[32:64]`) — which is the *most-significant*
   256 bits in RFC terms.

2. **The S/P/L precompute table folds only the linear part.** `lpTable[p][v]`
   holds `L(P(·))` applied to a single byte value `v` at little-endian
   position `p`, built once in `init()` from the RFC's `tau`/`matrixA`
   constants (`linearLP`). This is intentional: the nonlinear substitution
   `π` maps a zero byte to `pi[0] = 0xfc ≠ 0`, so `LP(0) == 0` but
   `LPS(0) ≠ 0` — folding `S` into the table as well would break that
   linear-only property. `S` (`pi`) is instead applied per byte at lookup
   time in `lps()`, and the eight resulting `[8]uint64` table rows are XORed
   together across the 64 input byte positions.

3. **`N` is incremented by 512 as a little-endian 512-bit integer.** Stage 2
   adds `512` to `N` (RFC §9 Step 2) via `add512`, a carrying add over the
   full 64-byte little-endian buffer — not a 64-bit counter. `block512le` is
   the constant `0x0200` (512) placed in the low two bytes.

4. **Stage-3 ordering and the *partial* `N` increment.** The exact sequence
   in `Sum` (RFC §9 Step 3 is easy to get subtly wrong):
   1. Pad the buffer (`0x01` after the data, zero-fill).
   2. `g_N(h, paddedBlock)` at the **pre-finalisation** `N`.
   3. `Σ := Σ + paddedBlock` — the *padded* block, including the `0x01` and
      zero fill, not the raw tail.
   4. `N := N + (tailBytes * 8)` — add the bit length of the real tail only,
      not 512.
   5. `g_0(h, N)` then `g_0(h, Σ)`, both with `N = 0`.

   A common bug is adding 512 (instead of the tail bit length) in step 4, or
   adding `Σ += rawTail` instead of `Σ += paddedBlock`. The carry-propagation
   test vector below exists precisely to catch checksum carry-chain errors
   in this stage.

5. **The empty-input case is handled by the normal path.** Unlike GOST R
   34.11-**94**, Streebog has no special-cased empty-input behavior: stage 2
   runs zero times and stage 3 pads a block holding a lone `0x01` byte. The
   empty-input KAT below exercises this directly.

6. **`Sum` is non-destructive; `Write` buffers partial blocks.** `Write` may
   be called repeatedly with arbitrary chunk sizes — it buffers bytes and
   only compresses on reaching a full 64-byte block, and always returns
   `(len(data), nil)`. `Sum(in)` snapshots `h`, `N`, `Σ`, and the partial
   buffer into locals, runs stage 3 on the copies, and appends the digest to
   `in` — the receiver is left untouched, so a caller can `Sum`, then `Write`
   more, then `Sum` again and get the running-hash result. This is required
   for `hash.Hash` conformance (`crypto/hmac` calls `Sum` without expecting
   it to reset state) and is checked directly by `TestSumNonDestructive`.

7. **13 key additions, 12 round constants.** `E(K, m)` performs 13 XOR-key
   stages (`K_1..K_13`) but only **12** round constants `C_1..C_12` are used
   to derive `K_2..K_13`; the loop in `e()` runs 12 iterations, each producing
   the next round key and applying one `LPS` round, before a final XOR. An
   off-by-one on the constant count yields a completely wrong digest.

## Test vectors

All vectors below are inline and runnable; they are exactly the cases in
`streebog/streebog_test.go`.

### RFC 6986 §10 standard examples

**M1** — 63-byte ASCII string
`"012345678901234567890123456789012345678901234567890123456789012"`:

- Streebog-256 =
  `9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500`
- Streebog-512 =
  `1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48`

**M2** (RFC 6986 §10.2 / GOST R 34.11-2012 §А.2) — the CP1251-encoded
"Се ветри, Стрибожи внуци..." message, given here as its raw hex bytes:

```
d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f1
20eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb
```

- Streebog-256 =
  `9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50`
- Streebog-512 =
  `1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d961376035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28`

**Empty string** (`""`):

- Streebog-256 =
  `3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb`
- Streebog-512 =
  `8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a`

**Carry-propagation stress** — 128 bytes (input hex): `0xee`×64, then `0x16`,
then `0x11`×62, then `0x16`:

- Streebog-256 =
  `81bb632fa31fcc38b4c379a662dbc58b9bed83f50d3a1b2ce7271ab02d25babb`
- Streebog-512 =
  `8b06f41e59907d9636e892caf5942fcdfb71fa31169a5e70f0edb873664df41c2cce6e06dc6755d15a61cdeb92bd607cc4aaca6732bf3568a23a210dd520fd41`

The empty-string vector exercises stage 3 with no stage 2 at all; the carry
vector exercises the `Σ`/`N` modular-add carry chain; M1 (63 bytes, one short
of a block) exercises padding with the `1`-bit pad in the last byte position.

### Property coverage

The test suite also pins the streaming and non-destructive contracts:
`TestStreaming` feeds a 1050-byte message through `Write` at chunk sizes
{1, 3, 7, 31, 63, 64, 65, 127, 128} and checks the result matches a one-shot
`Write`; `TestSumNonDestructive` checks that two consecutive `Sum` calls
return identical bytes, and that `Write` after `Sum` continues the running
hash correctly.

## Conformance testing

Streebog is a pure function (`[]byte msg → []byte digest`), so conformance
testing is direct known-answer comparison. The in-package tests
(`streebog/streebog_test.go`) anchor all the vectors above for both 256- and
512-bit output, plus the streaming and non-destructive-`Sum` properties.

```sh
go test ./streebog/
```

An independent reference implementation is used in a differential fuzz
harness elsewhere in this module's test suite, comparing digests over
arbitrary-length random messages for both output sizes.

## References

- **[RFC 6986](rfc/rfc6986.txt)** — "GOST R 34.11-2012: Hash Function".
  - §6 — S-box π (Table 1), permutation τ (Table 2), linear matrix `A` / `l`.
  - §6.5 — iteration constants `C_1..C_12` (printed MSB-first).
  - §7 — transformations X[k], S, P, L.
  - §8 — round function: E key schedule (`K_{i+1}=LPS(K_i⊕C_i)`),
    compression `g_N(h,m)=E(LPS(h⊕N),m)⊕h⊕m`.
  - §9 — three-stage hashing procedure (init / process / finalise),
    incl. Step 3.6 output and 256-bit truncation `MSB_256`.
  - §10 — informative worked examples (M1, M2).
- **GOST R 34.11-2012** — the originating Russian national standard
  (equivalent to RFC 6986).
- OIDs: Streebog-256 `1.2.643.7.1.1.2.2`, Streebog-512 `1.2.643.7.1.1.2.3`.

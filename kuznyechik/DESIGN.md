# Kuznyechik (Grasshopper) — GOST R 34.12-2015 128-bit block cipher

This document describes the Kuznyechik block cipher implemented by `package
kuznyechik`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

Kuznyechik (Russian "Кузнечик", "Grasshopper") is the 128-bit block cipher of
the Russian national standard **GOST R 34.12-2015**, republished as
**RFC 7801** ("GOST R 34.12-2015: Block Cipher 'Kuznyechik'", March 2016). It
is an SP-network with:

- block size **16 bytes** (128 bits),
- key size **32 bytes** (256 bits),
- **10 rounds** driven by **10 round keys**, each 16 bytes,
- a fixed 256-entry byte S-box (π), a fixed 16-byte linear transform L over
  GF(2^8), and a Feistel-based key schedule using 32 constants C_1…C_32.

It is a plain block cipher: it transforms exactly one 16-byte block. Modes
(CTR, OMAC, MGM, ACPKM, kexp15) are layered on top elsewhere — this document
covers only the block primitive `Encrypt`/`Decrypt`.

This package (`kuznyechik.go`) is a pure-Go, BSD-2-Clause implementation
deriving every constant from RFC 7801; it imports no GOST backend. `NewCipher`
returns a `*Cipher` satisfying `crypto/cipher.Block`. `Encrypt`/`Decrypt` use
fused `S∘L` / `L⁻¹` lookup tables built at first use from the underlying
bit-loop transforms; the slow `gf()`/`r()` path remains in the source as both
the table generator and the reference definition of the math. The default
cipher is table-driven and not constant-time — see
[SECURITY.md](SECURITY.md) for the timing model and the constant-time
`NewCipherCT` alternative.

### Where this module uses it

- The root `gostcrypto` facade re-exports it as `NewKuznyechikCipher`
  (returning `cipher.Block`) and the byte-in/byte-out `KuznyechikEncrypt` /
  `KuznyechikDecrypt` helpers.
- The mode packages in this module build on `*Cipher` generically through
  `cipher.Block`: **`ctracpkm`** (CTR + ACPKM re-keying), **`omac`**
  (CMAC/OMAC1 authentication), and **`mgm`** (MGM AEAD) are all exercised
  against Kuznyechik. See [`../ctracpkm/DESIGN.md`](../ctracpkm/DESIGN.md),
  [`../omac/DESIGN.md`](../omac/DESIGN.md), and
  [`../mgm/DESIGN.md`](../mgm/DESIGN.md).
- **`kexp15`** imports this package directly for its `KexpKuznyechik` variant
  (key-export wrapping). See [`../kexp15/DESIGN.md`](../kexp15/DESIGN.md).
- The pure-Go TLS client (the sibling `gostls` TLS module) builds the
  CTR-OMAC record layer on top of these mode packages for cipher suite
  **`0xC100`** (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`, RFC 9367 §4.3).
  The suite's KDF/PRF is Streebog-256 — Kuznyechik is only the bulk cipher and
  the OMAC block primitive.

There is no standalone OID for the bare block cipher in the TLS path; it is
identified by the suite ID `0xC100`.

---

## Specification

All section numbers below refer to **RFC 7801**. Sizes: input/output block 16
bytes; key 32 bytes; 10 round keys × 16 bytes; no IV (this is the raw block
transform).

### Field and notation

Operations are over the finite field **GF(2)[x]/p(x)** with reduction
polynomial (RFC 7801 §3.2):

```
p(x) = x^8 + x^7 + x^6 + x + 1
```

As a byte modulus this is `0x1C3` (9-bit), i.e. the low-byte XOR mask after a
left shift that overflows bit 7 is **`0xC3`**. A reference GF(2^8) multiply:

```
gf(a, b):
    c = 0
    while b > 0:
        if b & 1: c ^= a
        if a & 0x80: a = (a << 1) ^ 0xC3   # reduce by p(x)
        else:        a = a << 1
        b >>= 1
    return c & 0xFF
```

Bytes within a 128-bit block are indexed `a_15 || a_14 || … || a_0`, where
`a_15` is the **most significant / leftmost** byte (the first byte on the
wire) and `a_0` is the least significant. This big-endian byte indexing
matters for the direction of the L transform; see Implementation notes below.

### 1. Nonlinear transform S (π S-box) — RFC 7801 §4.1

> "The bijective nonlinear mapping is a substitution Pi = (Vec_8)Pi'(Int_8)."

S applies the 256-byte table π to every one of the 16 bytes independently.
The full table (π[0]…π[255], decimal as published):

```
252 238 221  17 207 110  49  22 251 196 250 218  35 197   4  77
233 119 240 219 147  46 153 186  23  54 241 187  20 205  95 193
249  24 101  90 226  92 239  33 129  28  60  66 139   1 142  79
  5 132   2 174 227 106 143 160   6  11 237 152 127 212 211  31
235  52  44  81 234 200  72 171 242  42 104 162 253  58 206 204
181 112  14  86   8  12 118  18 191 114  19  71 156 183  93 135
 21 161 150  41  16 123 154 199 243 145 120 111 157 158 178 177
 50 117  25  61 255  53 138 126 109  84 198 128 195 189  13  87
223 245  36 169  62 168  67 201 215 121 214 246 124  34 185   3
224  15 236 222 122 148 176 188 220 232  40  80  78  51  10  74
167 151  96 115  30   0  98  68  26 184  56 130 100 159  38  65
173  69  70 146  39  94  85  47 140 163 165 125 105 213 149  59
  7  88 179  64 134 172  29 247  48  55 107 228 136 217 231 137
225  27 131  73  76  63 248 254 141  83 170 144 202 216 133  97
 32 113 103 164  45  43   9  91 203 155  37 208 190 229 108  82
 89 166 116 210 230 244 180 192 209 102 175 194  57  75  99 182
```

The same table in hex (first byte `0xFC`):

```
FC EE DD 11 CF 6E 31 16 FB C4 FA DA 23 C5 04 4D
E9 77 F0 DB 93 2E 99 BA 17 36 F1 BB 14 CD 5F C1
F9 18 65 5A E2 5C EF 21 81 1C 3C 42 8B 01 8E 4F
05 84 02 AE E3 6A 8F A0 06 0B ED 98 7F D4 D3 1F
EB 34 2C 51 EA C8 48 AB F2 2A 68 A2 FD 3A CE CC
B5 70 0E 56 08 0C 76 12 BF 72 13 47 9C B7 5D 87
15 A1 96 29 10 7B 9A C7 F3 91 78 6F 9D 9E B2 B1
32 75 19 3D FF 35 8A 7E 6D 54 C6 80 C3 BD 0D 57
DF F5 24 A9 3E A8 43 C9 D7 79 D6 F6 7C 22 B9 03
E0 0F EC DE 7A 94 B0 BC DC E8 28 50 4E 33 0A 4A
A7 97 60 73 1E 00 62 44 1A B8 38 82 64 9F 26 41
AD 45 46 92 27 5E 55 2F 8C A3 A5 7D 69 D5 95 3B
07 58 B3 40 86 AC 1D F7 30 37 6B E4 88 D9 E7 89
E1 1B 83 49 4C 3F F8 FE 8D 53 AA 90 CA D8 85 61
20 71 67 A4 2D 2B 09 5B CB 9B 25 D0 BE E5 6C 52
59 A6 74 D2 E6 F4 B4 C0 D1 66 AF C2 39 4B 63 B6
```

S^{-1} (used only by `Decrypt`) is the inverse permutation: `piInv[pi[i]] =
i`, computed once at package init rather than tabulated separately.

### 2. Linear transform R and L — RFC 7801 §4.2–4.3

The 16-coefficient vector (RFC 7801 §4.2, the `l(...)` definition), decimal,
indexed from `a_15` down to `a_0`:

```
148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
```

Stored MS-first so that `lc[i]` pairs with `blk[i]` (`blk[0]` is the MS byte):

```
hex:  94 20 85 10 C2 C0 01 FB 01 C0 C2 10 85 20 94 01
dec: 148 32 133 16 194 192  1 251  1 192 194 16 133 32 148  1
```

**R** (one LFSR step), RFC 7801 §4.3, `R(a_15||…||a_0) = l(a_15,…,a_0) ||
a_15 || … || a_1`: compute one new byte `t` as the GF(2^8) dot product of the
block with the coefficient vector, shift every byte one position toward the
least-significant end, and place `t` into the most-significant position:

```
R(blk[0..15]):
    t = blk[15]
    for i in 0..14: t ^= gf(blk[i], lc[i])
    blk[1..15] = blk[0..14]      # shift right (toward LS index)
    blk[0] = t
```

**L = R applied 16 times** (RFC 7801 §4.3, `L(a) = R^16(a)`); `L^{-1}` runs R
backwards 16 times.

KAT for one R step: with all-zero block except `blk[14] = 0x01`, after one R
the block is `94 00 … 00 01`. This pins both the coefficient order and the
shift direction.

KAT for L: input `64 a5 94 00 00 … 00` → output
`d4 56 58 4d d0 e3 e8 4c c3 16 6e 4b 7f a2 89 0d`.

### 3. Round constants C_i — RFC 7801 §4.4

> "C_i = L(Vec_128(i)), i = 1, 2, …, 32."

`Vec_128(i)` is the 16-byte block whose least-significant byte (index 15 in
MS-first numbering) equals `i`, all other bytes zero; then apply L:

```
for i in 0..31:
    C[i] = zero 16-byte block
    C[i][15] = i + 1          # constants are 1-indexed: C_1..C_32
    L(C[i])
```

KAT: `C_1 = 6e a2 76 72 6c 48 7a b8 5d 27 bd 10 dd 84 94 01`;
`C_2 = dc 87 ec e4 d8 90 f4 b3 ba 4e b9 20 79 cb eb 02`.

### 4. Key schedule (10 round keys) — RFC 7801 §4.4

Split the 32-byte key into two 16-byte halves: `K_1 = key[0:16]`,
`K_2 = key[16:32]` — these are round keys 1 and 2 directly (no transform).

The Feistel round function is `F[C](a_1, a_2) = (LSX[C](a_1) XOR a_2, a_1)`,
where `LSX[C](x) = L(S(x XOR C))`. Then (RFC 7801 §4.4):

> `(K_{2i+1}, K_{2i+2}) = F[C_{8(i-1)+8}] … F[C_{8(i-1)+1}] (K_{2i-1}, K_{2i})`,
> i = 1, 2, 3, 4.

For each `i` in `1..4`, run 8 Feistel rounds over the current pair using
constants `C_{8(i-1)+1} … C_{8(i-1)+8}` (16 constants per pair × 4 pairs = 32
constants total, all `C_1..C_32` used), then emit the resulting pair as the
next two round keys. This yields `K_1…K_10`:

```
kr0 = key[0:16]; kr1 = key[16:32]
ks[0] = kr0; ks[1] = kr1
for i in 0..3:                       # 4 outer iterations
    for j in 0..7:                   # 8 Feistel rounds
        krt = kr0 XOR C[8*i + j]     # X[C]
        krt = S(krt)                 # S
        krt = L(krt)                 # L      → LSX
        krt = krt XOR kr1            # Feistel XOR with right half
        kr1 = kr0                    # swap
        kr0 = krt
    ks[2 + 2*i]     = kr0
    ks[2 + 2*i + 1] = kr1
```

KAT, with key
`8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef`:
`K_3 (ks[2]) = db31485315694343 228d6aef8cc78c44` … through
`K_10 (ks[9]) = 72e9dd7416bcf45b 755dbaa88e4a4043`.

### 5. Encryption / Decryption — RFC 7801 §4.5

`X[k](a) = a XOR k` (round-key add). `LSX[k] = L(S(X[k](a)))`.

**Encrypt** (RFC 7801 §4.5.1, `E = X[K_10] LSX[K_9] … LSX[K_1]`):

```
blk = src
for i in 0..8:                 # 9 LSX rounds
    blk = blk XOR ks[i]
    blk = S(blk)
    blk = L(blk)
blk = blk XOR ks[9]            # final X[K_10]
dst = blk
```

**Decrypt** (RFC 7801 §4.5.2,
`D = X[K_1] L^{-1}S^{-1} X[K_2] … L^{-1}S^{-1} X[K_10]`):

```
blk = src
for i = 9 down to 1:
    blk = blk XOR ks[i]
    blk = Linv(blk)
    blk = Sinv(blk)
blk = blk XOR ks[0]           # final X[K_1]
dst = blk
```

---

## Implementation notes

Points where a naive reading of the RFC text is easy to get backwards; each is
pinned by a test vector below.

1. **The L coefficient vector's byte order is easy to reverse.** RFC 7801
   §4.2 writes coefficients against `a_15 … a_0` (MS byte first):
   `148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1`. The
   vector is a palindrome **except at the endpoints** (`148` vs `1`), so a
   wrong-direction read produces visibly wrong output rather than a silent
   pass — the `R` KAT above catches it immediately.

2. **R shifts toward higher indices.** RFC 7801 §4.3 defines
   `R(a) = l(a) || a_15 || … || a_1` — the new byte enters the top (MS)
   position and the bottom byte `a_0` falls off. With `blk[0]` as the MS byte,
   that means the block shifts toward higher indices and `blk[0] = t`.

3. **The GF(2^8) reduction constant is `0xC3`, not `0x1B` or `0x87`.**
   RFC 7801 §3.2 fixes `p(x) = x^8+x^7+x^6+x+1`, whose post-shift XOR mask is
   `0xC3`. This is a different field than AES's `0x1B` or the OMAC/CMAC
   128-bit `Rb = 0x87` used one layer up by `package omac` — those apply to
   the *mode*, not to this block cipher's internal field arithmetic.

4. **π^{-1} is the true permutation inverse of π**, derived once
   (`piInv[pi[i]] = i`), not a second independently-published table.

5. **Round-constant indexing is 1-based and seeds the least-significant
   byte.** `C_i = L(Vec_128(i))`, `i` from 1; the implementation sets
   `cnst[i][15] = i+1` — index 15 is the LS byte in MS-first numbering, and
   the `+1` makes array slot 0 hold `C_1`. An off-by-one here silently
   corrupts the entire key schedule, which is why the `C_1`/`C_2` KAT is
   checked directly.

6. **Key-schedule step order is XOR-then-S-then-L, then XOR the other
   half, then swap.** RFC 7801 §4.4 composes `F[C]` as `LSX[C]` on the left
   half XOR the right half. Applying L before S, or omitting the swap, is a
   common mistake the round-key KAT catches.

7. **Encrypt runs 9 LSX rounds plus one final XOR; Decrypt is the exact
   inverse, `L^{-1}` before `S^{-1}`.** The inverse of `L∘S` is `S^{-1}∘L^{-1}`
   applied to the block in that textual order. The final whitening key is
   `K_10` for `Encrypt`, `K_1` for `Decrypt`.

8. **No endianness surprise inside the block transform itself.** Unlike
   GOST 28147-89 / Magma, Kuznyechik here is byte-array-oriented end to end:
   input bytes map directly to `blk[0..15]` with `blk[0]` as the first/MS
   byte, and output is copied back in the same order. There is no per-word
   little-endian reversal at the block boundary.

9. **`Encrypt`/`Decrypt` panic on short buffers.** `NewCipher` panics unless
   `len(key) == 32`; `Encrypt`/`Decrypt` panic if `src` or `dst` is shorter
   than `BlockSize` rather than silently truncating.

10. **Fused `S∘L` / `L^{-1}` tables replace the bit-loop on the hot path.**
    Because L is GF(2)-linear, `L(S(x))` decomposes over the 16 byte
    positions: `encTable[pos][b]` precomputes L applied to a block holding
    `S(b)` at position `pos` alone, packed as two big-endian `uint64` words;
    a full S+L round is then 16 table loads XORed together instead of the
    per-bit `gf()`/`r()` loop. `lInvTable` fuses `L^{-1}` alone (no S-box) for
    `Decrypt`'s round body. Every table entry is generated from the bit-loop
    transforms at first use (`sync.Once`) — the slow path remains the source
    of truth and the tables are never hand-transcribed. `EncryptBlocks`
    extends this to whole batches: on every default build it is successive
    `Encrypt` calls, but on `amd64` with `GOEXPERIMENT=simd` it dispatches to
    a 32-block, constant-time AVX2 engine that is *faster* than this
    non-constant-time table path (see [EXPERIMENT-simd.md](EXPERIMENT-simd.md)
    for the design and numbers). `CTRXORBlocks`, gated the same way, fuses
    keystream generation and XOR for CTR-style callers such as `ctracpkm`.

11. **None of the known GOST reference-implementation divergences touch this
    primitive.** There are three known gogost/gost-engine ground-truth
    divergences — GOST 28147-89 S-box row order, GOST R 34.11-94 empty-input
    finalization, and CryptoPro key meshing — and all three are specific to
    those other primitives.
    Kuznyechik's π, L vector, constants, and round structure are
    bit-for-bit consistent across the references checked during
    implementation; there is no analogous caveat to carry for this cipher.

---

## Test vectors

### Primary KAT — GOST R 34.12-2015 §A.1 / RFC 7801 §5.5–5.6

```
Key (32 B):        8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
Plaintext  (16 B): 1122334455667700ffeeddccbbaa9988
Ciphertext (16 B): 7f679d90bebc24305a468d42b9d4edcd
```

`Encrypt(Key, Plaintext) == Ciphertext` and `Decrypt(Key, Ciphertext) ==
Plaintext`.

### Intermediate KATs (pin each stage independently)

- **S (one π pass):** input `ffeeddccbbaa9988 1122334455667700` → after one S
  `b66cd8887d38e8d7 7765aeea0c9a7efc`.
- **R (one LFSR step):** input `00…00 0100` (i.e. `blk[14]=0x01`) →
  `9400000000000000 0000000000000001`.
- **L (= R^16):** input `64a5940000000000 0000000000000000` →
  `d456584dd0e3e84c c3166e4b7fa2890d`.
- **Constants:** `C_1 = 6ea276726c487ab8 5d27bd10dd849401`,
  `C_2 = dc87ece4d890f4b3 ba4eb92079cbeb02`.
- **Round keys:** full `K_1…K_10` for the §A.1 key above;
  `K_10 = 72e9dd7416bcf45b 755dbaa88e4a4043`.

These five line up exactly with the RFC 7801 §5.1–5.4 worked example, so they
double as an RFC cross-check.

### ECB sequence

GOST R 34.13-2015 §A.1.1 additionally publishes a 4-block ECB sequence for the
same key, exercised in this package's tests as an end-to-end confirmation that
successive `Encrypt` calls compose correctly.

---

## Conformance testing

In-package tests (`kuznyechik/kuznyechik_test.go`, white-box `package
kuznyechik`) anchor the primary §A.1 / RFC 7801 §5.5–5.6 vector, the 4-block
ECB sequence from GOST R 34.13-2015 §A.1.1, the per-stage KATs for S, R, L,
the round constants and the round keys, a deterministic round-trip sweep, full
buffer-overlap aliasing, key-copy non-retention, and the bad-key/short-buffer
panics (`guard_test.go`). `BenchmarkEncrypt`/`BenchmarkDecrypt` measure the
table-driven path.

In addition, a differential fuzz harness compares this package's `NewCipher`
against an independent reference implementation over random keys and inputs,
including the pinned KATs, to catch any divergence a fixed test vector alone
would miss.

```sh
go test ./kuznyechik/
```

The constant-time (`NewCipherCT`) and SIMD (`EncryptBlocks`/`CTRXORBlocks`)
paths have their own verification methodology — see
[SECURITY.md](SECURITY.md) and [EXPERIMENT-simd.md](EXPERIMENT-simd.md).

## References

- **[RFC 7801](rfc/rfc7801.txt)** — "GOST R 34.12-2015: Block Cipher
  'Kuznyechik'", V. Dolmatov (Ed.), March 2016.
  - §3.2 reduction polynomial `x^8+x^7+x^6+x+1`
  - §4.1 nonlinear S (π and π^{-1})
  - §4.2 linear coefficient vector `l(…)`
  - §4.3 R and `L = R^16`
  - §4.4 constants `C_i = L(Vec_128(i))` and Feistel key schedule
  - §4.5.1 Encryption `E`, §4.5.2 Decryption `D`
  - §5.1–5.6 worked example and §A.1 test vector
- **GOST R 34.12-2015** — Russian national standard (Kuznyechik is the
  128-bit cipher; Magma is the 64-bit cipher — see
  [`../magma/DESIGN.md`](../magma/DESIGN.md)). RFC 7801 is its English
  republication.
- **[RFC 9367](rfc/rfc9367.txt)** — GOST cipher suites for TLS 1.2; §4.3
  defines `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` (`0xC100`), this
  module's consumer of the primitive.
- **[RFC 9189](rfc/rfc9189.txt)** — GOST cipher suites for TLS 1.2 (key
  transport / `kexp15` context for the Kuznyechik usage).

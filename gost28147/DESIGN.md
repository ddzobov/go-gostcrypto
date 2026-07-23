# GOST 28147-89 — block cipher core (RFC 5830)

This document describes the GOST 28147-89 block cipher implemented by
`package gost28147`: what it is, its specification, the notable points of
this implementation, and the test vectors that pin it. For the public API and
a usage example see the [package README](README.md).

## What it is

GOST 28147-89 is the Soviet/Russian 64-bit-block, 256-bit-key Feistel block
cipher (Государственный стандарт). The cipher algorithms — ECB ("simple
substitution"), gamma/CTR, gamma-feedback/CFB, and IMIT/MAC — are republished
in English as **RFC 5830**.

This package covers the **core block primitive only**: the key schedule, the
round function (the `t`-substitution + 11-bit cyclic shift), the 32-round
encrypt/decrypt schedule, the 16-round MAC (IMIT) schedule, the little-endian
block↔word packing, and the two named S-box parameter sets. Modes built on
top of it — the CNT counter stream, the IMIT MAC with CryptoPro key meshing,
and the CFB step used by the CryptoPro key wrap — are consumers of this
primitive and are documented in their own packages; they are covered here
only insofar as they depend on the 16-round schedule or a raw ECB block.

The cipher is sometimes called "Magma" in its 2015 re-standardization
(GOST R 34.12-2015, still a 64-bit block), but the 2015 Magma uses a *fixed*
S-box and a *big-endian* block convention — it is a **different** primitive,
implemented separately in `package magma` (see
[`../magma/DESIGN.md`](../magma/DESIGN.md)).

S-box parameter sets and their OIDs come from **RFC 4357 §2** ("Additional
Cryptographic Algorithms for Use with GOST 28147-89…").

**Dimensions**

| Quantity | Value |
|---|---|
| Block size | 8 bytes (64 bit) |
| Key size | 32 bytes (256 bit) |
| Subkeys | 8 × 32-bit, little-endian from the key |
| Rounds (encrypt/decrypt) | 32 |
| Rounds (IMIT MAC) | 16 (separate schedule) |
| S-box | 8 × 16 nibbles |
| MAC tag (IMIT) | 1–8 bytes (TLS truncates to 4) |

### Where this module uses it

- **`gost28147cnt`** builds the GOST 28147-89 CNT counter/gamma stream over a
  `*Cipher`; its key meshing rebuilds the cipher with the original S-box
  (read back via `SBox()`). See
  [`../gost28147cnt/DESIGN.md`](../gost28147cnt/DESIGN.md).
- **`gost28147imit`** builds the 16-round IMIT MAC on top of the same key
  schedule and S-box tables, using its own truncated round sequence and
  output-half convention (see Implementation notes below). See
  [`../gost28147imit/DESIGN.md`](../gost28147imit/DESIGN.md).
- **`keywrap`** uses the GOST 28147-89 ECB block step and a CFB-mode IMIT for
  the CryptoPro key wrap and key diversification. See
  [`../keywrap/DESIGN.md`](../keywrap/DESIGN.md).
- The root facade exposes an opaque `GOST28147Cipher` handle
  (`Encrypt`/`Decrypt`/`SeqMACBlock`), single-block `GOST2814789Encrypt` /
  `GOST2814789Decrypt` helpers, and the CNT/IMIT stream factories. It selects
  **CryptoPro-A** for GOST 2001 suites and **tc26-Z** for GOST 2012 suites.

## Specification

### 1. Block ↔ word packing (little-endian)

The 64-bit block is split into two 32-bit halves `N1` (low) and `N2` (high).
The bytes are read **little-endian**: byte 0 is the least significant byte of
`N1`.

```
N1 = b[0] | b[1]<<8 | b[2]<<16 | b[3]<<24      // first 4 bytes, LE
N2 = b[4] | b[5]<<8 | b[6]<<16 | b[7]<<24      // last 4 bytes, LE
```

The subkeys are derived from the 256-bit key the same way — eight 32-bit
little-endian words `X[0..7]`.

> **Endianness caution.** RFC 5830 §4 (General Statements) phrases the cipher
> over a 64-bit value and 32-bit subkeys `X(i)` without nailing down a byte
> order, because the original GOST defined the cipher over machine words, not
> octet strings. The octet→word convention is **little-endian** in every
> interoperable implementation. Getting this wrong makes every test vector
> fail.

### 2. Round function `t` (the S-box substitution + shift)

Within a round, the 32-bit input `x` (already `= half + subkey mod 2^32`) is
substituted nibble-by-nibble through the eight S-boxes, then cyclically left-
rotated by 11 bits.

RFC 5830 §4 describes the substitution box `K` as eight nodes `K(1)…K(8)`,
each a permutation of `{0..15}`, applied to the eight 4-bit groups of the
32-bit word; the result is rotated left by 11. In this package, the S-box is
indexed by nibble `i` (bits `4i..4i+3`) through table row `s[i]`, and the
substituted nibble is written back to bit position `4i`:

```
t(x) = Σ over i=0..7 of  s[i][(x >> 4i) & 0xF]  << 4i
```

So **row `s[0]` substitutes the lowest nibble (bits 0–3); row `s[7]`
substitutes the highest nibble (bits 28–31).** Then:

```
f(x) = rotl32(t(x), 11)
```

### 3. One Feistel round

```
(N1, N2) ← ( f(N1 + X[i]) XOR N2,  N1 )
```

i.e. the new `N1` is `f(N1 + X[i]) ⊕ N2`, and the new `N2` is the old `N1`,
with the addition mod 2³². The per-round subkey index sequence determines
which `X[i]` is used at each step.

### 4. Encrypt schedule (32 rounds)

```
SeqEncrypt = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7,  7,6,5,4,3,2,1,0]
```

Three forward passes `X[0..7]` then one reverse pass `X[7..0]`. This matches
RFC 5830 §5 (Electronic Codebook Mode, basic encryption step `A`): subkeys
used in order K0…K7 three times, then K7…K0 once.

### 5. Decrypt schedule (32 rounds)

```
SeqDecrypt = [0,1,2,3,4,5,6,7,  7,6,5,4,3,2,1,0,  7,6,5,4,3,2,1,0,  7,6,5,4,3,2,1,0]
```

One forward pass then three reverse passes — the exact inverse of encrypt.

### 6. Output packing (note the half-swap)

After the final round the two halves are written back, but with the halves
**swapped** relative to input order — `N2` goes to bytes 0–3, `N1` to bytes
4–7:

```
out[0..3] = LE(N2)
out[4..7] = LE(N1)
```

This swap is what makes the 32-round Feistel network its own structural
inverse under the reversed key schedule.

### 7. The 16-round MAC (IMIT) schedule

IMIT (имитовставка / message authentication) uses a **truncated 16-round**
encryption — only the first two forward subkey passes, no reverse pass:

```
SeqMAC = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7]
```

RFC 5830 §8 (the MAC generation mode / imitovstavka) specifies exactly 16
rounds of the encryption step, not 32 — this is **the** defining difference
between the MAC core and the cipher core. This module surfaces the 16-round
step through the root facade as `GOST28147Cipher.SeqMACBlock`, since it is
otherwise unreachable via the plain cipher API; the full IMIT chaining
(XOR the next plaintext block into the running state, run the 16-round
transform, repeat, then take the leading `s` bytes of the final state as the
tag) is implemented in `gost28147imit`.

### 8. S-box parameter sets (RFC 4357 §2)

An S-box is `[8][16]byte` — eight rows of sixteen nibbles. Row `s[i]`
substitutes nibble `i` (row 0 = lowest nibble). Two are load-bearing in this
repo:

**CryptoPro-A** (`id-Gost28147-89-CryptoPro-A-ParamSet`, OID
`1.2.643.2.2.31.1`) — used for TLS suite `0x0081` record protection and the
CryptoPro key wrap when the certificate is GOST R 34.10-2001 (RFC 4357 §2.3):

```
s[0] = {9,6,3,2,8,11,1,7,10,4,14,15,12,0,13,5}
s[1] = {3,7,14,9,8,10,15,0,5,2,6,12,11,4,13,1}
s[2] = {14,4,6,2,11,3,13,8,12,15,5,10,0,7,1,9}
s[3] = {14,7,10,12,13,1,3,9,0,2,11,4,15,8,5,6}
s[4] = {11,5,1,9,8,13,15,0,14,4,2,3,12,7,10,6}
s[5] = {3,10,13,12,1,2,0,11,7,5,9,4,8,15,14,6}
s[6] = {1,13,2,9,7,10,6,0,8,12,4,5,15,3,11,14}
s[7] = {11,10,15,5,0,12,14,8,6,2,3,9,1,7,13,4}
```

**tc26-Z** (`id-tc26-gost-28147-param-Z`, OID `1.2.643.7.1.2.5.1.1`) — used
for the 2012 TLS suites (`0xFF85`, `0xC102`) record protection and the
CryptoPro key wrap when the certificate is GOST R 34.10-2012:

```
s[0] = {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1}
s[1] = {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15}
s[2] = {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0}
s[3] = {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11}
s[4] = {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12}
s[5] = {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0}
s[6] = {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7}
s[7] = {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2}
```

This module exports only `SboxCryptoProA` and `SboxTC26Z`; the root facade
selects the appropriate one per suite. A third named set, "R34.11-94-
CryptoPro", is used internally by the GOST R 34.11-94 hash — it is not
exported from this package and is not used for TLS record protection or key
wrap.

## Implementation notes

Points where a naive reading of the RFC is easy to get backwards; each is
exercised by a test vector below.

1. **Little-endian octet packing is mandatory, not just conventional.**
   RFC 5830 defines the cipher over 64-bit values and 32-bit subkeys without
   fixing an octet order — all interoperable implementations pack octets
   little-endian (byte 0 → LSB of `N1`; key bytes 0–3 → `X[0]` LSB-first). A
   big-endian reading fails every vector below.

2. **The output half-swap is easy to drop.** Encrypt/decrypt write the two
   final halves swapped: `N2` to the first 4 octets, `N1` to the last 4.
   Omitting the swap yields a transform that is not invertible by the
   `SeqDecrypt` schedule.

3. **The MAC's internal output-half ordering is deliberately the opposite of
   the cipher's.** The IMIT MAC's block transform keeps `(N1,N2)` in
   "natural" (non-swapped) order across chained blocks, while the cipher
   writes `N2` first. Both conventions are internally self-consistent — an
   implementation that reuses the cipher's pack/unpack verbatim inside the
   MAC produces wrong tags.

4. **The 16-round MAC schedule is not the 32-round cipher schedule.**
   RFC 5830 §8 fixes IMIT at 16 rounds; using the 32-round schedule for the
   MAC is a classic and silent bug — it produces a plausible-looking 8-byte
   value that is simply wrong.

5. **The S-box row convention here matches gogost and gost-engine, not the
   raw RFC/textbook table layout.** Independent implementations (gogost,
   gost-engine) agree byte-for-byte on the S-box tables for this cipher: row
   `s[0]` is the low nibble, `s[7]` the high nibble, with no transposition
   between them. Both differ from the RFC/GOST textbook presentation by a
   90° rotation — GOST prints each S-box node as a column, code stores it as
   a row — so a table transcribed directly out of RFC 4357 or a textbook may
   need transposing before it matches the byte tables in §8 above; the
   tables as printed in this document are already in the row convention this
   package uses and need no further transposition. (A related but distinct
   row-reversal quirk exists in the GOST R 34.11-94 hash's own use of this
   cipher — that is specific to the hash, not to the plain ECB/CNT/IMIT paths
   this package implements.)

6. **CNT (counter) mode increments by fixed constants** — not part of the
   block core, but relevant context for `gost28147cnt`: the two 32-bit
   counter halves are incremented by `C2 = 0x01010101` (low half) and
   `C1 = 0x01010104` (high half) per gamma block.

7. **CryptoPro key meshing re-keys every 1024 bytes.** Also not block-core,
   but the closest gotcha for `gost28147imit` over long records: the
   CryptoPro key-meshing step (RFC 4357 §2.3.2) re-keys every 1024 processed
   bytes by ECB-decrypting the current key against a fixed 32-byte constant:

   ```
   69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
   18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
   ```

8. **A MAC built on this cipher should finalize on a copy, not mutate live
   state.** A MAC's `Sum`/finalize step should snapshot state rather than
   alias into the running accumulator when a partial block is pending —
   otherwise a caller that calls `Sum` and then continues writing gets
   corrupted results. `gost28147imit` implements this finalize-on-copy
   discipline on top of the primitives here.

## Test vectors

### V1. ECB single block, CryptoPro-A S-box

```
S-box:          CryptoPro-A (1.2.643.2.2.31.1)
key  (32B):     00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1
plaintext (8B): 1020304050607080
ciphertext(8B): 2685b30ddb497d05
```

`NewCipher(key, SboxCryptoProA).Decrypt` recovers `1020304050607080` from the
ciphertext above.

### V1b. ECB single block, tc26-Z S-box

Same key and plaintext as V1, under the tc26 param-Z S-box instead of
CryptoPro-A, so the tc26-Z table can be validated against a fixed ciphertext
rather than only by round-trip:

```
S-box:          tc26-Z (1.2.643.7.1.2.5.1.1)
key  (32B):     00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1
plaintext (8B): 1020304050607080
ciphertext(8B): 9810491f00ca7be0
```

An implementation that reproduces both `2685b30ddb497d05` (CryptoPro-A) and
`9810491f00ca7be0` (tc26-Z) has both S-box transcriptions correct.

### Module unit tests

- `gost28147/gost28147_test.go` — the two ECB KATs above, four additional
  engine-derived ECB vectors (edge-case keys/plaintexts under tc26-Z), a
  256-input round-trip sweep per S-box, an S-box permutation sanity check,
  and the `SBox()` accessor.
- `gost28147/guard_test.go` — the compile-time `cipher.Block` assertion,
  panic guards (bad key length, short `src`/`dst`), and an in-place
  `Encrypt`/`Decrypt` test (buffer aliasing, load-bearing for higher modes
  such as `omac` and `keywrap` that operate in place on shared buffers).

## Conformance testing

The in-package tests above anchor the fixed vectors. In addition, a
differential fuzz harness compares this implementation's `Encrypt`/`Decrypt`
against an independent reference implementation, byte-for-byte, over random
keys and inputs under the CryptoPro-A S-box.

```sh
go test ./gost28147/
```

No `//go:build` tags are required for this package.

## References

- **[RFC 5830](rfc/rfc5830.txt)** — "GOST 28147-89: Encryption, Decryption,
  and Message Authentication Code (MAC) Algorithms".
  - §4 — General statements: the substitution box `K` and round function.
  - §5 — Electronic Codebook Mode (the 32-round encryption step).
  - §8 — MAC generation mode (the 16-round IMIT transform).
- **[RFC 4357](rfc/rfc4357.txt)** — "Additional Cryptographic Algorithms for
  Use with GOST 28147-89, GOST R 34.10-94, GOST R 34.10-2001, and
  GOST R 34.11-94 Algorithms".
  - §2 — S-box parameter sets and OIDs (CryptoPro-A, tc26-Z).
  - §2.3.2 — CryptoPro key meshing.
  - §6.3 / §6.5 — CryptoPro key wrap.
- **[RFC 9189](rfc/rfc9189.txt)** — GOST cipher suites for TLS 1.2. §4.1
  GOST_KEY_TRANSPORT, §4.2 IMIT-4 MAC truncation.
- **[RFC 5831](rfc/rfc5831.txt)** — GOST R 34.11-94 hash function (context
  for the related R34.11-94-CryptoPro S-box, not used by this package).
- **GOST 28147-89** — Russian Federal Standard, block cipher (the normative
  source republished as RFC 5830).
- **GOST R 34.12-2015 / GOST R 34.13-2015** — the 2015 re-standardization
  ("Magma"); a different primitive (fixed S-box, big-endian) — see
  [`../magma/DESIGN.md`](../magma/DESIGN.md).

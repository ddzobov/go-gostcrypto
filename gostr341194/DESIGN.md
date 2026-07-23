# GOST R 34.11-94 legacy hash — CryptoPro parameter set

This document describes the legacy hash implemented by `package gostr341194`:
what it is, its specification, the notable points of this implementation, and
the test vectors that pin it. For the public API and a usage example see the
[package README](README.md).

## What it is

GOST R 34.11-94 is the legacy Soviet/Russian 256-bit hash function, specified
in English as [RFC 5831](rfc/rfc5831.txt) and superseded by Streebog
(GOST R 34.11-2012, see [`../streebog/DESIGN.md`](../streebog/DESIGN.md)).
Structurally it is a
Merkle–Damgård-like construction whose compression function is built directly
on the GOST 28147-89 block cipher: each compression step derives four 256-bit
keys from the chaining value and message block, runs four GOST 28147-89 ECB
encryptions, and folds the results through a fixed linear mixing transform.

The algorithm is parameterized by the S-box its inner 28147 cipher uses. This
package hard-codes the **CryptoPro parameter set** —
`id-GostR3411-94-CryptoProParamSet`, OID `1.2.643.2.2.30.1`
([RFC 4357](rfc/rfc4357.txt) §11.2 / §10.4) — which is the variant used on the
wire by Tarantool-EE. Swapping in RFC 5831's own S-box instead would produce
the RFC's published "test parameter set" vectors, which this package does not
expose.

| Quantity | Value |
|---|---|
| Output / block / internal state size | 32 bytes (256 bits) each |
| Hash algorithm OID | `id-GostR3411-94` = `1.2.643.2.2.9` ([RFC 4357](rfc/rfc4357.txt) §10.4) |
| Parameter-set OID | `id-GostR3411-94-CryptoProParamSet` = `1.2.643.2.2.30.1` ([RFC 4357](rfc/rfc4357.txt) §10.4 / §11.2) |
| Inner cipher | GOST 28147-89, ECB, 32-round encrypt (see [`../gost28147`](../gost28147)) |

### Where this module uses it

- The root facade exposes it as `NewGOSTR341194CryptoProHash` (returning
  `hash.Hash`) and the one-shot `GOSTR341194` byte-in/byte-out helper.
- **`x509gost`** — the hash OID `1.2.643.2.2.9` appears in legacy
  GOST R 34.10-2001 certificate signature algorithms; the digest under those
  signatures is this primitive.
- Internally, the compression function's four ECB encryptions are performed
  by **`package gost28147`** ([`../gost28147/DESIGN.md`](../gost28147/DESIGN.md)),
  keyed with this package's own CryptoPro *hash* S-box — a different table
  from any of `gost28147`'s own named cipher S-boxes (`SboxCryptoProA`,
  `SboxTC26Z`), transcribed directly from [RFC 4357](rfc/rfc4357.txt) §11.2.

## Specification

All step references below are to **RFC 5831**. GOST R 34.11-94 numbers its
symbols right-to-left (RFC 5831 §3): the rightmost byte of a 256-bit word is
byte #1. This implementation stores every block so that array index `i` holds
byte #(i+1) — i.e. message bytes are used in their natural order, with no
per-block or per-word reversal anywhere. The transforms below (`A`, `P`, `ψ`)
and the constant `C3` are defined directly on that numbering; see
[Implementation notes](#implementation-notes) for why this is the simpler of
two equally-valid conventions.

### Sizes and constants

| Item | Value |
|---|---|
| Block size | 32 bytes (256 bits) |
| Output size | 32 bytes (256 bits) |
| Internal state `H` | 32 bytes, initialized to all-zero (`h0 = 0^256`) |
| Checksum `Σ` | 32 bytes, addition modulo 2^256, initialized to zero |
| Length `L` | 32 bytes, total message bit-length mod 2^256, initialized to zero |
| Inner cipher | GOST 28147-89, ECB, 32-round encrypt |

Compression-function constants `C2`, `C3`, `C4` (RFC 5831 §5.1). `C2` and `C4`
are all-zero. `C3` is the 32-byte pattern

```
1^8 0^8 1^16 0^24 1^16 0^8 (0^8 1^8)^2 1^8 0^8 (0^8 1^8)^4 (1^8 0^8)^4
```

written most-significant byte (#32) first; this package builds the constant
from that bit pattern directly rather than transcribing a byte table, so no
separate reversal step is needed to match this implementation's byte-order
convention.

### CryptoPro S-box (the parameter dependency)

The compression function's inner 28147 cipher uses the CryptoPro **hash**
S-box, 8 rows × 16 nibbles ([RFC 4357](rfc/rfc4357.txt) §11.2; row `i`
substitutes nibble `i` of a 32-bit word), applied exactly as printed, with no
row reversal:

```
row0: 10  4  5  6  8  1  3  7 13 12 14  0  9  2 11 15
row1:  5 15  4  0  2 13 11  9  1  7  6  3 12 14 10  8
row2:  7 15 12 14  9  4  1  0  3 11  5  2  6 10  8 13
row3:  4 10  7 12  0 15  2  8 14  1  6  5 13 11  9  3
row4:  7  6  4 11  9 12  2 10  1  8  0 14 15 13  3  5
row5:  7  6  2  4 13  9 15  0 10  1  5 11  8 14 12  3
row6: 13 14  4  1  7  0  5 10  3 12  8 15  6  2  9 11
row7:  1  3 10  9  5 11  4 15  8  6  7 14 13  0  2 12
```

### Compression function χ(M, H) (RFC 5831 §5)

Inputs `H, M ∈ V256`. Three stages:

**1. Key generation (§5.1).** Produce four 256-bit keys `K1..K4` via
transforms `A` and `P`:

- `A(X)`: split `X = x4||x3||x2||x1` into four 64-bit words;
  `A(X) = (x1 ⊕ x2) || x4 || x3 || x2`.
- `P(X)`: the byte permutation `φ(i+1+4(k-1)) = 8i+k`, `i = 0..3`, `k = 1..8`.

```
U := H ; V := M ; W := U ⊕ V ; K1 := P(W)
U := A(U) ⊕ C2 ; V := A(A(V)) ; W := U ⊕ V ; K2 := P(W)
U := A(U) ⊕ C3 ; V := A(A(V)) ; W := U ⊕ V ; K3 := P(W)
U := A(U) ⊕ C4 ; V := A(A(V)) ; W := U ⊕ V ; K4 := P(W)
```

**2. Encryption (§5.2).** Split `H = h4||h3||h2||h1` (four 64-bit words);
`si = E(Ki, hi)` (a GOST 28147-89 ECB 32-round encryption per word).
`S = s4||s3||s2||s1`.

**3. Mixing (§5.3).** Define `ψ` on `η16||...||η1` (sixteen 16-bit words):

```
ψ(X) = (η1⊕η2⊕η3⊕η4⊕η13⊕η16) || η16 || η15 || ... || η2
```

i.e. every word shifts down one slot, the top slot receives the XOR fold, and
`η1` is dropped. The final compression output is

```
χ(M, H) = ψ^61( H ⊕ ψ( M ⊕ ψ^12(S) ) )
```

— 12 applications of ψ over `S`, XOR `M`, one more ψ, XOR `H`, then 61 more ψ
(74 total).

### Main procedure (RFC 5831 §6)

Initialize `H := 0^256`, `Σ := 0^256`, `L := 0^256`. For each full 256-bit
message block `M_s`, in order:

```
H := χ(M_s, H)
L := (L + 256) mod 2^256
Σ := Σ ⊕' M_s        # ⊕' = byte-wise addition mod 2^256, with carry
```

For the final (possibly partial, possibly zero-length) fragment of `|M|` bits,
with `M' = 0^(256-|M|) || M` (left zero-padded):

```
L := (L + |M|) mod 2^256
Σ := Σ ⊕' M'
H := χ(M', H)
H := χ(L, H)     # absorb the length block
H := χ(Σ, H)     # absorb the checksum block
```

The resulting 256-bit `H` is the digest. `Σ` uses addition modulo 2^256, NOT
XOR — RFC 5831 §6 writes it as the `(+)'` operator.

## Implementation notes

Points where a naive reading of the RFC is easy to get wrong; each is pinned
by a test vector below.

1. **Byte order: this implementation reverses nothing.** RFC 5831 §3 numbers
   symbols right-to-left, so a literal reading suggests reversing every block
   at its boundaries and reversing the inner-cipher word feed to compensate.
   That reversal is not actually required: reading the RFC's right-to-left
   numbering directly as "array index `i` holds byte #(i+1)" (natural message
   order) and defining `A`, `P`, `ψ`, and the `C3` constant on that same
   numbering throughout produces bit-identical output on every non-empty
   input, with no reversal anywhere — the two conventions are equivalent, and
   "reverse nothing" is simply the simpler one to implement correctly. Mixing
   the two conventions (reversing in some places but not others) is the
   classic way to get a byte-swapped digest.

2. **The CryptoPro hash S-box is applied exactly as printed, rows in natural
   order.** Some other implementations store the rows in reverse order and
   compensate with an extra block-reversal step inside the compression
   function; since this implementation already reverses nothing (note 1),
   applying the table as printed and reversing nothing else is the correct,
   consistent choice.

3. **`Σ` is mod-2^256 addition with carry, not XOR.** Implemented as a
   byte-wise add with a running carry across all 32 bytes. Using XOR here is
   a common bug: it happens to match addition for short inputs by luck and
   only diverges once a carry actually occurs, so it survives naive testing
   and fails on longer messages (see the multi-block vectors below).

4. **The length block `L` is a bit count, not a byte count.** The running
   total is tracked and encoded in bits (`nbuf * 8` bits added for the final
   fragment); encoding a byte count instead silently corrupts every digest
   whose input length isn't a whole number of bytes-as-bits coincidence.

5. **Empty input requires an extra compression step (the empty-input
   quirk).** RFC 5831 §6 is silent on the degenerate empty-message case: its
   loop only describes processing "the last block" when a message exists.
   Well-known GOST implementations genuinely disagree here — one widely used
   reference Go implementation folds in only the length block and the
   checksum block for an empty message (two compressions total), while the
   reference GOST engine used by Tarantool inserts one *additional*
   compression over an all-zero block **before** those two (three
   compressions total), and the two produce different 256-bit digests for
   `""`. This package matches the engine/Tarantool behavior: when total
   length is zero, it compresses one extra all-zero block first. Non-empty
   inputs are unaffected and agree bit-for-bit across implementations; the
   divergence is isolated to the zero-length case. See the two candidate
   digests in [Test vectors](#test-vectors) below.

6. **`Sum` is non-destructive.** It snapshots the chaining value, checksum,
   and length before folding in the finalization blocks, so the receiver
   survives repeated `Sum` calls and later `Write`s — the same
   finalize-on-copy contract documented for
   [`omac`](../omac/DESIGN.md#implementation-notes).

7. **The key-schedule constants `C2`/`C4` are no-ops; only `C3` does
   anything.** Since `C2` and `C4` are all-zero, `A(U) ⊕ C2` and `A(U) ⊕ C4`
   are just `A(U)`; only the `K3` step's XOR with `C3` has any effect. Some
   references reach the same `K3` via bit-complementing specific bytes of `U`
   instead of an explicit XOR table — both are equivalent ways of expressing
   the same constant; this package uses the plain XOR-table form built
   directly from the RFC's bit pattern.

## Test vectors

CryptoPro-parameter-set known-answer values, all reproduced from the
in-package test table (`gostr341194/gostr341194_test.go`):

| Input | Digest (hex) |
|---|---|
| `"a"` | `e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011` |
| `"abc"` | `b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c` |
| `""` (empty — **the divergence**, see note 5) | `3f25bc1fbbce27ca10fb1958f319473ae7e17482c3b53ecf47a7e2de8aabe4c8` (this package; matches the reference GOST engine / Tarantool) |
| `""` — for comparison only, **not** produced by this package | `981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0` (produced by at least one other well-known Go implementation, which omits the extra empty-input step) |
| `"message digest"` | `bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0` |
| `128 × "U"` (4 full 32-byte blocks) | `1c4ac7614691bbf427fa2316216be8f10d92edfd37cd1027514c1008f649c4e8` |
| `132 × "U"` (4 full blocks + 4-byte partial block) | `e791faa11d4ab35ffcdb5246db8fe4c3d6802e9eef52be9405c11b69bce108b4` |
| `"The quick brown fox jumps over the lazy dog"` | `9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76` |
| `"The quick brown fox jumps over the lazy cog"` (one-letter avalanche check) | `a93124f5bf2c6d83c3bbf722bc55569310245ca5957541f4dbd7dfaf8137e6f2` |
| `"This is message, length=32 bytes"` | `2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb` |
| `"Suppose the original message has length = 50 bytes"` | `c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011` |

The `128 × "U"` / `132 × "U"` pair exercises the block-aligned vs. partial-final-block
paths side by side; both were validated against the reference GOST engine.
The `"a"` and `"abc"` vectors are the canonical published CryptoPro test
vectors and additionally pin the non-destructive-`Sum` behavior (note 6): a
`Sum` call after writing `"ab"`, followed by writing `"c"` and summing again,
must reproduce the `"abc"` digest.

The in-package tests also verify the streaming contract: writing a 200-byte
message in chunks of 1, 3, 7, 31, 32, 33, 64, and 199 bytes all reproduce the
same one-shot digest, exercising the partial-block buffering path across
block boundaries in every alignment.

## Conformance testing

The in-package tests (`gostr341194/gostr341194_test.go`) anchor all of the
vectors above, including the deliberately-chosen engine value for the
empty-input case. In addition, a differential fuzz harness compares this
implementation against an independent reference implementation over random
message lengths and streaming split points — deliberately excluding the
empty-input case, since that is the one documented, intentional divergence
(note 5): this package matches the reference GOST engine, not that other
reference, for Tarantool interoperability.

```sh
go test ./gostr341194/
```

## References

- **[RFC 5831](rfc/rfc5831.txt)** — "GOST R 34.11-94: Hash Function Algorithm".
  - §3 — byte-ordering convention (right-to-left symbol numbering).
  - §5 — compression function: §5.1 key generation (`A`, `P`, `C2`/`C3`/`C4`),
    §5.2 encryption, §5.3 mixing (`ψ`).
  - §6 — main procedure (block absorption, length/checksum finalization).
- **[RFC 4357](rfc/rfc4357.txt)** — "Additional Cryptographic Algorithms for
  Use with GOST 28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R
  34.11-94 Algorithms".
  - §10.4 — `id-GostR3411-94` = `1.2.643.2.2.9`.
  - §11.2 — `id-GostR3411-94-CryptoProParamSet` = `1.2.643.2.2.30.1` and its
    S-box.
- GOST R 34.11-94 — the Russian national standard itself (Информационная
  технология. Криптографическая защита информации. Функция хэширования);
  RFC 5831 is its English republication.
- **[`../gost28147/DESIGN.md`](../gost28147/DESIGN.md)** — the GOST 28147-89
  block cipher used for the four ECB encryptions in the compression function.
- **[`../streebog/DESIGN.md`](../streebog/DESIGN.md)** — GOST R 34.11-2012
  "Streebog", the successor hash function.

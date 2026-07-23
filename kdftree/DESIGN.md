# KDF_TREE_GOSTR3411_2012_256 (KDFTree2012_256)

For the public API and a usage example see the [package README](README.md).

## What it is

`KDFTree2012_256` is a counter-mode key-derivation function built on HMAC with
the Streebog-256 hash (GOST R 34.11-2012, 256-bit output; see
[`../streebog/DESIGN.md`](../streebog/DESIGN.md)). It takes a derivation key
plus a `label` and a `seed` and expands them into an arbitrary multiple of 32
bytes of keying material. It is the KDF defined in **RFC 7836 §4.4** ("The Key
Derivation Function KDF_TREE_GOSTR3411_2012_256"), also published as Russian
recommendation **R 50.1.113-2016 §4.5**. The single-block variant (RFC 7836
§4.5, `KDF_GOSTR3411_2012_256`) is just this function with `R = 1` and
`L = 256`, i.e. exactly the first (and only) iteration producing 32 bytes.

## Where this module uses it

- **`keg` / key expansion for RFC 9367 ciphers** — `keg.go` calls
  `KDFTree256(tmpkey, "kdf tree", seed, 1, 64)` to split a VKO-derived
  `tmpkey` into a 64-byte `(cipher_key || mac_key)` pair. See
  [`../keg/DESIGN.md`](../keg/DESIGN.md).
- **Repo-root facade** — `gostcrypto.KDFTree2012_256` (in `modes.go`) wraps
  this package's `KDFTree256` directly, pinning `r = 1` and requiring
  `outLen` to be a positive multiple of 32 that fits the 2-byte length
  encoding.
- **`tlstree` key meshing** — [`../tlstree/DESIGN.md`](../tlstree/DESIGN.md)
  chains three calls to the *single-block* variant of this same KDF (`R = 1`,
  `L = 256`), with labels `"level1"`, `"level2"`, `"level3"` and masked TLS
  sequence numbers as seeds, to mesh a per-record key from a master secret.
  It reimplements the single-block HMAC call inline rather than importing this
  package, but the underlying construction — and the reference gost-engine's
  `gost_tlstree()` — is the same tree KDF described here.

## Specification

### HMAC core (RFC 7836 §4.1.1)

`HMAC_GOSTR3411_2012_256` is plain HMAC ([RFC 2104](rfc/rfc2104.txt))
instantiated with:

- Hash `H_256` = GOST R 34.11-2012 with 256-bit output (Streebog-256,
  [RFC 6986](rfc/rfc6986.txt)).
- HMAC output size: **32 bytes**.
- HMAC block size (the `ipad`/`opad` width): **64 bytes**.

`ipad`/`opad` are the standard RFC 2104 constants (`0x36`/`0x5c` repeated).
Go's `crypto/hmac` handles all of this given a `func() hash.Hash` for
Streebog-256.

### KDF_TREE (RFC 7836 §4.4)

Inputs:

| Symbol  | Meaning                                                            |
|---------|---------------------------------------------------------------------|
| `K_in`  | derivation key (HMAC key); any length                             |
| `label` | protocol-assigned byte string, fixed length per use site          |
| `seed`  | protocol-assigned byte string, fixed length per use site          |
| `R`     | width in bytes of the iteration-counter field (1, 2, 3, or 4)     |
| `L`     | required output size **in bits**, `L <= 256 * (2^(8*R) - 1)`      |

Output, normative formula ([RFC 7836](rfc/rfc7836.txt) §4.4):

```
KDF_TREE_GOSTR3411_2012_256(K_in, label, seed, R) = K(1) | K(2) | K(3) | ...

K(i) = HMAC_GOSTR3411_2012_256(K_in, [i]_b | label | 0x00 | seed | [L]_b)
```

where:

- `[i]_b` — byte representation of the iteration counter `i`, **network byte
  order (big-endian)**, exactly `R` bytes wide.
- `0x00` — a single literal zero separator byte between `label` and `seed`.
- `[L]_b` — byte representation of `L` (the bit-length of the *total* desired
  output), **network byte order (big-endian)**, **variable length with no
  leading zero bytes added** (RFC 7836 §4.4: "no leading zero bytes added").
- `|` denotes concatenation.

The number of iterations is `ceil(L / 256)`. Each `K(i)` is a full 32-byte
HMAC block; the concatenation is truncated to `L` bits if `L` is not a
multiple of 256. `KDFTree256` supports arbitrary `outLen > 0` and truncates
accordingly; all in-repo consumers use multiples of 32 bytes.

### Single-block KDF (RFC 7836 §4.5)

```
KDF_GOSTR3411_2012_256(K_in, label, seed)
  = HMAC_GOSTR3411_2012_256(K_in, 0x01 | label | 0x00 | seed | 0x01 | 0x00)
```

This is `KDF_TREE(..., R=1)` with `L = 256`: `[1]_b = 0x01`,
`[256]_b = 0x01 0x00`.

### Parameters used by this repo

The in-module consumers (`keg`, `tlstree`, and the root facade) always call
with:

- `R = 1` (1-byte counter).
- `outLen` a positive multiple of **32 bytes** (32 and 64 in practice; 64 for
  `keg`'s KEG step).
- `L = outLen * 8`. For 64 bytes, `L = 512`, and `[L]_b = 0x02 0x00`.

`KDFTree256` supports the full generality: `R` in 1..4, any positive `outLen`
(panics if it exceeds what the `R`-byte counter can address). Because `R = 1`
in every in-repo call site, the counter field is a single byte
`0x01, 0x02, ...`; with `outLen <= 32*255 = 8160` bytes the 1-byte counter
never overflows.

### Per-iteration HMAC input layout (R = 1)

```
  +------+----------------+------+---------------+----------------+
  | i_b  |     label      | 0x00 |     seed      |     L_b        |
  | 1 B  |  len(label) B  | 1 B  |  len(seed) B  | 1 or 2 B (BE)  |
  +------+----------------+------+---------------+----------------+
   i = 1..ceil(L/256), big-endian
```

`L_b` is the **same value for every iteration** (it encodes the total output
length, not the per-block length). Only `i_b` changes between iterations.

## Implementation notes

1. **The tree KDF is a strict superset of the single-block KDF, and the two
   must not be confused.** A well-known reference Go implementation of the
   GOST suite (gogost) exposes only the RFC 7836 §4.5 single-block form — its
   counter byte is hardcoded to `0x01` and its length suffix to `0x01 0x00`
   (`L = 256`), so it produces exactly 32 bytes once and cannot express a
   multi-iteration derivation. `KDFTree256` implements the general §4.4 loop:
   the counter byte changes per iteration and `[L]_b` reflects the *total*
   requested output length (e.g. `0x02 0x00` for a 64-byte request), not a
   per-block constant. Wiring the single-block form into a call site that
   needs more than 32 bytes yields the wrong answer.

2. **`[L]_b` strips leading zero bytes.** RFC 7836 §4.4 says `[L]_b` carries
   no leading zero bytes; the reference gost-engine enforces this literally,
   and this module (`encodeNoLeadingZeros`) matches it: 64 bytes → `L = 512 =
   0x0200` → two bytes `0x02 0x00`; 32 bytes → `L = 256 = 0x0100` → `0x01
   0x00`; 16 bytes → `L = 128 = 0x80` → a single byte `0x80`. All three
   widths (1 and 2 bytes) are exercised by the test vectors below.

3. **Counter `[i]_b` width is `R`, big-endian, and takes the *low* `R` bytes
   of `i`** (`counterBytes`), matching the reference engine's "last `R` bytes
   of the big-endian counter" convention. For `R = 1` that is simply the
   single least-significant byte. Taking the high `R` bytes instead — or
   zero-padding on the wrong side — is the classic mistake for `R > 1`; the
   counter-width test vectors below guard against it.

4. **Streebog-256's own internal endianness is out of scope here.** The KDF
   input layout above is byte-oriented and endianness-neutral at this layer,
   but the underlying Streebog-256 hash is full of little-endian block
   handling internally, entirely encapsulated inside
   `github.com/tarantool/go-gostcrypto/streebog`. Validate the hash
   independently against its own known-answer tests before debugging the KDF
   — a wrong-endian Streebog will pass nothing here, and the failure looks
   like a KDF bug when it is not.

5. **No destructive-state hazard in this construction.** A fresh `hmac.New`
   is created per iteration and `Sum` is called once on each; there is no
   reused or aliased HMAC state across iterations, no key meshing, and no
   deferred-last-block behavior to get wrong.

6. **Signature differs from gogost's `Derive`.** gogost's single-block
   `Derive(dst, label, seed)` appends to and returns `dst`. `KDFTree256(key,
   label, seed, r, outLen)` returns a freshly allocated slice and takes the
   key as an explicit first argument; do not assume the gogost argument order
   when reading around this code.

## Test vectors

### KAT-1 — reference engine etalon (R = 1, 64-byte output)

This is the parity target used to validate the implementation against the
reference gost-engine. Inputs are all hex.

```
key   (32 B) = 000102030405060708090A0B0C0D0E0F
               101112131415161718191A1B1C1D1E1F
label (4 B)  = 26BDB878
seed  (8 B)  = AF21434145656378
R            = 1
keyOutLen    = 64 bytes   (L = 512 bits -> L_b = 0x02 0x00)
```

Expected output (64 bytes):

```
22B6837845C6BEF65EA71672B2658310
86D3C76AEBE6DAE91CAD51D83F79D16B
074C9330599D7F8D712FCA54392F4DDD
E93751206B3584C8F43F9E6DC51531F9
```

Trace of the two HMAC iterations (both use Streebog-256, key = `key`):

```
iter 1 message = 01 26BDB878 00 AF21434145656378 0200
  -> HMAC = 22B6837845C6BEF65EA71672B265831086D3C76AEBE6DAE91CAD51D83F79D16B
iter 2 message = 02 26BDB878 00 AF21434145656378 0200
  -> HMAC = 074C9330599D7F8D712FCA54392F4DDDE93751206B3584C8F43F9E6DC51531F9
out = iter1 || iter2
```

Note the counter byte (`01` then `02`) is the only difference between the
two messages; `L_b = 0200` is identical in both.

### KAT-2 — single-block (R = 1, 32-byte output) — RFC 7836 Appendix B example 9

Same key/label/seed as KAT-1; `L = 256`, so `[L]_b = 0x01 0x00`. The HMAC
message is:

```
01 26BDB878 00 AF21434145656378 0100
```

Expected output (32 bytes):

```
a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9
```

This is also the single-block `KDF_GOSTR3411_2012_256` (RFC 7836 §4.5), which
equals `KDF_TREE` with `R=1, L=256` — an authoritative RFC vector.

Note: `KDFTree256(key, label, seed, 1, 32)` uses `L_b = 0x0100`, which differs
from `KDFTree256(key, label, seed, 1, 64)`, which uses `L_b = 0x0200`. The two
outputs are entirely different values, not a prefix/truncation of one another
— this pins that `[L]_b` is derived from the *total* requested length, not
recomputed per block.

### Property coverage

Beyond the two fixed vectors, the test suite pins several structural
properties against independent in-test HMAC oracles (built from scratch,
without reusing the package's own `counterBytes`/`encodeNoLeadingZeros`
helpers):

- **Truncation content** — `outLen = 40` (2-byte `L_b`) and `outLen = 16`
  (1-byte `L_b`) both match a byte-for-byte oracle computation.
- **`L`-binding** — `KDFTree256(..., 17)` is *not* a prefix of
  `KDFTree256(..., 64)`, guarding against a bug that omits `[L]_b` or ignores
  it when chaining iterations.
- **Counter width** — `r = 2, 3, 4` are each cross-checked against an oracle
  that builds `[i]_b` independently, catching a low/high-byte mixup.
- **Counter overflow** — `outLen = 8160` (the `r = 1` maximum, `32 * 255`)
  succeeds; `outLen = 8161` panics.
- **Argument validation** — `r = 0`, `r = 5`, `outLen = 0`, and negative
  `outLen` all panic.

## Conformance testing

The in-package tests (`kdftree/kdftree_test.go`) anchor both fixed KATs above
plus the property coverage. In addition, a differential fuzz harness compares
this implementation against an independent reference over random keys,
labels, and seeds at both 32-byte and 64-byte output, to catch any divergence
a fixed vector alone would miss.

```sh
go test ./kdftree/
```

## References

- **[RFC 7836](rfc/rfc7836.txt)** — "Guidelines on the Cryptographic
  Algorithms to Accompany the Usage of Standards GOST R 34.10-2012 and GOST R
  34.11-2012".
  - §4.1.1 — `HMAC_GOSTR3411_2012_256` (HMAC core: 32-byte output, 64-byte
    block).
  - §4.4 — The Key Derivation Function `KDF_TREE_GOSTR3411_2012_256`
    (counter-mode tree; `[i]_b`, `[L]_b` big-endian, `[L]_b` no leading
    zeros).
  - §4.5 — The Key Derivation Function `KDF_GOSTR3411_2012_256` (single
    block, `R = 1`, `L = 256`).
- **R 50.1.113-2016** §4.5 — Russian recommendation, same `KDF_TREE`
  definition.
- **[RFC 6986](rfc/rfc6986.txt)** — GOST R 34.11-2012 (Streebog) hash
  function, needed for the HMAC core. See
  [`../streebog/DESIGN.md`](../streebog/DESIGN.md).
- **[RFC 2104](rfc/rfc2104.txt)** — HMAC construction (`ipad`/`opad`).
- **GOST standards:** GOST R 34.11-2012 (hash), GOST R 34.10-2012
  (companion).

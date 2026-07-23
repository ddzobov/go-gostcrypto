# TLSTree — per-record key derivation (RFC 9189 §8.1)

This document describes the TLSTREE key-diversification function implemented
by `package tlstree`: what it is, its specification, the notable points of
this implementation, and the test vectors that pin it. For the public API and
a usage example see the [package README](README.md).

## What it is

TLSTREE is the per-record key-diversification function used by the GOST TLS
1.2 CTR-OMAC cipher suites (RFC 9189 §8.1). Given a fixed 32-byte root key and
a 64-bit TLS record sequence number `i`, it deterministically derives a
32-byte per-record key by running a three-level tree of
`KDF_GOSTR3411_2012_256` invocations, each level keyed on a progressively
wider-masked slice of `i`. The masks are chosen so the derived key changes
only after a fixed number of records — a "key tree" / key-meshing construction
that bounds how much data is ever protected under one leaf key.

The underlying KDF is `KDF_GOSTR3411_2012_256` (RFC 7836 §4.5), built on
HMAC_GOSTR3411_2012_256 (RFC 7836 §4.1.1), whose hash is GOST R 34.11-2012
(Streebog-256, [RFC 6986](rfc/rfc6986.txt)). TLSTREE itself uses no block
cipher; only the *choice* of mask constants is per-suite (Kuznyechik vs
Magma).

### Where this module uses it

- The sibling `gostls` TLS module's record-layer protector for the CTR-OMAC
  suites owns two trees per direction — `encTree` and `macTree` — so a
  connection has four trees total: {enc, mac} × {read, write}. Each
  Seal/Open calls `tree.Derive(seqNum)` to obtain the fresh CTR key and the
  fresh OMAC key for that record.
- Suites that pull it in: `0xC100`
  `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` and `0xC101`
  `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`. The derived enc-tree key feeds
  the CTR keystream (see [`../ctracpkm/DESIGN.md`](../ctracpkm/DESIGN.md) for
  the CTR half, and [`../kuznyechik/DESIGN.md`](../kuznyechik/DESIGN.md) /
  [`../magma/DESIGN.md`](../magma/DESIGN.md) for the block ciphers each
  suite's tree keys), and the mac-tree key feeds
  [`../omac/DESIGN.md`](../omac/DESIGN.md) (CMAC/OMAC1) at the suite's full
  block width.

## Specification

### Top-level function (RFC 9189 §8.1)

> `TLSTREE(K_root, i) = KDF_3(KDF_2(KDF_1(K_root, STR_8(i & C_1)), STR_8(i & C_2)), STR_8(i & C_3))`

with

> `KDF_1(K, D) = KDF_GOSTR3411_2012_256(K, "level1", D)`
> `KDF_2(K, D) = KDF_GOSTR3411_2012_256(K, "level2", D)`
> `KDF_3(K, D) = KDF_GOSTR3411_2012_256(K, "level3", D)`

So:

```
K1 = KDF_GOSTR3411_2012_256(K_root, "level1", STR_8(i & C_1))
K2 = KDF_GOSTR3411_2012_256(K1,     "level2", STR_8(i & C_2))
K3 = KDF_GOSTR3411_2012_256(K2,     "level3", STR_8(i & C_3))   // the result
```

- `K_root` is **32 bytes**. Every intermediate `K1`, `K2` and the output `K3`
  is **32 bytes** (KDF output is fixed at 256 bits). The constructor enforces
  the 32-byte master-key length and **panics** on any other length — a
  programmer error, not a runtime condition, so there is no truncation or
  zero-padding.
- `i` is the **64-bit TLS record sequence number**.
- `STR_8(x)` serializes a 64-bit integer to **8 bytes, network byte order
  (big-endian)** — see the endianness note below; this is the part most
  likely to trip up a reimplementation. Labels `"level1"`/`"level2"`/`"level3"`
  are the 6 ASCII bytes `0x6C 0x65 0x76 0x65 0x6C 0x31` (…`32`, …`33`).

### Inner KDF (RFC 7836 §4.5)

> `KDF_GOSTR3411_2012_256(K_in, label, seed) = HMAC_GOSTR3411_2012_256(K_in, 0x01 | label | 0x00 | seed | 0x01 | 0x00)`

The HMAC message is the concatenation, in order:

| field         | bytes | value                                   |
|---------------|-------|------------------------------------------|
| counter       | 1     | `0x01`                                   |
| label         | 6     | `"levelN"` (N ∈ {1,2,3})                 |
| separator     | 1     | `0x00`                                   |
| seed          | 8     | `STR_8(i & C_n)` (big-endian)            |
| length suffix | 2     | `0x01 0x00` (= 256, the output bit-length) |

Total HMAC input = 1+6+1+8+1+1 = **18 bytes**. HMAC key = `K_in` (the 32-byte
level input). Output = the full 32-byte HMAC tag (no truncation). The
trailing `0x01 0x00` is the network-byte-order representation of `L = 256`
bits with no leading zero bytes (RFC 7836 §4.4 `[L]_b`); for this primitive it
is always exactly these two bytes, because the requested output is a single
256-bit Streebog block — see the output-length note in
[Implementation notes](#implementation-notes) below.

### Constant sets (RFC 9189 §8.1.1)

The 64-bit masks `C_1, C_2, C_3` select how many low bits of `i` are allowed
to vary inside a leaf window.

**Kuznyechik-CTR-OMAC — 0xC100, `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`:**

| const | hex (big-endian)     | low varying bits | window size    |
|-------|----------------------|-------------------|-----------------|
| C_1   | `0xFFFFFFFF00000000` | 32                | —               |
| C_2   | `0xFFFFFFFFFFF80000` | 19                | —               |
| C_3   | `0xFFFFFFFFFFFFFFC0` | 6                 | **64 records**  |

**Magma-CTR-OMAC — 0xC101, `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`:**

| const | hex (big-endian)     | low varying bits | window size       |
|-------|----------------------|-------------------|--------------------|
| C_1   | `0xFFFFFFC000000000` | 38                | —                  |
| C_2   | `0xFFFFFFFFFE000000` | 25                | —                  |
| C_3   | `0xFFFFFFFFFFFFF000` | 12                | **4096 records**   |

The leaf window (number of consecutive `i` that map to the same final key) is
`~C_3 + 1`: 64 for Kuznyechik (`0x40`), 4096 for Magma (`0x1000`).

## Implementation notes

Points where a naive reading of the RFC is easy to get wrong, or where the
GOST reference implementations in the wild carry surprises.

1. **Endianness of `STR_8(i & C_n)` is big-endian — mask the integer, then
   serialize.** RFC 9189 §8.1 writes `STR_8(i & C_1)`; RFC 7836 §4.4 says
   integer-to-bytes is network byte order (big-endian). The correct sequence
   is: treat `i` as a normal `uint64`, AND it with the big-endian-hex mask
   constant from the table above, then serialize the masked value big-endian
   into 8 seed bytes. GOST is little-endian in many other places (key
   scalars, curve point coordinates), which makes it tempting to reach for a
   little-endian serialization here — that produces the wrong seed bytes.
   Some GOST reference implementations store their mask constants
   little-endian and read the wire sequence bytes host-endian instead; that
   is a self-consistent alternative encoding that happens to produce the same
   masked bytes, but mixing conventions (e.g. a little-endian constant with
   big-endian serialization) silently corrupts every derived key.

2. **A well-known reference-implementation gotcha: an unprimed cache returns
   the all-zero key.** A common way to implement TLSTREE adds a
   cache that short-circuits `Derive` when the new sequence number shares all
   three masked windows with the previously derived one — call it
   `DeriveCached`. If such a cache initializes its "previous sequence number"
   to `0` and its cached key buffer to all-zero bytes, then the very *first*
   call to `DeriveCached(seqNum)` with `seqNum > 0` but still inside the
   initial window (e.g. `seqNum` in `1..63` for Kuznyechik, `1..4095` for
   Magma) spuriously matches that unset "previous" state, the cache "hits",
   and the function returns **32 zero bytes** — without ever having run the
   KDF chain. In real TLS this rarely bites because the first protected
   record (Finished) is always `seq=0`, which never satisfies the `seqNum > 0`
   cache-hit guard. It is nonetheless a foot-gun for any caller that starts
   mid-window or for test code that calls `Derive` out of order. **This
   package sidesteps the whole class of bug: `Derive` has no cache and always
   runs the full three-level KDF chain**, so it returns the correct key on
   the very first call for any `seqNum` — see `TestKAT_FirstCallNotZero` and
   `TestKAT_Kuznyechik_Seq63` in `tlstree_test.go`, which pin exactly this
   case (a fresh tree's first call is `Derive(63)`, not `Derive(0)`).

3. **`Derive` returns a freshly allocated, non-aliasing slice on every call.**
   A cached implementation that hands back a pointer into its own internal
   buffer risks the caller's key being silently overwritten by the next
   `Derive` call. This package copies the final KDF output into a fresh
   32-byte slice each time (`TestDeriveNonAliasing`), so a caller may hold
   onto a derived key across subsequent `Derive` calls on the same tree.

4. **The KDF message framing is exactly 18 bytes: counter, label, separator,
   seed, length suffix.** It's easy to drop the leading `0x01` counter byte
   or the trailing `0x01 0x00` length suffix, or to reach for the wrong hash.
   It is HMAC over **Streebog-256** (GOST R 34.11-2012, 256-bit) — not GOST R
   34.11-94, and not Streebog-512.

5. **Output length is exactly 32 bytes per level — no multi-block
   iteration.** Because the requested output is 256 bits, exactly one
   Streebog block, the KDF runs a **single** HMAC with the counter fixed at
   `0x01`; there is no multi-iteration expansion to implement. Contrast with
   [`../kdftree/DESIGN.md`](../kdftree/DESIGN.md), which iterates the counter
   to produce longer (e.g. 64-byte) outputs — that iterative path is not
   needed here; TLSTREE only ever uses the single-block form of the KDF.

6. **Not affected by the GOST reference-implementation divergences that touch
   other primitives in this module** (S-box row order, GOST R 34.11-94
   empty-input finalization, CryptoPro key meshing in GOST 28147 IMIT).
   TLSTREE uses no block cipher and no GOST R
   34.11-94; it uses only HMAC-Streebog-256, whose input here is never empty
   (always exactly 18 bytes) and which has no S-box or key-meshing surface.

## Test vectors

### RFC 9189 Appendix A.1.1 — official vectors

RFC 9189 Appendix A.1.1 publishes the reference test vectors directly, for
both suites, sharing one 32-byte root key:

```
K_root = 00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
         11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
```

Each suite's table lists seven sequence numbers straddling the level-3,
level-2, and (in the last row) level-1 window boundaries, and pins the
intermediate `K1` ("Divers_1"), `K2` ("Divers_2"), and the final `K3`
("resulting key"). Two representative rows
per suite:

**Kuznyechik-CTR-OMAC** (window = 64):

```
seqnum = 0
  K3 = 19a76ed30f4d6d1f5b7263ec491ad83817c0b57d8a0356127140fb4f7425494d

seqnum = 4294967296     (2^32, crosses the level-1 / C_1 boundary)
  K3 = 16180b24645400b836143837d86aac93952ae3eb8244d5ec2ab02cff30781138
```

**Magma-CTR-OMAC** (window = 4096):

```
seqnum = 0
  K3 = 19a76ed30f4d6d1f5b7263ec491ad83817c0b57d8a0356127140fb4f7425494d   (same as Kuznyechik at seqnum=0 — see below)

seqnum = 274877906944   (2^38, crosses the level-1 / C_1 boundary)
  K3 = 2528c1c6a8f0927bf2be27bb78d27f2146d65593b0c7173a06cb9d88df923265
```

At `seqnum = 0`, both suites' `K1`/`K2`/`K3` are identical: the masks only
matter once `i` has nonzero bits inside them, and `0 & C_n == 0` for every
`C_n` regardless of suite. This is not a bug — the two chains only diverge
once a sequence number crosses one suite's window boundary but not the
other's, which the higher `seqnum` rows above exercise. All seven rows per
suite are pinned in `tlstree_rfc9189_test.go`
(`TestRFC9189_A1_1_Kuznyechik`, `TestRFC9189_A1_1_Magma`), checking `K1` and
`K2` against the white-box `kdf` step and `K3` against the public `Derive`.

### Window-crossing vectors (all-`0xFF` root key)

`tlstree_test.go:TestKAT_MultiSeq` additionally pins six window-crossing
leaves per suite for `K_root = 32×0xFF`, cross-checked against an independent
GOST reference implementation. One value worth calling out because it is
simple enough to reproduce by hand:

```
K_root = FF × 32
Kuznyechik, seqnum = 63:
  K3 = 507642d958c520c6d7eef5ca8a5316d4f34b855d2dd4bcbf4e5bf0ff641a19ff
```

Since `63 < 64` (the Kuznyechik window), `63 & C_1 = 63 & C_2 = 63 & C_3 = 0`,
so all three seeds are 8 zero bytes — yet each level still keys differently
(`K_root` → K1 → K2 → K3) via the distinct `"level1"/"level2"/"level3"`
labels. This is exactly the case the unprimed-cache gotcha in
[Implementation notes](#implementation-notes) above threatens: a naively
cached implementation's first call would return zeros instead of this value;
`TestKAT_Kuznyechik_Seq63` and `TestKAT_FirstCallNotZero` assert the correct
behavior on a fresh tree's very first call.

### Behavioral / windowing assertions (no external KAT needed)

`tlstree_test.go` also asserts:

- output length is always exactly 32 bytes, with no aliasing between
  successive `Derive` calls (`TestDeriveNonAliasing`);
- the same leaf window derives an identical key, and crossing it derives a
  different one, for both suites (`TestWindowing`, window = 64 / 4096);
- determinism (`TestDeterminism`);
- the 32-byte master-key length is enforced by panic
  (`TestMasterKeyLength`).

## Conformance testing

In-package tests (`tlstree_test.go`, `tlstree_rfc9189_test.go`) anchor the
official RFC 9189 Appendix A.1.1 vectors for both suites, the window-crossing
KATs, the windowing/aliasing/determinism properties above, and a fuzz target
(`FuzzTLSTree`) that checks determinism, fixed output length, no panics at
window boundaries, and the intra-window equal-key invariant across random
master keys and sequence numbers.

In addition, a differential fuzz harness compares this implementation against
an independent reference implementation over random root keys, sequence
numbers, and both suites' constant sets — including window-boundary sequence
numbers — to catch any divergence a fixed KAT alone would miss. TLSTREE is
deterministic, so this is a direct differential comparison rather than a
round-trip.

```sh
go test ./tlstree/
```

## References

- **[RFC 9189](rfc/rfc9189.txt)** — "GOST Cipher Suites for Transport Layer
  Security (TLS) Protocol Version 1.2".
  - §8.1 — TLSTREE definition, `KDF_1/2/3` with labels `level1`/`level2`/`level3`.
  - §8.1.1 — `C_1`/`C_2`/`C_3` constants for `0xC100` (Kuznyechik-CTR-OMAC) and
    `0xC101` (Magma-CTR-OMAC).
  - Appendix A.1.1 — official test vectors for both suites (root key, and
    `K1`/`K2`/`K3` for seven sequence numbers each).
- **[RFC 7836](rfc/rfc7836.txt)** — "Guidelines on the Cryptographic
  Algorithms to Accompany the Usage of Standards GOST R 34.10-2012 and GOST R
  34.11-2012".
  - §4.5 — `KDF_GOSTR3411_2012_256` (HMAC over
    `0x01 | label | 0x00 | seed | 0x01 | 0x00`).
  - §4.1.1 — `HMAC_GOSTR3411_2012_256`.
  - §4.4 — network-byte-order integer serialization (`[L]_b`).
- **[RFC 6986](rfc/rfc6986.txt)** — GOST R 34.11-2012 (Streebog), the hash
  underlying the HMAC. See [`../streebog`](../streebog) for the
  implementation.
- **GOST R 34.12-2015** — Kuznyechik / Magma block ciphers; only relevant here
  for which constant set applies (TLSTREE itself uses no block cipher). See
  [`../kuznyechik/DESIGN.md`](../kuznyechik/DESIGN.md) and
  [`../magma/DESIGN.md`](../magma/DESIGN.md).

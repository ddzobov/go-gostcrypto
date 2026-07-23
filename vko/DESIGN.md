# VKO Diffie-Hellman Key Agreement — GOST R 34.10-2001 & 2012

This document describes the VKO key-agreement function implemented by
`package vko`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

VKO (ВКО, *выработка ключа общего* — "shared key derivation") is the
Diffie-Hellman-style key-agreement function for GOST elliptic-curve keys. One
party combines its own private key, the other party's public key, and a small
"user keying material" (UKM) integer into a single elliptic-curve point, then
hashes that point's coordinates to produce a Key Encryption Key (KEK). It is
symmetric: `KEK(d_A, Q_B, UKM) == KEK(d_B, Q_A, UKM)`.

Three variants exist, differing only in the final hash:

| Variant      | Curve size | Hash                            | KEK length | Spec          |
|--------------|------------|----------------------------------|------------|---------------|
| `KEK2001`    | 256-bit    | GOST R 34.11-94 (CryptoPro)      | 32 bytes   | RFC 4357 §5.2 |
| `KEK2012256` | 256/512    | Streebog-256 (GOST R 34.11-2012) | 32 bytes   | RFC 7836 §4.3 |
| `KEK2012512` | 512        | Streebog-512 (GOST R 34.11-2012) | 64 bytes   | RFC 7836 §4.3 |

The curve math and signature scheme are GOST R 34.10-2012 (and the legacy
GOST R 34.10-2001); the agreement function itself is specified in RFC 4357
§5.2 (2001) and RFC 7836 §4.3 (2012). The 2012 hash is GOST R 34.11-2012 /
Streebog ([RFC 6986](rfc/rfc6986.txt), see [../streebog/DESIGN.md](../streebog/DESIGN.md));
the 2001 hash is GOST R 34.11-94 with the CryptoPro S-box
([RFC 5831](rfc/rfc5831.txt), see [../gostr341194/DESIGN.md](../gostr341194/DESIGN.md)).
The curve parameter sets and point arithmetic come from
[../gost3410curves/DESIGN.md](../gost3410curves/DESIGN.md); this package
adds only the agreement scalar, the point serialization, and the final hash.

## Where this module uses it

- **`keg` package** — `KEG2012_256` (the RFC 9367 / R 1323565.1.020-2018
  §6.4.5.1 key-export step) calls `KEK2012256` as its inner VKO step, on a
  16-byte UKM built by reversing `ukm_source[0:16]` (an all-zero source maps
  to `00…00 01`). See [../keg/DESIGN.md](../keg/DESIGN.md).
- **The module root** (`github.com/tarantool/go-gostcrypto`) re-exports this
  package as its public GOST key-agreement API: `VKO2001` / `VKO2001OnCurve` /
  `VKO2001TestCurve` wrap `KEK2001` (defaulting to the
  `id-GostR3410-2001-CryptoPro-A-ParamSet` curve), and `VKO2012_256` /
  `VKO2012_256OnCurve` / `VKO2012_512` wrap `KEK2012256` / `KEK2012512`
  (defaulting to `id-tc26-gost-3410-12-512-paramSetA`).
- **The sibling `gostls` TLS module** drives VKO for its GOST cipher-suite key
  exchange: the legacy suite `0x0081` (GOST2001-GOST89-GOST89) and RFC 9189's
  `0xFF85`-class suites (GOST2012-GOST8912-GOST8912) call the 2001 / 2012-256
  KEK directly, while the RFC 9367 suites `0xC100`/`0xC101` reach it through
  `keg`'s `KEG2012_256` step. Across the pre-2018 suites the UKM is the first
  8 bytes of the TLS `client_random` — a convention carried over from the
  pre-RFC-9189 draft-chudov-cryptopro-cptls suites, distinct from RFC 9189
  §8.3's own UKM derivation (`Streebog(client_random‖server_random)`,
  truncated to 8 or 16 bytes depending on the record-protection mode).

## Specification

### Common structure

Given a local private scalar `d` (an integer mod the subgroup order `q`), a
peer public point `Q = (Q_x, Q_y)`, the curve cofactor `h`, and a UKM integer:

1. Compute the agreement scalar `s = (h · UKM · d) mod q`.
2. Compute the agreement point `K = s · Q` (elliptic-curve scalar
   multiplication). `K = (K_x, K_y)`.
3. Serialize the point as `LE(K_x) || LE(K_y)` — each coordinate
   little-endian, fixed width = curve point size (32 or 64 bytes,
   `Curve.PointSize()`).
4. `KEK = Hash(LE(K_x) || LE(K_y))`.

The hash choice and output length are the only differences between the three
variants (see table above).

### RFC 4357 §5.2 (VKO GOST R 34.10-2001), verbatim

> This algorithm creates a key encryption key (KEK) using 64 bit UKM, the
> sender's private key, and the recipient's public key (or the reverse of the
> latter pair).
>
> 1) Let K(x,y,UKM) = ((UKM\*x)(mod q)) . (y.P) (512 bit), where
>    x - sender's private key (256 bit)
>    x.P - sender's public key (512 bit)
>    y - recipient's private key (256 bit)
>    y.P - recipient's public key (512 bit)
>    UKM - non-zero integer, produced as in step 2 p. 6.1 [GOSTR341001]
>    P - base point on the elliptic curve (two 256-bit coordinates)
>    UKM\*x - x multiplied by UKM as integers
>    x.P - a multiple point
> 2) Calculate a 256-bit hash of K(x,y,UKM):
>    KEK(x,y,UKM) = gostR3411 (K(x,y,UKM))
>
> This algorithm MUST NOT be used when x.P = P, y.P = P

RFC 4357's formula omits the cofactor `h` because every 2001 CryptoPro curve
has cofactor 1, so `h` vanishes. The 2012 formula below makes it explicit.

### RFC 7836 §4.3 (VKO GOST R 34.10-2012), verbatim

> KEK_VKO (x, y, UKM) = H_256 (K (x, y, UKM))
> KEK_VKO (x, y, UKM) = H_512 (K (x, y, UKM))
>
> K (x, y, UKM) = (m/q\*UKM\*x mod q)\*(y\*P)

where `m` is the elliptic-curve group order and `q` the cyclic subgroup order,
so `m/q` is the cofactor `h`. `H_256` is Streebog-256, `H_512` is Streebog-512.
The UKM's default value is 1, with a usable range of `1 … 2^(n/2)-1`.

### RFC 7836 §3 — coordinate serialization (verbatim)

> When a point on an elliptic curve is given to an input of a hash function,
> affine coordinates for short Weierstrass form are used: an x coordinate
> value is fed first, a y coordinate value is fed second, both in
> little-endian format.

### Sizes and constants

- Private key scalar `d`: `Curve.PointSize()` bytes (32 for a 256-bit curve,
  64 for a 512-bit one), supplied little-endian on the wire.
- Public key point `Q`: `2 × PointSize()` bytes, decoded as `LE(Q_x) ||
  LE(Q_y)`.
- UKM: any length on the wire, interpreted as a little-endian integer. TLS
  uses 8 bytes (pre-2018 suites) or a reversed 16-byte value (2018/KEG path).
- KEK output: 32 bytes (`KEK2001`, `KEK2012256`) or 64 bytes (`KEK2012512`).
- `PointSize()` is 64 if the curve's field prime exceeds 256 bits, else 32 —
  so the 256-bit 2012 paramsets (`paramSetA`–`D`) use 32-byte coordinates,
  even though this package's own `VKO2012_256`/`VKO2012_512` default to the
  512-bit `paramSetA` curve.

### `KEK2001` hash detail

`KEK2001` hashes with `gostr341194.New()` — GOST R 34.11-94 with the
CryptoPro parameter set (the only S-box this package's `gostr341194` sibling
implements). This is a distinct S-box from the GOST 28147-89 cipher S-boxes
used elsewhere in the module.

## Implementation notes

1. **UKM is little-endian.** The wire UKM bytes are reversed, then
   interpreted as an integer — i.e. the wire representation is a
   little-endian integer. Concrete: wire UKM `1d80603c8544c727` decodes to
   `0x27c744853c60801d` (pinned by an in-package test). RFC 7836 §4.3 calls
   UKM an integer without spelling out endianness; little-endian is the
   de-facto convention this package follows.

2. **Cofactor handling and UKM reduction.** The agreement point is computed
   as `K1 = d·Q` (the private-scalar multiply), then `u = (UKM·cofactor) mod
   (cofactor·q)`; if `u == 1` the agreement point is `K1` itself, otherwise
   `K = u·K1`. Reducing `u` modulo the full group order `cofactor·q` — rather
   than leaving the wire UKM's magnitude unbounded — bounds the second scalar
   multiply's cost regardless of how large the UKM is, without changing the
   result: every point's order divides `cofactor·q`, so `(u mod
   cofactor·q)·K1 == u·K1` exactly, including the torsion component on the
   cofactor-4 curves. Both cofactor-1 curves (all CryptoPro and TC26 512-bit
   A/B curves) and cofactor-4 curves (`tc26-256-A`, `tc26-512-C`) are handled
   by reading the curve's own `Cofactor` field; any other cofactor value is
   rejected outright rather than silently producing a wrong KEK. The UKM
   input is never mutated.

3. **Public-key decode is `LE(X) || LE(Y)`.** The `2*PointSize()` buffer
   splits into two little-endian halves: `X` from the first half, `Y` from
   the second. Getting the X/Y order or the endianness wrong here is the
   single most common VKO bug — two parties who both get it wrong the same
   way will still agree with each other, but the KEK won't match a correct
   implementation or a real TLS peer.

4. **The agreement point is serialized `LE(K_x) || LE(K_y)` before hashing**,
   each `PointSize()` bytes wide — matching RFC 7836 §3 (x first, y second,
   both little-endian) exactly.

5. **The private key is reduced mod `q`, and zero is rejected both before and
   after reduction** — catching both an all-zero wire scalar and a scalar
   that happens to equal exactly the subgroup order.

6. **Degenerate results are rejected explicitly, not silently propagated.** A
   zero or empty UKM, a `UKM·cofactor` product that reduces to zero, an
   agreement point at infinity, and a public point that fails the curve
   equation each return a distinct, named error rather than continuing to
   produce a meaningless KEK.

7. **A caller-supplied curve's cofactor is validated.** Every registered GOST
   curve has cofactor 1 or 4; a `*gost3410curves.Curve` with any other
   cofactor is rejected before any scalar multiplication runs, so a malformed
   or unsupported curve produces an error instead of a silently wrong KEK.

8. **The secret-scalar multiply is only as constant-time as the curve asks
   for.** The private-key multiply `d·Q` goes through
   `Curve.ScalarMultSecret`, which uses the constant-time backend only if the
   caller has set `curve.ConstantTime = true` on that curve instance; the
   curves this package's own convenience constructors (`Curve2001Test`,
   `Curve2012ParamSetA`) return do not set it. See
   [../gost3410curves/SECURITY.md](../gost3410curves/SECURITY.md) before
   relying on side-channel resistance for a caller-held private key.

## Test vectors

### Inline KAT #1 — VKO GOST R 34.10-2001 (test paramset, cofactor 1)

Curve: `id-GostR3410-2001-TestParamSet` (RFC 4357 §11.4). Hash: GOST R
34.11-94 CryptoPro. Curve parameters (big-endian hex, short Weierstrass
`y² = x³ + a·x + b mod p`, subgroup order `q`, base point `(x, y)`, cofactor
1):

```
p = 8000000000000000000000000000000000000000000000000000000000000431
a = 0000000000000000000000000000000000000000000000000000000000000007
b = 5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
q = 8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
x = 0000000000000000000000000000000000000000000000000000000000000002
y = 08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8
co = 1
```

Self-agreement vector (both private keys known, so both symmetry and the
absolute KEK are verified):

```
curve  = id-GostR3410-2001-TestParamSet
ukm    = 5172be25f852a233                         (8 bytes, little-endian int)
d_1    = 1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928  (LE)
d_2    = 5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473  (LE)
Q_1    = d_1 · P
Q_2    = d_2 · P
KEK    = KEK2001(d_1, Q_2, ukm) = KEK2001(d_2, Q_1, ukm)
       = ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6
```

### Inline KAT #2 — VKO GOST R 34.10-2012, 256/512-bit KEK

Curve: `id-tc26-gost-3410-12-512-paramSetA` (cofactor 1, 64-byte
coordinates). Hash: Streebog-256 / Streebog-512. Both public keys are given
so the vector runs without deriving anything first:

```
curve  = id-tc26-gost-3410-12-512-paramSetA
ukm    = 1d80603c8544c727                         (8 bytes, little-endian int)
d_A    = c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8
         c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667   (64-byte LE)
Q_A    = aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5
         d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7
         914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38
         461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a   (128-byte LE X||Y)
d_B    = 48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b
         8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db
Q_B    = 192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e
         fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651
         04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b
         b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79

KEK256 = KEK2012256(d_A, Q_B, ukm) = KEK2012256(d_B, Q_A, ukm)
       = c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221

KEK512 = KEK2012512(d_A, Q_B, ukm)   (same inputs, Streebog-512)
       = 79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa
         7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf
```

### Cofactor-4 vector — `tc26-256-A`

Closes the gap the two KATs above leave (both use cofactor-1 curves): a
vector on `id-tc26-gost-3410-12-256-paramSetA` (OID `1.2.643.7.1.2.1.1.1`,
cofactor 4).

```
curve  = id-tc26-gost-3410-12-256-paramSetA
priv   = 0x11 × 32                                (LE)
peerQ  = 5bdf2b87cb48d375feaed65e3c840548d0c3c497f1dbbba163a6a25077a927b8
         5b99b9f94433e8fe42aaf7190f5ae254695f65b52e111a129f1a65e3a62976ce
ukm    = 01 00 00 00 00 00 00 00
KEK256 = 0fb3a1f57deab23f4ac566ae07707169f1f5ec7fea2477625b58b259cf529453
```

### gost-engine-derived fixture set

A published gost-engine key-derivation test suite (its `'derive'` subtest)
provides a much larger fixture set: thirteen rows covering every registered
GOST curve — the five 2001 CryptoPro/Xch curves, the four 2012 256-bit
paramsets, the three 2012 512-bit paramsets, plus two range-boundary variants
where one side's private scalar sits at the very edge of the valid range.
Each row carries two static private keys (Alice, Bob) and three expected
SHA-256 values: a hash of each side's derived public key re-encoded as a DER
SubjectPublicKeyInfo, and a hash of the shared KEK itself (both directions).
The two cofactor-4 rows additionally carry a public key deliberately placed
in the curve's small subgroup ("Malice's key"), which the agreement must
reject rather than accept.

## Conformance testing

The in-package tests anchor all of the vectors above and exercise every
error path:

- `vko_test.go` pins inline KAT #1 and KAT #2 in both directions, and ports
  the full gost-engine fixture set described above (public-key SPKI hash,
  shared-KEK hash, small-subgroup rejection).
- `cofactor4_test.go` pins the `tc26-256-A` cofactor-4 vector.
- `vko_negative_test.go` covers the negative paths — malformed private/public
  key lengths, an all-zero or exactly-`q` private scalar, a zero UKM, an
  off-curve public point — and a property test verifying that an
  oversized UKM (larger than the curve's full group order) is reduced
  correctly and still yields the same KEK, on both a 256-bit and a 512-bit
  cofactor-4 curve.
- Further tests in `vko_test.go` guard the caller-supplied-cofactor
  validation (rejecting cofactors other than 1 and 4) and re-check a subset
  of the gost-engine fixtures byte-for-byte as a regression backstop for that
  validation.

```sh
go test ./vko/
```

## References

- **RFC 4357** — "Additional Cryptographic Algorithms for Use with GOST
  28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94
  Algorithms".
  - §5.2 — VKO GOST R 34.10-2001 key agreement.
  - §11.4 — the fixed test parameter set used by KAT #1.
- **RFC 7836** — "Guidelines on the Cryptographic Algorithms to Accompany the
  Usage of Standards GOST R 34.10-2012 and GOST R 34.11-2012".
  - §3 — coordinate serialization for hashing (x first, y second, both
    little-endian).
  - §4.3 — VKO_GOSTR3410_2012_256/512 key agreement.
- **[RFC 6986](rfc/rfc6986.txt)** — GOST R 34.11-2012 (Streebog), the 2012 KEK
  hash. See [../streebog/DESIGN.md](../streebog/DESIGN.md).
- **[RFC 5831](rfc/rfc5831.txt)** — GOST R 34.11-94, the 2001 KEK hash. See
  [../gostr341194/DESIGN.md](../gostr341194/DESIGN.md).
- **[RFC 9189](rfc/rfc9189.txt)** — GOST cipher suites for TLS 1.2. Its own
  UKM derivation (`Streebog(client_random‖server_random)`, §8.3) differs from
  the raw `client_random[0:8]` rule the pre-RFC-9189 legacy suites use.
- **GOST R 34.10-2012 / GOST R 34.10-2001** — the signature/curve standards
  this agreement function is defined against; see
  [../gost3410curves/DESIGN.md](../gost3410curves/DESIGN.md) for the curve
  parameter sets and point arithmetic.
- **GOST R 34.11-2012**, **GOST R 34.11-94** — the hash standards used for
  the KEK finalization.
- gost-engine — the CryptoPro OpenSSL engine, the ground truth for the
  larger fixture set in Test vectors above.

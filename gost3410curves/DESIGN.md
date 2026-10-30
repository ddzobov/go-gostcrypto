# GOST R 34.10 curve parameter sets and point arithmetic

For the public API and a usage example see the [package README](README.md).

## What it is

A **GOST R 34.10 curve parameter set** is the fixed tuple `(p, a, b, q, x, y)`,
plus a cofactor, that defines one named elliptic curve over a prime field
`GF(p)`. GOST R 34.10-2001 and GOST R 34.10-2012 do **not** define a single
curve; instead an X.509 certificate, a key, or a TLS handshake names a
parameter set by **OID**, and every signing / verifying / VKO / KEG operation
must first resolve that OID to the concrete constants. This package owns
exactly that: the twelve registered parameter-set tables, OID→curve resolution,
and the short-Weierstrass affine point arithmetic (`Add`, `Double`,
`ScalarMult`) that operations elsewhere in this module build on.

Standards identity:

- **GOST R 34.10-2001** — superseded signature standard; its 256-bit curves
  (`1.2.643.2.2.35.x`) are still current in some legacy suites.
- **GOST R 34.10-2012** — current standard ([RFC 7091](rfc/rfc7091.txt)
  describes the algorithm).
- Curve constants are specified by [RFC 4357](rfc/rfc4357.txt) §11 (CryptoPro
  2001 sets) and [RFC 7836](rfc/rfc7836.txt) §5 / Appendix A (TC26 2012 sets).
  [draft-deremin-rfc4491-bis](rfc/draft-deremin-rfc4491-bis.txt) collects the
  full OID list and the 2012↔2001 aliasing.

## Where this module uses it

- **`gost3410sign`** — signing multiplies the base point by the per-signature
  nonce `k` and the private key `d` (both secret, routed through
  `ScalarMultSecret`); verification multiplies two *public* scalars by the
  base point and the public key (`ScalarMult`).
- **`vko`** — VKO 2001/2012 shared-secret derivation: `K1 = d·Q` (secret `d`,
  via `ScalarMultSecret`), then `K = u·K1` for a UKM-derived public scalar `u`
  (via `ScalarMult`). Reads `Curve.Cofactor` to compute the full group order
  `cofactor·q` for the UKM reduction.
- **`keg`** — RFC 9367 KEG key exchange, hardcoded to the tc26-256-A curve
  (`CurveByOID("1.2.643.7.1.2.1.1.1")`).
- **`x509gost`** — resolves the issuer certificate's curve via `CurveByOID`
  before verifying a signature on it.

## Specification

### Curve equation forms

Two equation forms appear in the standards ([RFC 7836](rfc/rfc7836.txt) §5.1 /
§5.2):

- **Short Weierstrass** (canonical, all 2001 sets and most 2012 sets):
  `y² = x³ + a·x + b (mod p)`
- **Twisted Edwards** (§5.2; only `tc26-256-A`, `tc26-512-C`):
  `e·u² + v² = 1 + d·u²·v² (mod p)`

  A twisted-Edwards set still has birationally-equivalent Weierstrass
  `(a,b,x,y)` coordinates — those are what signing/VKO actually uses. This
  package stores **only** the Weierstrass form; the `(e,d)` pair and the
  Edwards basepoint are omitted entirely, since nothing in this module's
  sign/verify/VKO path touches them (see Implementation notes).

### Parameters and their sizes

| Field | Meaning | 256-bit size | 512-bit size |
|---|---|---|---|
| `p` | field characteristic (prime) | 32 B | 64 B |
| `a` | Weierstrass coefficient | ≤ 32 B | ≤ 64 B |
| `b` | Weierstrass coefficient | ≤ 32 B | ≤ 64 B |
| `q` | order of the basepoint cyclic subgroup (prime) | 32 B | 64 B |
| `x`,`y` | basepoint affine coordinates | ≤ 32 B | ≤ 64 B |
| `Cofactor` | `#E(GF(p)) = Cofactor·q` | 1 or 4 | 1 or 4 |

`PointSize()` is derived purely from `P.BitLen()`: **32 if `P.BitLen() ≤
256`, else 64**. It is not read from a table. All public keys, private keys,
and signature halves elsewhere in this module are `PointSize()` bytes each.

### On-curve validity

Unlike a validating constructor, `Curve` values here are plain struct
literals — there is no `NewCurve` that rejects a bad table at construction
time. Instead, every registered table's on-curve property (`y² ≡ x³+ax+b (mod
p)`) and base-point order (`q·G == ∞`) are pinned by the test suite (see Test
vectors below) for all ten sets. A hand-edited table that is wrong by one byte
fails those tests immediately, not silently at first use.

### OID → parameter-set table

This is exactly what `CurveByOID` resolves. All hex below is **big-endian**
(the natural integer notation); the curve constants are never byte-reversed —
only key/signature *wire* serialization elsewhere in this module is
little-endian (see Implementation notes).

#### CryptoPro 2001, 256-bit ([RFC 4357](rfc/rfc4357.txt) §11.2; aliased to tc26 2012 256-bit sets)

The 2001 CryptoPro sets are **identical curves** to three of the tc26 2012
256-bit sets:

| OID | Name | identical to |
|---|---|---|
| `1.2.643.2.2.35.1` | CryptoPro-A | tc26-256-**B** |
| `1.2.643.2.2.35.2` | CryptoPro-B | tc26-256-**C** |
| `1.2.643.2.2.35.3` | CryptoPro-C | tc26-256-**D** |

**CryptoPro-A** (= tc26-256-B), `Cofactor = 1`, Weierstrass:
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
a = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94
b = 00000000000000000000000000000000000000000000000000000000000000A6
q = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
x = 0000000000000000000000000000000000000000000000000000000000000001
y = 8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14
```

**CryptoPro-B** (= tc26-256-C), `Cofactor = 1`, Weierstrass:
```
p = 8000000000000000000000000000000000000000000000000000000000000C99
a = 8000000000000000000000000000000000000000000000000000000000000C96
b = 3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B
q = 800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F
x = 0000000000000000000000000000000000000000000000000000000000000001
y = 3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC
```

**CryptoPro-C** (= tc26-256-D), `Cofactor = 1`, Weierstrass. `q` is the full
group order (same bit-length as `p`); cofactor 4 is mathematically impossible
here, since `4·q` would exceed the Hasse bound `p + 1 ± 2√p` (see
Implementation notes):
```
p = 9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B
a = 9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598
b = 000000000000000000000000000000000000000000000000000000000000805A
q = 9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9
x = 0000000000000000000000000000000000000000000000000000000000000000
y = 41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67
```

**CryptoPro 2001, 256-bit key-exchange (Xch) sets** — the 2001 key-exchange
parameter sets are **identical curves** to two of the signing sets above
([RFC 4357](rfc/rfc4357.txt) §11.4; the same GC256B/GC256D identity appears in
RFC 9189, Table 9). `CurveByOID` builds them from the CryptoPro-A/C
constructors and only overwrites `Name`:

| OID | Name | identical to |
|---|---|---|
| `1.2.643.2.2.36.0` | CryptoPro-XchA | CryptoPro-**A** |
| `1.2.643.2.2.36.1` | CryptoPro-XchB | CryptoPro-**C** |

Both have `Cofactor = 1` and reuse the `p, a, b, q, x, y` of their
CryptoPro-A / CryptoPro-C counterparts shown above.

#### TC26 2012, 256-bit ([RFC 7836](rfc/rfc7836.txt) §5.2 / draft-deremin)

| OID | Name | form | Cofactor |
|---|---|---|---|
| `1.2.643.7.1.2.1.1.1` | tc26-256-A | twisted Edwards | 4 |
| `1.2.643.7.1.2.1.1.2` | tc26-256-B | Weierstrass | 1 |
| `1.2.643.7.1.2.1.1.3` | tc26-256-C | Weierstrass | 1 |
| `1.2.643.7.1.2.1.1.4` | tc26-256-D | Weierstrass | 1 |

**tc26-256-A** (`Cofactor = 4`, twisted Edwards; Weierstrass coordinates used
for crypto — `q` is the prime subgroup order, the full curve order is `4·q`):
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
a = C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335
b = 295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513
q = 400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67
x = 91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28
y = 32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C
```
(tc26-256-B/C/D are the CryptoPro-A/B/C tables above — same integers, a
different `Name`.)

#### TC26 2012, 512-bit ([RFC 7836](rfc/rfc7836.txt) §5.1 / Appendix A.1)

| OID | Name | form | Cofactor |
|---|---|---|---|
| `1.2.643.7.1.2.1.2.1` | tc26-512-A | Weierstrass | 1 |
| `1.2.643.7.1.2.1.2.2` | tc26-512-B | Weierstrass | 1 |
| `1.2.643.7.1.2.1.2.3` | tc26-512-C | twisted Edwards | 4 |

**tc26-512-A** (`Cofactor = 1`, Weierstrass):
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
a = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4
b = E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265
    EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760
q = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
x = 3
y = 7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921
    DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4
```

**tc26-512-B** (`Cofactor = 1`, Weierstrass):
```
p = 8000000000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000006F
a = 8000000000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000006C
b = 687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F
    3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116
q = 8000000000000000000000000000000000000000000000000000000000000001
    49A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD
x = 2
y = 1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335
    DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD
```

**tc26-512-C** (`Cofactor = 4`, twisted Edwards, Weierstrass coordinates used
for crypto; `q` is the prime subgroup order, the full curve order `4·q`):
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
a = DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645
    46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3
b = B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE0
    38CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1
q = 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    C98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED
x = E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043A
    A27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148
y = F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9B
    E18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F
```
(Whitespace inside the 64-byte hex above is purely for line-wrapping;
concatenate to 128 hex chars = 64 bytes.)

Also standardized but **not registered in `CurveByOID`**: a 2001 test
parameter set (`1.2.643.2.2.35.0`) and a 512-bit test parameter set, both used
only for out-of-band vector round-trips by consuming packages, not resolved
by OID here.

## Implementation notes

Points where a naive reading diverges from a literal transcription of the
standard.

1. **Endianness: constants are big-endian, the wire is little-endian.** Every
   value in the tables above is a big-endian integer, and this package never
   reverses them. The raw private key, raw public key, and signature bytes
   that cross a wire boundary are little-endian — but that (de)serialization
   is a concern of the packages that consume a `*Curve` (`vko`,
   `gost3410sign`), not of this package. Do not byte-swap `p,a,b,q,x,y`.

2. **`PointSize` is computed from `p`, not stored.** `PointSize()` returns 64
   iff `P.BitLen() > 256`, else 32. A resolver that keys point size off the
   OID family instead would mis-size any future parameter set; always derive
   it from `P.BitLen()`.

3. **Twisted-Edwards sets are stored purely as Weierstrass.** RFC 7836 §5.2
   gives `tc26-256-A` and `tc26-512-C` in twisted-Edwards form with
   `(e,d,u,v)`. This package keeps only the birationally-equivalent
   Weierstrass `(a,b,x,y)`, because `Add`/`Double`/`ScalarMult` are pure
   Weierstrass and nothing in this module's sign/verify/VKO path needs the
   Edwards coordinate maps. A `Curve` value here has no `E`/`D` fields at all.

4. **The 2001↔2012 256-bit aliasing is real, not coincidental.**
   `CryptoPro-A/B/C` (`1.2.643.2.2.35.{1,2,3}`) and `tc26-256-{B,C,D}`
   (`1.2.643.7.1.2.1.1.{2,3,4}`) are the **same six integers**. `CurveByOID`
   builds the tc26-256-B/C/D cases from the CryptoPro-A/B/C constructors and
   only overwrites `Name`. The same pattern covers the 2001 key-exchange
   sets: `CryptoPro-XchA` (`1.2.643.2.2.36.0`) is identical to CryptoPro-A and
   `CryptoPro-XchB` (`1.2.643.2.2.36.1`) to CryptoPro-C (RFC 4357 §11.4), and
   is likewise built from the shared constructors with only `Name`
   overwritten. A caller must still be able to resolve *all* OID arcs —
   certificates and TLS handshakes use whichever the issuer chose.

5. **Cofactor is explicit per set, not defaulted.** Each of the twelve
   registered OID arcs sets `Cofactor` directly (no "defaults to 1 if unset"
   logic; the Xch aliases inherit `Cofactor = 1` from the CryptoPro-A/C
   constructors they are built from).
   `CryptoPro-C`/`tc26-256-D` is `1` — its stored `q` is the full group order
   (`#E = q`), so a cofactor of `4` is mathematically impossible (`4·q` would
   exceed the Hasse bound `p + 1 ± 2√p`). `tc26-256-A` and `tc26-512-C` are
   `4` (twisted-Edwards derived); their stored `q` is the *prime subgroup*
   order, and the full curve order is `4·q`. A hand-transcribed table that
   flips one of these is caught by `TestCofactorField`.

6. **Field-name discipline when cross-checking against another source.**
   When comparing these constants against any other GOST curve table, always
   match fields by **label** (`p`, `a`, `b`, `q`, `x`, `y`), never by
   positional order — different sources lay the same seven fields out in
   different column orders, and porting by position silently swaps values.

7. **`Add`/`Double`/`ScalarMult` do not validate their input.** All three
   assume the point argument is either the identity or a reduced, on-curve
   point; passing an unreduced or off-curve point produces a garbage result
   without an error (an invalid-curve-attack shape for `ScalarMult` on
   untrusted input). Callers accepting untrusted points must gate with
   `IsOnCurve` first. `IsOnCurve` itself does check reduction (`0 ≤ X,Y <
   P`) as well as the curve equation.

8. **`ScalarMult` is not constant-time.** It is a `math/big` left-to-right
   double-and-add: correct, and fine for public scalars (verification), but
   both its branch pattern and its `math/big` arithmetic are secret-dependent
   when fed a signing nonce or a private key. `ScalarMultSecret` and the
   experimental `ScalarMultCT` exist for that case — see
   [SECURITY.md](SECURITY.md) and [EXPERIMENT-ct.md](EXPERIMENT-ct.md).

## Test vectors

### On-curve and order checks (all twelve registered sets)

The cheapest and strongest correctness gate: for every OID, `IsOnCurve(Base())`
must hold, and `ScalarMult(Q, Base())` must be the identity while
`ScalarMult(Q-1, Base())` must not be — ruling out both a wrong base point and
a subtly wrong `Q` that happens to clear early. A single mistranscribed byte
in any of `(p,a,b,q,x,y)` fails one of these immediately.

### Independent scalar-multiplication KAT

Pinned against points computed offline, independently of this package, from
the same public curve constants — catching an arithmetic bug that happens to
preserve on-curve-ness or the subgroup order (which the property tests above
would miss):

```
scalar k = 0badc0ffee0ddf00ddeadbeefcafef00d0123456789abcdeffedcba9876543210

tc26-256-A (OID 1.2.643.7.1.2.1.1.1):
  Double(G) = (e8c6740e58d616ca220db7da0d9c3e19b53e86e38bf3e8747774631452ec174c,
               0b837a5e560a29a2327b575f29b4be8baef4bc947fcc2ed4f3264bc434309381)
  k·G       = (d9328e9d40b6cfeb8cc4ff3330c354b7c44a28e5f3170f9aa70c5d1dc2f531e4,
               a1dad70383ecbd6a23430437c7631785855cb2c0c34673efb5d4da82b6ce6b16)

tc26-512-A (OID 1.2.643.7.1.2.1.2.1):
  Double(G) = (3b89dcfc622996ab97a5869dbff15cf51db00954f43a58a5e5f6b0470a132b2f
               4434bbcd405d2a9516151d2a6a04f2e4375bf48de1fdb21fb982afd9d2ea137c,
               c813c4e2e2e0a8a391774c7903da7a6f14686e98e183e670ee6fb784809a3e92
               ca209dc631d85b1c7534ed3b37fddf64d854d7e01f91f18bb3fd307591afc051)
  k·G       = (0412747e4a266b941e28391723a1d46fd2cdf25db6f120880aaed33ac5382863
               3a5822df6923cc7eef2a00c79c1d2c88834fbbbfaaec9f40db234b83051a069b,
               c7bbde34937139d855e0b2f01c700b4ab48e393f6258c4f754447a83e9b24c4f
               2740f3a2cc2965b831ba94aaae9a745ef37ea41131789f1edae6cab83d3ff34a)
```

### Group-law and edge-case pins

- Commutativity (`Add(G,2G) == Add(2G,G)`) and `ScalarMult(3,G) ==
  Add(Add(G,G),G)`.
- `Add(G, -G) == identity`, where `-G = (G.X, P - G.Y)`.
- Identity absorption: `Add(∞,G)==G`, `Add(G,∞)==G`, `Double(∞)==∞`,
  `ScalarMult(nil|0|-1, G)==∞`, `ScalarMult(1,G)==G`, `ScalarMult(Q,G)==∞`,
  `ScalarMult(k,∞)==∞`.
- `Add` returns a fresh clone, not a reference into its arguments — mutating
  the result must not perturb the input points.
- `IsOnCurve` rejection paths: off-curve `Y`, unreduced coordinates
  (`X+P, Y+P`), and negative coordinates must all report `false`; the
  identity must report `true`.
- Cofactor per OID (§ table above) and the 2001↔2012 aliasing (identical
  `p,a,b,q,x,y` across the three aliased OID pairs).

## Conformance testing

The in-package tests (`gost3410curves/curves_test.go`) anchor all of the above
for every registered OID: on-curve, order, the independent scalar-mult KAT,
group laws, cofactor, `IsOnCurve` rejection, identity edge cases, and
aliasing. `TestRandomScalarMultOnCurve` additionally spot-checks random
scalars per curve, asserting the result stays on-curve and non-identity.

```sh
go test ./gost3410curves/
```

The constant-time `ScalarMultCT` path has its own, separate validation regime
(differential vs. `ScalarMult`, `dudect`, and `ctgrind` instruction-level
leak detection) — see [EXPERIMENT-ct.md](EXPERIMENT-ct.md).

## References

- **[RFC 4357](rfc/rfc4357.txt)** — "Additional Cryptographic Algorithms for
  GOST 28147-89, GOST R 34.11-94, GOST R 34.10-94, and GOST R 34.10-2001."
  §11.2/§11.4 — CryptoPro 2001 256-bit parameter sets; §10.8 — OID arcs.
- **[RFC 7836](rfc/rfc7836.txt)** — "Guidelines on the Cryptographic
  Algorithms to Accompany the Usage of Standards GOST R 34.10-2012 and GOST R
  34.11-2012." §5.1 (Weierstrass form), §5.2 (twisted Edwards), Appendix A —
  the 256/512-bit TC26 parameter sets.
- **[RFC 7091](rfc/rfc7091.txt)** — GOST R 34.10-2012 algorithm; §A.1/§A.2
  hold a sign/verify KAT exercised end-to-end in `gost3410sign`.
- **[RFC 4491](rfc/rfc4491.txt)** — "Using the GOST R 34.10-94, GOST R
  34.10-2001, and GOST R 34.11-94 Algorithms with the Internet X.509 Public
  Key Infrastructure Certificate and CRL Profile" — the certificate-profile
  context consumed by `x509gost`.
- **[draft-deremin-rfc4491-bis](rfc/draft-deremin-rfc4491-bis.txt)** —
  consolidated OID list and the 2012↔2001 256-bit curve aliasing.
- GOST R 34.10-2001 (curves `1.2.643.2.2.35.x`), GOST R 34.10-2012 (TC26
  curves `1.2.643.7.1.2.1.{1,2}.x`), GOST R 34.11-2012 (Streebog, the digest
  these signatures consume).

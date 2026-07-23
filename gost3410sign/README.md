# gost3410sign — GOST R 34.10 Digital Signature Algorithm (RFC 5832 / RFC 7091)

`package gost3410sign` implements the GOST R 34.10 elliptic-curve digital
signature algorithm: sign, verify, and public-key derivation over a
short-Weierstrass GOST curve. It is structurally an EC-Schnorr/ElGamal
variant — **not** ECDSA, despite the superficial resemblance — and covers
both generations of the standard (GOST R 34.10-2001 / RFC 5832 and GOST R
34.10-2012 / RFC 7091) with the same sign/verify math; only the companion
hash and coordinate size differ between them. Curve arithmetic is supplied by
the sibling package `gost3410curves`.

Import path: `github.com/tarantool/go-gostcrypto/gost3410sign`

## API

| Symbol | Description |
|---|---|
| `SignDigest(c *curves.Curve, prv, digest, k []byte) []byte` | Signs `digest` under the little-endian private key `prv` using nonce `k` (big-endian), returning the `2·PointSize`-byte raw signature `s\|\|r`. Returns `nil` on a degenerate input (zero private key, zero nonce mod `q`, or a nonce that yields `r == 0` or `s == 0`) — a correct caller retries with a fresh `k`. |
| `VerifyDigest(c *curves.Curve, pubRaw, digest, sig []byte) bool` | Reports whether `sig` (`2·PointSize` bytes, `s\|\|r`) is a valid signature of `digest` under the LE-encoded public key `pubRaw`. Returns `false` — never panics — on any malformed input: wrong-length `sig`/`pubRaw`, an off-curve public key, or out-of-range `r`/`s`. |
| `PublicKeyRaw(c *curves.Curve, prv []byte) []byte` | Derives the public key (`LE(X) \|\| LE(Y)`, `2·PointSize` bytes) from the little-endian private key `prv`. Returns `nil` if `prv` reduces to zero mod `q`. |

There are no exported types in this package; `c *curves.Curve` comes from the
sibling `gost3410curves` package (`curves.CurveByOID`, or a curve built
directly from parameter constants for test/unlisted parameter sets). None of
`SignDigest`/`VerifyDigest`/`PublicKeyRaw` take or return an `io.Reader` or an
`error` — nonce generation and retry-on-degenerate-input are the caller's
responsibility; see [DESIGN.md](DESIGN.md) for why.

## Usage

```go
import (
	curves "github.com/tarantool/go-gostcrypto/gost3410curves"
	"github.com/tarantool/go-gostcrypto/gost3410sign"
)

c, err := curves.CurveByOID("1.2.643.7.1.2.1.1.1") // tc26-gost-3410-2012-256-paramSetA
if err != nil {
	panic(err)
}

pub := gost3410sign.PublicKeyRaw(c, prv) // prv: PointSize bytes, little-endian

sig := gost3410sign.SignDigest(c, prv, digest, nonce) // digest, nonce: big-endian
if sig == nil {
	// degenerate nonce — draw a fresh one and retry
}

ok := gost3410sign.VerifyDigest(c, pub, digest, sig)
```

`digest` is the hash of the message read as a big-endian integer (RFC 7091
§5.3) — GOST R 34.11-94 for 34.10-2001, Streebog-256 or Streebog-512 (see
[`../streebog/README.md`](../streebog/README.md)) for 34.10-2012. `nonce`
must be drawn uniformly from `(0, q)` per signature; reusing a nonce across
two signatures under the same key leaks the private key, exactly as with
ECDSA/Schnorr nonce reuse.

## Standards

- [RFC 5832](rfc/rfc5832.txt) — GOST R 34.10-2001 (Digital Signature Algorithm).
- [RFC 7091](rfc/rfc7091.txt) — GOST R 34.10-2012 (Digital Signature Algorithm), the current generation.
- [RFC 7836](rfc/rfc7836.txt) §3 — TC26 2012 curve parameter sets (256- and 512-bit).
- [RFC 4357](rfc/rfc4357.txt) — legacy CryptoPro 2001 curve parameter sets and cipher-suite context.
- GOST R 34.10-2012 / GOST R 34.10-2001 — the originating Russian national standards (no local copy; RFC 7091/5832 are their English republications).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

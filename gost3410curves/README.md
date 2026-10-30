# gost3410curves — GOST R 34.10 Curve Parameter Sets (RFC 4357 / RFC 7836)

`package gost3410curves` resolves a GOST R 34.10 named elliptic-curve
parameter set by OID and implements the short-Weierstrass affine point
arithmetic over it. GOST R 34.10-2001/2012 do not define a single curve — a
certificate, key, or TLS handshake names one of twelve registered parameter
sets (`p, a, b, q, x, y`, plus a cofactor) by OID, and every sign/verify/VKO/KEG
operation resolves that OID first. `gost3410sign`, `vko`, and `keg` all build
on this package for their curve arithmetic.

Import path: `github.com/tarantool/go-gostcrypto/gost3410curves`

## API

| Symbol | Description |
|---|---|
| `type Curve struct{ P, A, B, Q, X, Y *big.Int; Name string; Cofactor int; ConstantTime bool }` | A registered parameter set: `y² = x³+a·x+b (mod P)`, base point `(X,Y)` of prime order `Q`. `Cofactor` is 1 or 4. `ConstantTime` selects the `ScalarMultSecret` backend (see below); zero value is `false`. |
| `type Point struct{ X, Y *big.Int }` | An affine point; the identity is `(nil, nil)`. |
| `(Point) IsInfinity() bool` | Reports whether `p` is the point at infinity. |
| `CurveByOID(oid string) (*Curve, error)` | Resolves one of the twelve registered dotted-decimal OID arcs (CryptoPro-A/B/C, CryptoPro-XchA/B, tc26-256-A/B/C/D, tc26-512-A/B/C) to its parameter set. Unknown OID → error. |
| `(*Curve) PointSize() int` | Serialized coordinate size in bytes, derived from `P.BitLen()`: 32 for the 256-bit curves, 64 for the 512-bit ones. |
| `(*Curve) Base() Point` | Returns the base point `G = (X, Y)`. |
| `(*Curve) IsOnCurve(p Point) bool` | Reports whether `p` satisfies `y² ≡ x³+ax+b (mod P)`; the identity is always on-curve. |
| `(*Curve) Add(p, q Point) Point` | Affine point addition. Precondition: both points reduced and on-curve (or the identity) — no validation is performed. |
| `(*Curve) Double(p Point) Point` | Affine point doubling; same precondition as `Add`. |
| `(*Curve) ScalarMult(k *big.Int, p Point) Point` | `k·p` via left-to-right double-and-add over `math/big`. **Not constant-time** — branches on the bits of `k`. Correct for public scalars (verification); see [SECURITY.md](SECURITY.md) before using it on a secret. |
| `(*Curve) ScalarMultCT(k *big.Int, p Point) Point` | Constant-time `k·p` (EXPERIMENT) via a fixed-window Montgomery-domain ladder. Covers the 256-bit (4-limb) and 512-bit (8-limb) curves; on any other width it falls back to `ScalarMult` (documented, not constant-time). See [EXPERIMENT-ct.md](EXPERIMENT-ct.md). |
| `(*Curve) ScalarMultSecret(k *big.Int, p Point) Point` | The selector for secret scalars (signing nonce, private key): calls `ScalarMultCT` if `c.ConstantTime` is `true`, else `ScalarMult`. Callers opt into the constant-time path per curve instance. |

## Usage

```go
import (
	"math/big"

	"github.com/tarantool/go-gostcrypto/gost3410curves"
)

curve, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.1.1") // tc26-256-A
if err != nil {
	// unknown OID
}

// Public-key derivation from a private scalar d.
pub := curve.ScalarMultSecret(d, curve.Base())
if !curve.IsOnCurve(pub) {
	// should never happen for a well-formed curve/scalar
}
```

Opt into the constant-time backend for secret-scalar operations by setting
`curve.ConstantTime = true` once before use; see
[EXPERIMENT-ct.md](EXPERIMENT-ct.md) for what it does and does not guarantee.

## Standards

- [RFC 4357](rfc/rfc4357.txt) §11 — CryptoPro 2001 256-bit parameter sets; §10 — OID arcs.
- [RFC 7836](rfc/rfc7836.txt) §5.1 (Weierstrass form), §5.2 (twisted Edwards), Appendix A — the TC26 2012 256/512-bit parameter sets.
- [RFC 7091](rfc/rfc7091.txt) — the GOST R 34.10-2012 signature algorithm that consumes a resolved curve; §A.1/§A.2 hold a sign/verify KAT.
- [RFC 4491](rfc/rfc4491.txt) — GOST R 34.10-94/2001 with X.509; the certificate-profile context for these OIDs.
- [draft-deremin-rfc4491-bis](rfc/draft-deremin-rfc4491-bis.txt) — consolidated OID list and the 2012↔2001 256-bit curve aliasing.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.
- [SECURITY.md](SECURITY.md) — why `ScalarMult` is not constant-time, and what a constant-time replacement requires.
- [EXPERIMENT-ct.md](EXPERIMENT-ct.md) — the constant-time `ScalarMultCT` experiment: design, results, and honest limits.
- [EXPERIMENT-asm.md](EXPERIMENT-asm.md) — forward-looking plan for assembly/codegen acceleration of the constant-time field multiply.

# x509gost — GOST-signed X.509 certificate parsing and verification (RFC 9215 / RFC 4491, over RFC 5280)

`package x509gost` parses X.509 certificates that use the GOST R 34.10-2001 or
GOST R 34.10-2012 (256-/512-bit) signature and public-key algorithms, and
verifies GOST certificate chains end to end. It builds entirely on this
module's pure-Go primitives (`gost3410sign`, `gost3410curves`, `streebog`,
`gostr341194`) via the top-level `github.com/tarantool/go-gostcrypto` facade —
no build tags, no third-party dependencies. Every non-GOST certificate is
handled by delegating to `crypto/x509` unchanged.

Import path: `github.com/tarantool/go-gostcrypto/x509gost`

## API

| Symbol | Description |
|---|---|
| `ParseCertificate(der []byte) (*Certificate, error)` | Parses a DER-encoded certificate. Always runs the stdlib parser first (for SANs, validity, extensions, etc.), then walks the DER a second time to extract GOST fields. Non-GOST certs return with only `.Stdlib`/`.Raw` populated. Errors on empty input, malformed DER, trailing bytes after the certificate, or a GOST signature OID paired with a non-GOST public-key OID. |
| `type Certificate struct{ Stdlib *x509.Certificate; Raw []byte; IsGOST bool; HasGOSTPubKey bool; GOSTAlgo GOSTAlgorithm; SigGOSTAlgo GOSTAlgorithm; PubKeyRaw []byte; CurveOID asn1.ObjectIdentifier; SPKIAlgorithmDER []byte }` | Wraps `*x509.Certificate`. See field-by-field description below. |
| `(*Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error)` | Verifies a certificate (chain construction + signature + validity + name + EKU checks). Non-GOST leaves delegate entirely to `x509.Certificate.Verify`; GOST leaves are chained and verified by this package (see [DESIGN.md](DESIGN.md)). |
| `type GOSTAlgorithm int` with `AlgoR341001`, `AlgoR341012_256`, `AlgoR341012_512`, and `(GOSTAlgorithm) String() string` | Identifies which GOST signature/key family a certificate uses. |
| `type VerifyOptions struct{ Roots *x509.CertPool; GOSTRoots []*Certificate; GOSTIntermediates []*Certificate; DNSName string; CurrentTime time.Time; KeyUsages []x509.ExtKeyUsage }` | Mirrors `x509.VerifyOptions`, with a separate GOST trust-anchor/intermediate pool since the stdlib `*x509.CertPool` cannot hold certificates the stdlib itself cannot verify. |
| `OIDSignatureGOSTR341001`, `OIDSignatureGOSTR341012_256`, `OIDSignatureGOSTR341012_512` | Signature-algorithm (signwithdigest) OIDs. |
| `OIDPublicKeyGOSTR341001`, `OIDPublicKeyGOSTR341012_256`, `OIDPublicKeyGOSTR341012_512` | Public-key algorithm OIDs. |
| `OIDHashGOSTR341194`, `OIDHashStreebog256`, `OIDHashStreebog512` | Hash-algorithm OIDs. |
| `OIDParamCryptoProA/B/C`, `OIDParamCryptoProXchA/B`, `OIDParamTC26_256A/B/C/D`, `OIDParamTC26_512A/B/C` | Curve parameter-set OIDs, for identifying the SPKI curve without going through `gost3410curves.CurveByOID`. |

`Certificate` field notes:

- `HasGOSTPubKey` is independent of `IsGOST`: a certificate can be RSA-signed
  while still carrying a GOST public key in its SPKI (a case the fixtures under
  `testdata/certs/` cover). Key-exchange code that only needs the subject key
  should check `HasGOSTPubKey`; chain verification via `Verify` needs `IsGOST`.
- `GOSTAlgo` describes the *subject key* (drives key parsing and the VKO/KEX
  role); `SigGOSTAlgo` describes the *signing digest* actually used over this
  certificate's `TBSCertificate` (per RFC 9215 §2, the signwithdigest OID, not
  the subject key's strength, picks the hash). A 256-bit leaf signed by a
  512-bit CA has `GOSTAlgo == AlgoR341012_256` and
  `SigGOSTAlgo == AlgoR341012_512` — see the mixed-strength notes in
  [DESIGN.md](DESIGN.md).
- `PubKeyRaw` is `LE(X) || LE(Y)` — the little-endian X coordinate followed by
  the little-endian Y coordinate — the wire convention shared with
  `gost3410sign` and `gost3410curves` across this module.

## Usage

```go
import (
	"crypto/x509"
	"time"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// Parse a leaf and a self-signed (or CA) root, both DER-encoded.
leaf, err := x509gost.ParseCertificate(leafDER)
root, err := x509gost.ParseCertificate(rootDER)

if leaf.IsGOST {
	chains, err := leaf.Verify(x509gost.VerifyOptions{
		GOSTRoots:   []*x509gost.Certificate{root},
		DNSName:     "example.com",
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	// chains[0] is leaf-first, root-last, mirroring x509.Verify's shape.
} else {
	// Non-GOST cert: leaf.Verify delegates entirely to leaf.Stdlib.Verify.
}
```

`GOSTIntermediates` bridges a leaf to a root through GOST-signed intermediate
CAs; omit it for a direct leaf-signed-by-root chain. See
[DESIGN.md](DESIGN.md) for the exact chain-building and path-validation rules
(name constraints, `pathLenConstraint`, unhandled critical extensions).

## Standards

- [RFC 9215](rfc/rfc9215.txt) — Using the GOST R 34.10-2012 and GOST R 34.11-2012 Algorithms with the Internet X.509 PKI.
- [RFC 4491](rfc/rfc4491.txt) — Using the GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms with the Internet X.509 PKI (updates RFC 3279).
- [RFC 5280](rfc/rfc5280.txt) — Internet X.509 Public Key Infrastructure Certificate and CRL Profile — the base profile both GOST RFCs extend, and the source of the path-validation rules (name constraints, `pathLenConstraint`, critical extensions) this package layers onto the GOST chain walk.
- [RFC 7091](../gost3410curves/rfc/rfc7091.txt) — defines the `signwithdigest`/pubkey OIDs for GOST R 34.10-2012/256 and /512 that RFC 9215 references.

## Documentation

- [DESIGN.md](DESIGN.md) — what the package does, the certificate wire format, chain-building and path-validation rules, implementation notes, and the test-fixture inventory.

# keg — KEG key export generation (R 1323565.1.020-2018)

`package keg` implements KEG ("key export generation"), the GOST 2012 TLS 1.2
key-derivation step specified in **R 1323565.1.020-2018 §6.4.5.1** and used by
the GOST cipher suites of **RFC 9189** / **RFC 9367**. It turns a VKO
Diffie-Hellman shared secret into the 64-byte symmetric key block that the
`kexp15` key-wrap step then uses to encrypt the TLS pre-master secret.

Import path: `github.com/tarantool/go-gostcrypto/keg`

## API

| Symbol | Description |
|---|---|
| `KEG2012_256(curve *gost3410curves.Curve, serverPub, clientPriv, ukmSource []byte) ([64]byte, error)` | Derives the 64-byte export key block for the 256-bit GOST 2012 TLS suites. `curve` selects the GOST R 34.10-2012 256-bit domain (`nil` defaults to TC26 ParamSet A); `serverPub` is the peer's 64-byte raw public key (`LE X ‖ LE Y`); `clientPriv` is the local 32-byte little-endian private scalar; `ukmSource` is exactly 32 bytes of UKM material. |
| `ErrUKMSourceLen` | Returned when `ukmSource` is not exactly 32 bytes. |
| `ErrCurve512` | Returned when `curve` is a 512-bit curve — `KEG2012_256` implements only the 256-bit algorithm. |

The output's first 32 bytes are the MAC key and the last 32 the cipher key
(`expkeys[:32]`, `expkeys[32:]`); see [DESIGN.md](DESIGN.md#output-split) for
why the order matters to the consumer.

## Usage

```go
import (
	"github.com/tarantool/go-gostcrypto/keg"
)

// curve == nil defaults to TC26 GOST R 34.10-2012 256-bit ParamSet A.
expkeys, err := keg.KEG2012_256(nil, serverPub, clientPriv, ukmSource)
if err != nil {
	// ...
}

macKey := expkeys[:32]
cipherKey := expkeys[32:]
```

To use a different 256-bit curve (e.g. a CryptoPro paramset signalled by the
server certificate), look it up with
[`gost3410curves.CurveByOID`](../gost3410curves/DESIGN.md) and pass it instead
of `nil`.

## Standards

- [R 1323565.1.020-2018](rfc/R1323565.1.020-2018.pdf) §6.4.5.1 — the KEG ("key export generation") definition.
- [RFC 9189](rfc/rfc9189.txt) — GOST cipher suites for TLS 1.2 that consume KEG's output via `kexp15`.
- [RFC 7836](rfc/rfc7836.txt) §4.3 (VKO_GOSTR3411_2012_256) and §4.4 (KDF_TREE_GOSTR3411_2012_256) — the two primitives KEG assembles.
- [RFC 6986](rfc/rfc6986.txt) — GOST R 34.11-2012 (Streebog), the hash used inside both VKO and the KDF tree.
- [RFC 7091](rfc/rfc7091.txt) — GOST R 34.10-2012, the signature/key-pair scheme and curve family KEG operates on.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

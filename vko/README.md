# vko — VKO Diffie-Hellman Key Agreement (GOST R 34.10-2001 & 2012)

`package vko` implements VKO (ВКО, *выработка ключа общего* — "shared key
derivation"), the Diffie-Hellman-style key-agreement function for GOST
elliptic-curve keys. One party combines its own private scalar, the peer's
public point, and a small "user keying material" (UKM) integer into a single
curve point, then hashes that point's coordinates to produce a Key Encryption
Key (KEK). The agreement is symmetric:
`KEK(d_A, Q_B, UKM) == KEK(d_B, Q_A, UKM)`. Both the GOST R 34.10-2001 flavour
(RFC 4357 §5.2) and the GOST R 34.10-2012 flavour (RFC 7836 §4.3) are
implemented, the latter in 256-bit and 512-bit KEK widths.

Import path: `github.com/tarantool/go-gostcrypto/vko`

## API

| Symbol | Description |
|---|---|
| `KEK2001(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error)` | VKO GOST R 34.10-2001 (RFC 4357 §5.2) on an explicit curve: agreement point hashed with GOST R 34.11-94 (CryptoPro S-box). Returns a 32-byte KEK. |
| `KEK2012256(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error)` | VKO GOST R 34.10-2012 (RFC 7836 §4.3) on an explicit curve, KEK hashed with Streebog-256. Returns a 32-byte KEK. |
| `KEK2012512(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error)` | Same as `KEK2012256` but hashed with Streebog-512. Returns a 64-byte KEK. |
| `VKO2001TestCurve(prvLE, pubLE, ukmRaw []byte) ([]byte, error)` | `KEK2001` pinned to the fixed `id-GostR3410-2001-TestParamSet` curve (RFC 4357 §11.4). |
| `VKO2012_256(prvLE, pubLE, ukmRaw []byte) ([]byte, error)` | `KEK2012256` pinned to the default 512-bit `id-tc26-gost-3410-12-512-paramSetA` curve. |
| `VKO2012_512(prvLE, pubLE, ukmRaw []byte) ([]byte, error)` | `KEK2012512` pinned to the same default curve as `VKO2012_256`. |
| `Curve2001Test() *gost3410curves.Curve` | Returns a fresh instance of the fixed 2001 test curve used by `VKO2001TestCurve`. |
| `Curve2012ParamSetA() *gost3410curves.Curve` | Returns a fresh instance of the default 2012 curve used by `VKO2012_256`/`VKO2012_512`. |
| `DeriveQLE(c *gost3410curves.Curve, dLE []byte) ([]byte, error)` | Derives the LE-encoded public point `d·G` for a little-endian private scalar `dLE` on curve `c`. Used to build a peer's public key from a private one; not itself part of the VKO agreement. |
| `ErrZeroPrivate`, `ErrBadPrivLen`, `ErrBadPubLen`, `ErrPubNotOn` | Sentinel errors for, respectively: a private scalar that is zero (before or after reduction mod the subgroup order), a private key of the wrong byte length, a public key of the wrong byte length, and a public point that fails the on-curve check. |

All private scalars, public points, and UKM values are little-endian byte
slices (see [DESIGN.md](DESIGN.md) for the exact encoding). `prvLE` must be
`c.PointSize()` bytes; `pubLE` must be `2*c.PointSize()` bytes
(`LE(X) || LE(Y)`); `ukmRaw` may be any length and is interpreted as a
little-endian integer.

## Usage

```go
import (
	"github.com/tarantool/go-gostcrypto/gost3410curves"
	"github.com/tarantool/go-gostcrypto/vko"
)

curve, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.2.1") // tc26-512-paramSetA
if err != nil {
	// unknown OID
}

// Each side derives its own public point from its private scalar...
pubA, err := vko.DeriveQLE(curve, privA)
pubB, err := vko.DeriveQLE(curve, privB)

// ...then both sides compute the same KEK from the peer's public point.
kekAB, err := vko.KEK2012256(curve, privA, pubB, ukm)
kekBA, err := vko.KEK2012256(curve, privB, pubA, ukm)
// kekAB == kekBA
```

Or, for the common 2012-256 default curve, skip the explicit `Curve` entirely:

```go
kek, err := vko.VKO2012_256(privA, pubB, ukm)
```

## Standards

- [RFC 4357](rfc/rfc4357.txt) §5.2 — VKO GOST R 34.10-2001 key agreement; §11.4 the fixed test parameter set.
- [RFC 7836](rfc/rfc7836.txt) §3 (coordinate serialization), §4.3 (VKO_GOSTR3410_2012_256/512) — VKO GOST R 34.10-2012 key agreement.
- [RFC 6986](rfc/rfc6986.txt) — GOST R 34.11-2012 (Streebog), the 2012 KEK hash.
- [RFC 5831](rfc/rfc5831.txt) — GOST R 34.11-94, the 2001 KEK hash.
- [RFC 9189](rfc/rfc9189.txt) — GOST cipher suites for TLS 1.2, a downstream consumer of VKO-derived key material.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

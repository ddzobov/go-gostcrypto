# go-gostcrypto

[![test](https://github.com/tarantool/go-gostcrypto/actions/workflows/test.yml/badge.svg)](https://github.com/tarantool/go-gostcrypto/actions/workflows/test.yml)
[![lint](https://github.com/tarantool/go-gostcrypto/actions/workflows/lint.yml/badge.svg)](https://github.com/tarantool/go-gostcrypto/actions/workflows/lint.yml)
[![fuzz](https://github.com/tarantool/go-gostcrypto/actions/workflows/fuzz.yml/badge.svg)](https://github.com/tarantool/go-gostcrypto/actions/workflows/fuzz.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tarantool/go-gostcrypto.svg)](https://pkg.go.dev/github.com/tarantool/go-gostcrypto)

Pure-Go GOST cryptographic primitives — Streebog (GOST R 34.11-2012),
Kuznyechik and Magma (GOST R 34.12-2015), GOST 28147-89, GOST R 34.10
sign/verify, VKO key agreement, MGM, OMAC, CTR-ACPKM, KDFTree, TLSTree, KEG,
KExp15, CryptoPro key wrap, and GOST R 34.11-94 — plus GOST-signed X.509
parsing and verification.

**Pure-Go, BSD-2-Clause, zero third-party dependencies** (`CGO_ENABLED=0`).
Every primitive is a clean-room re-implementation; no GPL code is linked and
none appears in this module's `go.mod`/`go.sum`.

## Quick start

```sh
go get github.com/tarantool/go-gostcrypto
```

```go
import "github.com/tarantool/go-gostcrypto"

// Hash with Streebog-256.
digest := gostcrypto.Streebog256([]byte("hello"))

// Encrypt and decrypt with Kuznyechik.
ciphertext, err := gostcrypto.KuznyechikEncrypt(key, plaintext)
if err != nil {
	// handle error
}
plaintext, err = gostcrypto.KuznyechikDecrypt(key, ciphertext)
```

The root package is a stable `[]byte`-in/`[]byte`-out facade; for the idiomatic
`cipher.Block` / `hash.Hash` API import the primitive packages directly (see
below). Full API reference:
[pkg.go.dev](https://pkg.go.dev/github.com/tarantool/go-gostcrypto).

## Layout

```
gostcrypto/                  package gostcrypto — the public facade (clean-room)
  *.go                       stable []byte-in/[]byte-out API, delegates to the primitives
  streebog/ kuznyechik/ …    BSD clean-room primitives, each importable directly;
                             each has a README.md (overview) and DESIGN.md (detail)
  x509gost/…                 GOST-signed X.509 parse/verify
  internal/ct/               shared branch-free masking primitives for the constant-time paths
```

- **Facade** (root `gostcrypto` package): a stable `[]byte`-in/`[]byte`-out API.
  Consumers that want a simple call surface import this.
- **Primitive packages** (`streebog/`, `kuznyechik/`, …): each primitive as its
  own package with an idiomatic `cipher.Block` / `hash.Hash` API, importable directly.
- **`x509gost`**: GOST X.509. `ParseCertificate` returns a `*Certificate`
  wrapping the stdlib cert plus GOST metadata; non-GOST DER passes through
  unchanged.

## Packages

Each package name links to its `README.md` — a short overview with the public
API and a usage example — which in turn links to the package's `DESIGN.md`:
the full algorithm description, specification, implementation notes, and test
vectors.

The Spec(s) column links to the copy of each standard committed alongside the
code, under that package's `rfc/` directory.

| Package | Primitive | Spec(s) |
|---|---|---|
| [`gost28147`](gost28147/README.md) | GOST 28147-89 block cipher core (ECB, key schedule, S-boxes) | [RFC 5830](gost28147/rfc/rfc5830.txt), [RFC 4357](gost28147/rfc/rfc4357.txt) |
| [`magma`](magma/README.md) | Magma — GOST R 34.12-2015, 64-bit block | [RFC 8891](magma/rfc/rfc8891.txt) |
| [`kuznyechik`](kuznyechik/README.md) | Kuznyechik — GOST R 34.12-2015, 128-bit block | [RFC 7801](kuznyechik/rfc/rfc7801.txt) |
| [`gost28147cnt`](gost28147cnt/README.md) | GOST 28147-89 CNT counter/gamma stream | [RFC 5830](gost28147cnt/rfc/rfc5830.txt), [RFC 4357](gost28147cnt/rfc/rfc4357.txt) |
| [`gost28147imit`](gost28147imit/README.md) | GOST 28147-89 IMIT MAC + CryptoPro key meshing | [RFC 5830](gost28147imit/rfc/rfc5830.txt), [RFC 4357](gost28147imit/rfc/rfc4357.txt) |
| [`ctracpkm`](ctracpkm/README.md) | CTR mode + ACPKM key meshing | [RFC 8645](ctracpkm/rfc/rfc8645.txt); [GOST R 34.13-2015](ctracpkm/rfc/GOST_R_34.13-2015.pdf) |
| [`omac`](omac/README.md) | OMAC / CMAC (GOST R 34.13-2015 MAC) | [RFC 4493](omac/rfc/rfc4493.txt); [GOST R 34.13-2015](omac/rfc/GOST_R_34.13-2015.pdf) |
| [`mgm`](mgm/README.md) | MGM AEAD (Multilinear Galois Mode) | [RFC 9058](mgm/rfc/rfc9058.txt); [R 1323565.1.026-2019](mgm/rfc/R1323565.1.026-2019.pdf) |
| [`streebog`](streebog/README.md) | Streebog hash — GOST R 34.11-2012, 256 & 512 | [RFC 6986](streebog/rfc/rfc6986.txt) |
| [`gostr341194`](gostr341194/README.md) | GOST R 34.11-94 legacy hash (CryptoPro param set) | [RFC 5831](gostr341194/rfc/rfc5831.txt), [RFC 4357](gostr341194/rfc/rfc4357.txt) |
| [`kdftree`](kdftree/README.md) | KDF_TREE_GOSTR3411_2012_256 | [RFC 7836](kdftree/rfc/rfc7836.txt) |
| [`tlstree`](tlstree/README.md) | TLSTree per-record key derivation | [RFC 9189](tlstree/rfc/rfc9189.txt), [RFC 7836](tlstree/rfc/rfc7836.txt) |
| [`gost3410sign`](gost3410sign/README.md) | GOST R 34.10-2001/2012 signature (sign + verify) | [RFC 7091](gost3410sign/rfc/rfc7091.txt), [RFC 5832](gost3410sign/rfc/rfc5832.txt) |
| [`gost3410curves`](gost3410curves/README.md) | GOST R 34.10 curve parameter sets (CryptoPro + TC26) | [RFC 4357](gost3410curves/rfc/rfc4357.txt), [RFC 7836](gost3410curves/rfc/rfc7836.txt) |
| [`vko`](vko/README.md) | VKO key agreement (GOST 34.10-2001 & 2012) | [RFC 4357](vko/rfc/rfc4357.txt), [RFC 7836](vko/rfc/rfc7836.txt) |
| [`keywrap`](keywrap/README.md) | CryptoPro KeyWrap + key diversification | [RFC 4357](keywrap/rfc/rfc4357.txt) §6 |
| [`keg`](keg/README.md) | KEG — key export generation (TLS GOST KEX) | [RFC 9189](keg/rfc/rfc9189.txt); [R 1323565.1.020-2018](keg/rfc/R1323565.1.020-2018.pdf) |
| [`kexp15`](kexp15/README.md) | KExp15 / KImp15 key export wrapping | [RFC 9189](kexp15/rfc/rfc9189.txt); [R 1323565.1.017-2018](kexp15/rfc/R1323565.1.017-2018.pdf) |
| [`x509gost`](x509gost/README.md) | GOST-signed X.509 parse/verify | [RFC 9215](x509gost/rfc/rfc9215.txt), [RFC 4491](x509gost/rfc/rfc4491.txt) |

A byte-order trap that cuts across all of them: GOST serializes integers,
keys, public-key coordinates, and signatures **little-endian** on the wire
(public keys are `LE(X) || LE(Y)`, signatures are `s || r`), while the
underlying math and the RFC constant tables are big-endian. When a test
vector fails, check byte order first — each package's `DESIGN.md`
implementation notes list the traps for that primitive.

## Constant-time / side channels

The default primitives are table-driven and **not constant-time** — they leak
the key/plaintext through cache timing, matching the GOST software norm
(gogost, gost-engine) and the table-driven AES shipped everywhere. Two
experimental, leak-free paths exist alongside them, sharing the branch-free
masking vocabulary in `internal/ct`:

- **`kuznyechik.NewCipherCT(key)`** — a constant-time Kuznyechik whose
  `Encrypt`/`Decrypt` and key schedule have no secret-dependent memory access
  (SWAR full-scan S-box + GF(2)-linear `L` columns, no fused 64 KiB tables).
  Byte-for-byte identical to the table cipher; ≈36× slower. See
  [`kuznyechik/SECURITY.md`](kuznyechik/SECURITY.md).
- **`gost3410curves.(*Curve).ScalarMultCT(k, p)`** — a constant-time EC scalar
  multiply for *secret* scalars (signing nonce, private key), built on
  fixed-limb Montgomery field arithmetic and complete short-Weierstrass
  formulas. The variable-time `big.Int` `ScalarMult` remains the default; opt in
  per `Curve` via the `ConstantTime` flag. See
  [`gost3410curves/SECURITY.md`](gost3410curves/SECURITY.md) and
  [`gost3410curves/EXPERIMENT-ct.md`](gost3410curves/EXPERIMENT-ct.md).

Both are exercised by a verification harness in CI: **ctgrind**
(valgrind/memcheck, instruction-level — fails if any branch/address depends on
the poisoned secret) and **dudect** (statistical timing-leak sweep). Each runs a
variable-time positive control that *must* be flagged, so a broken detector
can't pass silently.

## Build & test

```sh
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
make lint    # golangci-lint v2 (config in .golangci.yml)
make fuzz    # drive every Fuzz target (FUZZTIME=1m by default)
```

The KAT tests run oracle-free. CI (GitHub Actions) runs the test, lint, and
fuzz workflows (status shown by the badges above), plus parity / parity-fuzz
differentials and the `ctgrind` + `dudect` constant-time checks on every pull
request.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow, coding conventions, and the pre-push checklist. Notable
changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Licensing

BSD 2-Clause — see [LICENSE](LICENSE).

## Reference material

- `<package>/README.md` → `<package>/DESIGN.md` — per-package overview and the
  full algorithm description, specification, implementation notes, and test
  vectors (see the Packages table above).
- [`gost3410curves/SECURITY.md`](gost3410curves/SECURITY.md) — constant-time status of `ScalarMult` and the
  experimental `ScalarMultCT`.
- [`gost3410curves/EXPERIMENT-ct.md`](gost3410curves/EXPERIMENT-ct.md) — design and verification methodology for the
  constant-time EC scalar multiply (shared by both CT paths and the CI harness).
- [`kuznyechik/SECURITY.md`](kuznyechik/SECURITY.md) — cache-timing of the table-driven S-L rounds and the
  experimental constant-time `NewCipherCT` path.

Known gogost/gost-engine vector divergences (S-box row order, GOST R 34.11-94
empty-input finalization, CryptoPro key meshing) are described in the relevant
package `DESIGN.md` files, next to the code they affect.

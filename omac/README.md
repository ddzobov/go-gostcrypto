# omac — OMAC1 / CMAC (GOST R 34.13-2015 MAC mode)

`package omac` computes the GOST R 34.13-2015 message authentication code — the
"MAC mode" (§5.6), which is exactly OMAC1 / CMAC (RFC 4493, NIST SP 800-38B)
instantiated with a GOST block cipher instead of AES. It layers over any
[`crypto/cipher.Block`](https://pkg.go.dev/crypto/cipher#Block), so it works
with both Kuznyechik and Magma.

Import path: `github.com/tarantool/go-gostcrypto/omac`

## API

| Symbol | Description |
|---|---|
| `New(b cipher.Block, tagSize int) *OMAC` | Construct a MAC over the given block cipher, producing tags of `tagSize` bytes (`1 ≤ tagSize ≤ block size`). |
| `(*OMAC) Write(p []byte) (int, error)` | Feed message bytes. Streaming; any split produces the same tag. |
| `(*OMAC) Sum(b []byte) []byte` | Append the tag to `b` and return it. Non-destructive — the MAC may be written to again afterwards. |
| `(*OMAC) BlockSize() int` / `Size() int` | Cipher block size and configured tag length. |

`OMAC` is a streaming MAC accumulator — its `Write` makes it an
[`io.Writer`](https://pkg.go.dev/io#Writer) — but it deliberately does **not**
implement [`hash.Hash`](https://pkg.go.dev/hash#Hash): there is no `Reset`, and
`Sum` truncates to `tagSize` rather than always emitting the full digest.
Construct a fresh value per message.

## Usage

```go
import (
	"github.com/tarantool/go-gostcrypto/kuznyechik"
	"github.com/tarantool/go-gostcrypto/omac"
)

m := omac.New(kuznyechik.NewCipher(key), 16) // full 16-byte tag
m.Write(message)
tag := m.Sum(nil)
```

Verify tags in constant time with
[`crypto/subtle.ConstantTimeCompare`](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare);
never branch on a byte mismatch.

## Standards

- [RFC 4493](rfc/rfc4493.txt) — The AES-CMAC Algorithm (subkey generation, MAC generation, truncation).
- [GOST R 34.13-2015](rfc/GOST_R_34.13-2015.pdf) §5.6 — MAC mode, plus the Kuznyechik (A.1.6) and Magma (A.2.6) known-answer tests.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

# mgm — Multilinear Galois Mode AEAD (RFC 9058)

`package mgm` implements the Multilinear Galois Mode (MGM), a nonce-based AEAD
block-cipher mode standardized in **RFC 9058** and the Russian recommendation
**R 1323565.1.026-2019** — the GOST analogue of AES-GCM. It works over any
[`crypto/cipher.Block`](https://pkg.go.dev/crypto/cipher#Block) with a 64-bit
(Magma) or 128-bit (Kuznyechik) block size.

Import path: `github.com/tarantool/go-gostcrypto/mgm`

## API

| Symbol | Description |
|---|---|
| `NewMGM(c cipher.Block, tagSize int) (*MGM, error)` | Construct an MGM AEAD over the given block cipher. `c.BlockSize()` must be 8 (Magma) or 16 (Kuznyechik) bytes; `tagSize` must satisfy `4 ≤ tagSize ≤ blockSize`. Returns `errBlockSize` / `errTagSize` otherwise. |
| `(*MGM) NonceSize() int` | The ICN (nonce) size — equal to the block size. |
| `(*MGM) Overhead() int` | The configured tag size. |
| `(*MGM) Seal(dst, nonce, plaintext, additionalData []byte) []byte` | Encrypts and authenticates, appending `ciphertext‖tag` to `dst`. Panics on a wrong-length or top-bit-set nonce, on an all-empty `plaintext`+`additionalData`, or when a field exceeds the mode's length-block capacity. |
| `(*MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` | Verifies the tag and, on success, appends the recovered plaintext to `dst`. Returns an error (never partial plaintext) on any authentication failure. |

`*MGM` satisfies [`crypto/cipher.AEAD`](https://pkg.go.dev/crypto/cipher#AEAD)
(asserted at compile time: `var _ cipher.AEAD = (*MGM)(nil)`). It is **not
goroutine-safe** — a single `*MGM` reuses internal scratch buffers across
calls, so concurrent `Seal`/`Open` on the same value race.

## Usage

```go
import (
	"github.com/tarantool/go-gostcrypto/kuznyechik"
	"github.com/tarantool/go-gostcrypto/mgm"
)

aead, err := mgm.NewMGM(kuznyechik.NewCipher(key), 16) // full 16-byte tag
if err != nil {
	// handle invalid block size / tag size
}

nonce := make([]byte, aead.NonceSize()) // must have its top bit clear
// ... fill nonce, never reuse it under the same key ...

ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

recovered, err := aead.Open(nil, nonce, ciphertext, additionalData)
if err != nil {
	// authentication failed — discard, do not use recovered
}
```

The same `*MGM` value may be reused for multiple messages (its scratch buffers
are reset on each call), but never concurrently, and never with a repeated
nonce under the same key.

## Standards

- [RFC 9058](rfc/rfc9058.txt) — "Multilinear Galois Mode (MGM)".
- [R 1323565.1.026-2019](rfc/R1323565.1.026-2019.pdf) — the Russian
  recommendation defining MGM and its worked KATs (Kuznyechik and Magma, §A).
- [RFC 7801](../kuznyechik/rfc/rfc7801.txt) / [RFC 8891](../magma/rfc/rfc8891.txt)
  — the Kuznyechik and Magma block ciphers MGM drives.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

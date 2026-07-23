# streebog — Streebog Hash Function (GOST R 34.11-2012)

`package streebog` is the Russian national cryptographic hash function
standardised as **GOST R 34.11-2012** and republished as **RFC 6986**. It
produces either a 256-bit or a 512-bit digest; both variants share the entire
compression machinery and differ only in the initialization vector and a
final truncation.

Import path: `github.com/tarantool/go-gostcrypto/streebog`

## API

| Symbol | Description |
|---|---|
| `New256() hash.Hash` | Returns a fresh Streebog-256 hash state (32-byte digest). |
| `New512() hash.Hash` | Returns a fresh Streebog-512 hash state (64-byte digest). |
| `Sum256(b []byte) [32]byte` | One-shot Streebog-256 digest of `b`. |
| `Sum512(b []byte) [64]byte` | One-shot Streebog-512 digest of `b`. |
| `(hash.Hash) Write(p []byte) (int, error)` | Streaming input; any chunking produces the same digest. |
| `(hash.Hash) Sum(b []byte) []byte` | Appends the digest to `b`. Non-destructive — the hash may be written to again afterwards. |
| `(hash.Hash) Reset()` / `BlockSize()` / `Size()` | Standard `hash.Hash` metadata: `BlockSize()` is always `64`; `Size()` is `32` or `64` depending on which constructor built the state. |

Both `New256()` and `New512()` return a type that satisfies
[`hash.Hash`](https://pkg.go.dev/hash#Hash) (asserted at compile time:
`var _ hash.Hash = New256()`, `var _ hash.Hash = New512()`), so either drops
directly into `crypto/hmac.New` or any other API built against that
interface.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/streebog"

// One-shot.
digest256 := streebog.Sum256([]byte("hello"))
digest512 := streebog.Sum512([]byte("hello"))

// Streaming, e.g. for HMAC.
h := streebog.New256()
h.Write([]byte("hello, "))
h.Write([]byte("world"))
sum := h.Sum(nil) // 32 bytes

hm := hmac.New(streebog.New256, key)
```

## Standards

- [RFC 6986](rfc/rfc6986.txt) — "GOST R 34.11-2012: Hash Function" (S-box π,
  permutation τ, linear matrix `A`, iteration constants `C_1..C_12`, the three
  compression transformations, and the three-stage hashing procedure).
- GOST R 34.11-2012 — the originating Russian national standard (equivalent
  to RFC 6986; no local copy of the Russian-language standard in this repo).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

# gostr341194 — GOST R 34.11-94 legacy hash (CryptoPro parameter set)

`package gostr341194` is the legacy Soviet/Russian 256-bit hash function GOST R
34.11-94 (RFC 5831), superseded by Streebog (GOST R 34.11-2012) but still
required for interop with older GOST deployments. It is built on the
GOST 28147-89 block cipher: the compression function keys four ECB
encryptions from the chaining value and message block, then applies a linear
mixing transform. This package implements the **CryptoPro parameter set**
variant — `id-GostR3411-94-CryptoProParamSet`, OID `1.2.643.2.2.30.1` — which
selects a specific S-box for the inner 28147 cipher and is the variant used on
the wire by Tarantool-EE.

Import path: `github.com/tarantool/go-gostcrypto/gostr341194`

## API

| Symbol | Description |
|---|---|
| `Size` | `32` — the digest length in bytes (256 bits). |
| `BlockSize` | `32` — the message block length in bytes (256 bits). |
| `New() hash.Hash` | Constructs a fresh GOST R 34.11-94 hash (CryptoPro parameter set). Fully implements [`hash.Hash`](https://pkg.go.dev/hash#Hash) — asserted at compile time (`var _ hash.Hash = New()`) — including a working `Reset`. |
| `(hash.Hash) Write(p []byte) (int, error)` | Feed message bytes. Streaming; any split of the input produces the same digest. |
| `(hash.Hash) Sum(b []byte) []byte` | Appends the 32-byte digest to `b` and returns it. Non-destructive — the hash may be written to again afterwards. |
| `(hash.Hash) Reset()` | Resets to the initial (empty-message) state. |
| `(hash.Hash) Size() int` / `BlockSize() int` | Both return `32`. |
| `Sum(b []byte) [Size]byte` | Package-level one-shot helper — hashes `b` and returns the fixed-size digest array directly. (Distinct from the `hash.Hash` method of the same name above; this one is a plain function, not a method, and returns an array rather than appending to a slice.) |

> **Empty-input note.** Hashing the empty message does not simply run the
> length/checksum finalization on an all-zero chaining value — this package
> inserts an extra compression step first, to match the reference GOST engine
> used by Tarantool rather than at least one other well-known Go
> implementation, which omits it and produces a different digest for `""`.
> Non-empty inputs are unaffected. See
> [DESIGN.md's implementation notes](DESIGN.md#implementation-notes) for
> details.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/gostr341194"

h := gostr341194.New()
h.Write([]byte("The quick brown fox jumps over the lazy dog"))
digest := h.Sum(nil) // 32 bytes

// or, one-shot:
sum := gostr341194.Sum(msg) // [32]byte
```

## Standards

- [RFC 5831](rfc/rfc5831.txt) — GOST R 34.11-94 hash function: §3 (byte ordering), §5 (compression function), §6 (main procedure).
- [RFC 4357](rfc/rfc4357.txt) §10.4 / §11.2 — hash algorithm OID (`id-GostR3411-94` = `1.2.643.2.2.9`) and the CryptoPro parameter-set OID/S-box (`id-GostR3411-94-CryptoProParamSet` = `1.2.643.2.2.30.1`).
- GOST R 34.11-94 — the Russian national standard itself (no local copy in this repo; RFC 5831 is its English republication).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

# kdftree — KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.4)

`package kdftree` implements `KDF_TREE_GOSTR3411_2012_256`, the counter-mode
key-derivation function built on HMAC over Streebog-256 (GOST R 34.11-2012,
256-bit output). It is defined in **RFC 7836 §4.4** (also Russian
recommendation **R 50.1.113-2016 §4.5**) and expands a derivation key plus a
`label`/`seed` pair into an arbitrary multiple-of-32-bytes run of keying
material.

Import path: `github.com/tarantool/go-gostcrypto/kdftree`

## API

| Symbol | Description |
|---|---|
| `KDFTree256(key, label, seed []byte, r, outLen int) []byte` | Derives `outLen` bytes of keying material from `key` (any length), `label`, and `seed`. `r` (1..4) is the width in bytes of the iteration counter; `outLen` must be positive and must not exceed what an `r`-byte counter can address (`32*(2^(8r)-1)` bytes). Panics on out-of-range `r`/`outLen`. |

`KDFTree256` is a plain deterministic function, not a stateful type — there is
no constructor and nothing to reset.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/kdftree"

// Split a 32-byte VKO-derived key into a 64-byte (cipher_key || mac_key) pair,
// as the keg package does for RFC 9367 key expansion.
label := []byte("kdf tree")
seed := ukm[16:24] // 8-byte seed slice

out := kdftree.KDFTree256(tmpKey, label, seed, 1, 64)
cipherKey, macKey := out[:32], out[32:]
```

For the common case (`r = 1`, `outLen` a positive multiple of 32) the
repo-root facade `gostcrypto.KDFTree2012_256(key, label, seed, keyOutLen)`
wraps this call with those constraints pre-validated.

## Standards

- [RFC 7836](rfc/rfc7836.txt) §4.4 — The Key Derivation Function `KDF_TREE_GOSTR3411_2012_256` (this package); §4.5 — the single-block `KDF_GOSTR3411_2012_256` special case.
- [RFC 6986](rfc/rfc6986.txt) — GOST R 34.11-2012 (Streebog), the hash underlying the HMAC core; see [`../streebog/DESIGN.md`](../streebog/DESIGN.md).
- [RFC 2104](rfc/rfc2104.txt) — HMAC construction (`ipad`/`opad`), instantiated here with Streebog-256.
- R 50.1.113-2016 §4.5 — Russian-language recommendation restating the same `KDF_TREE` definition (no local copy in this repo).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

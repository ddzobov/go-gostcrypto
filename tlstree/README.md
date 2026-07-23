# tlstree — TLSTree per-record key derivation (RFC 9189 §8.1)

`package tlstree` implements TLSTREE, the per-record key-diversification
function used by the GOST TLS 1.2 CTR-OMAC cipher suites (RFC 9189 §8.1 /
§8.1.1). Given a fixed 32-byte root key and a 64-bit TLS record sequence
number, it deterministically derives a fresh 32-byte per-record key by
chaining three `KDF_GOSTR3411_2012_256` (RFC 7836 §4.5) invocations, each
keyed on a progressively wider-masked slice of the sequence number. This
bounds how many records are ever protected under one leaf key: 64 for the
Kuznyechik suite, 4096 for the Magma suite.

Import path: `github.com/tarantool/go-gostcrypto/tlstree`

## API

| Symbol | Description |
|---|---|
| `KeySize` | `32` — size in bytes of the root key, every intermediate key, and the derived leaf key. |
| `NewTLSTreeKuznyechikCTROMAC(master []byte) *TLSTree` | Tree for suite `0xC100` (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`), window = 64 records. Panics unless `len(master) == 32`. |
| `NewTLSTreeMagmaCTROMAC(master []byte) *TLSTree` | Tree for suite `0xC101` (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`), window = 4096 records. Panics unless `len(master) == 32`. |
| `(*TLSTree) Derive(seqNum uint64) []byte` | Returns the 32-byte leaf key for the given TLS record sequence number. Always runs the full three-level KDF chain (no caching), so the very first call is correct for any `seqNum` — see the [DeriveCached gotcha](DESIGN.md#implementation-notes) this deliberately avoids. Each call returns a freshly allocated, non-aliasing slice. |

## Usage

```go
import "github.com/tarantool/go-gostcrypto/tlstree"

tree := tlstree.NewTLSTreeKuznyechikCTROMAC(rootKey) // rootKey must be 32 bytes

key := tree.Derive(seqNum) // 32-byte per-record key for TLS record seqNum
```

A record protector typically owns two trees per direction — one for the
bulk-cipher key, one for the OMAC key — and calls `Derive(seqNum)` once per
record. See the CTR half in
[`../ctracpkm/DESIGN.md`](../ctracpkm/DESIGN.md) and the MAC half in
[`../omac/DESIGN.md`](../omac/DESIGN.md).

## Standards

- [RFC 9189](rfc/rfc9189.txt) §8.1 / §8.1.1 — TLSTREE definition, the `KDF_1/2/3` chain, and the per-suite `C_1/C_2/C_3` mask constants (including the official Appendix A.1.1 test vectors).
- [RFC 7836](rfc/rfc7836.txt) §4.5 — `KDF_GOSTR3411_2012_256`, the single-block KDF each tree level calls.
- [RFC 6986](rfc/rfc6986.txt) — GOST R 34.11-2012 (Streebog-256), the hash underlying the HMAC that `KDF_GOSTR3411_2012_256` uses.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

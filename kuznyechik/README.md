# kuznyechik — Kuznyechik (Grasshopper) block cipher (GOST R 34.12-2015 / RFC 7801)

`package kuznyechik` is the 128-bit Kuznyechik block cipher: a pure-Go,
clean-room implementation of the Russian national standard **GOST R
34.12-2015**, republished in English as **RFC 7801**. It is a plain block
transform — CTR, OMAC/CMAC, MGM, ACPKM and key-export modes are layered on top
by other packages in this module.

Import path: `github.com/tarantool/go-gostcrypto/kuznyechik`

## API

| Symbol | Description |
|---|---|
| `BlockSize` | `16` — the block size in bytes (128 bits). |
| `NewCipher(key []byte) *Cipher` | Table-driven cipher. Panics unless `len(key) == 32`. Fast, but table-lookup timing is secret-dependent — see [SECURITY.md](SECURITY.md). |
| `NewCipherCT(key []byte) *Cipher` | Constant-time cipher: same key/size contract as `NewCipher`, but `Encrypt`/`Decrypt` and the key schedule touch no secret-indexed memory. ~36× slower. |
| `(*Cipher) BlockSize() int` | Returns `16`. |
| `(*Cipher) Encrypt(dst, src []byte)` | Encrypts one 16-byte block. Panics if `src`/`dst` is shorter than `BlockSize`. |
| `(*Cipher) Decrypt(dst, src []byte)` | Decrypts one 16-byte block. Same length contract as `Encrypt`. |
| `(*Cipher) EncryptBlocks(dst, src []byte)` | Encrypts `len(src)/BlockSize` consecutive blocks; output always equals successive `Encrypt` calls. Panics on a non-whole-block length or an invalid `dst`/`src` overlap. Portable — on every build it falls back to the per-block loop; on `amd64` with `GOEXPERIMENT=simd` it batches through a data-oblivious SIMD engine instead (see [EXPERIMENT-simd.md](EXPERIMENT-simd.md)). |
| `(*Cipher) CTRXORBlocks(dst, src, iv []byte)` | Fused, constant-time CTR-keystream XOR. Only compiled under `//go:build goexperiment.simd && amd64`; absent from every default build. See [EXPERIMENT-simd.md](EXPERIMENT-simd.md). |

`*Cipher` satisfies [`crypto/cipher.Block`](https://pkg.go.dev/crypto/cipher#Block)
(asserted at compile time: `var _ cipher.Block = (*Cipher)(nil)`), so it drops
into any mode package built against that interface.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/kuznyechik"

c := kuznyechik.NewCipher(key) // key must be 32 bytes

ciphertext := make([]byte, kuznyechik.BlockSize)
c.Encrypt(ciphertext, plaintext) // plaintext must be 16 bytes

recovered := make([]byte, kuznyechik.BlockSize)
c.Decrypt(recovered, ciphertext)
```

`Cipher` is a raw single-block primitive — for a real message, wrap it in a
mode: `ctracpkm` for CTR-ACPKM keystream encryption, `omac` for CMAC
authentication, `mgm` for MGM AEAD, or `kexp15`/`keg` for GOST TLS key export.
If a local cache-timing adversary is in scope, use `NewCipherCT` instead of
`NewCipher`; see [SECURITY.md](SECURITY.md) for the trade-off.

## Standards

- [RFC 7801](rfc/rfc7801.txt) — "GOST R 34.12-2015: Block Cipher 'Kuznyechik'" — the primary specification implemented here.
- GOST R 34.12-2015 — the Russian national standard itself; RFC 7801 is its English republication (no local copy of the Russian-language standard in this repo).
- [RFC 9367](rfc/rfc9367.txt) §4.3 — defines TLS suite `0xC100` (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`), the module's main consumer of this cipher.
- [RFC 9189](rfc/rfc9189.txt) — GOST cipher suites for TLS 1.2 (key-export context for the Kuznyechik usage in `kexp15`/`keg`).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.
- [SECURITY.md](SECURITY.md) — why the default `NewCipher` is not constant-time, and the constant-time `NewCipherCT` alternative.
- [EXPERIMENT-simd.md](EXPERIMENT-simd.md) — the experimental AVX2 batch-encrypt and CTR-keystream engine behind `EncryptBlocks`/`CTRXORBlocks`.

# ctracpkm — CTR mode + ACPKM key meshing (RFC 8645)

`package ctracpkm` implements GOST R 34.13-2015 CTR ("gamma counter") mode and
layers the RFC 8645 ACPKM intra-record key-meshing mechanism on top of it. It
turns any [`crypto/cipher.Block`](https://pkg.go.dev/crypto/cipher#Block) into
a [`crypto/cipher.Stream`](https://pkg.go.dev/crypto/cipher#Stream), so it
works with both Kuznyechik and Magma.

Import path: `github.com/tarantool/go-gostcrypto/ctracpkm`

## API

| Symbol | Description |
|---|---|
| `NewCTR(b cipher.Block, iv []byte) cipher.Stream` | Plain CTR keystream generator. `iv` is the full block-size counter, already assembled (nonce in the high half, zeros in the low half). Panics unless `len(iv) == b.BlockSize()`. |
| `NewCTRACPKM(newBlock func(key []byte) cipher.Block, key, iv []byte, sectionSize int) cipher.Stream` | CTR with RFC 8645 ACPKM re-keying. `newBlock` rebuilds the cipher from each re-derived 32-byte section key; `key` (the master key) must be 32 bytes. `sectionSize` must be `0` (disables ACPKM, degrading to plain CTR) or a positive multiple of `newBlock(key).BlockSize()`. Panics on any violated precondition. |
| `SectionKuznyechik`, `SectionMagma` | `4096` and `1024` — the RFC 9367 TLS per-suite ACPKM section sizes for Kuznyechik-CTR-OMAC (`0xC100`) and Magma-CTR-OMAC (`0xC101`). |
| `CTR` | The concrete stream type both constructors return as `cipher.Stream`; callers do not normally name it directly. `*CTR` implements `cipher.Stream` (`XORKeyStream`), asserted at compile time in the package. |

`XORKeyStream` may be called repeatedly; a split call sequence produces the
same output as a single one-shot call over the concatenated input (the
partial-block offset is carried across calls).

## Usage

```go
import (
	"crypto/cipher"

	"github.com/tarantool/go-gostcrypto/ctracpkm"
	"github.com/tarantool/go-gostcrypto/kuznyechik"
)

newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }

// iv is 16 bytes: an 8-byte nonce in the high half, zeros in the low half.
stream := ctracpkm.NewCTRACPKM(newBlock, key, iv, ctracpkm.SectionKuznyechik)

ciphertext := make([]byte, len(plaintext))
stream.XORKeyStream(ciphertext, plaintext)
```

For plain CTR with no re-keying, build the block cipher once and call
`ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv)` instead — `NewCTRACPKM(...,
0)` is equivalent.

## Standards

- [RFC 8645](rfc/rfc8645.txt) — Re-keying Mechanisms for Symmetric Keys: §6.2.1 (ACPKM transformation), §6.3.1 (ACPKM-Master).
- [GOST R 34.13-2015](rfc/GOST_R_34.13-2015.pdf) §5.3 — CTR (gamma counter) mode, plus the Kuznyechik (A.1.2) and Magma (A.2.2) known-answer tests.
- [R 1323565.1.017-2018](rfc/R1323565.1.017-2018.pdf) — TC26 cryptographic mechanisms; source of the ACPKM `D` constant and Appendix A.1/A.4.2 CTR-ACPKM/ACPKM-Master end-to-end vectors.
- [RFC 9367](rfc/rfc9367.txt) — GOST cipher suites for TLS 1.2; defines the `0xC100`/`0xC101` suites that this package's `SectionKuznyechik`/`SectionMagma` constants are sized for.
- [RFC 4357](rfc/rfc4357.txt) — CryptoPro cryptographic algorithms; describes a *different* re-keying scheme (CryptoPro key meshing) that this package does not implement — see [DESIGN.md](DESIGN.md) for the distinction.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

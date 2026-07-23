# gost28147cnt — GOST 28147-89 CNT (Counter/Gamma) Stream Mode (RFC 5830 §6)

`package gost28147cnt` is the *gammirovaniye* (counter/gamma) stream mode of
the GOST 28147-89 64-bit block cipher. A keystream ("gamma") is produced by
ECB-encrypting a counter that is advanced by two fixed additive constants
between blocks; the gamma is XORed with the plaintext. Encryption and
decryption are the same operation. It layers over the sibling
[`gost28147`](../gost28147) block cipher and additionally implements the
CryptoPro key-meshing extension (RFC 4357 §2.3.2) required by the TLS GOST
cipher suites.

Import path: `github.com/tarantool/go-gostcrypto/gost28147cnt`

## API

| Symbol | Description |
|---|---|
| `NewCNT(c *gost28147.Cipher, iv []byte) *CNT` | Construct a CNT keystream generator over the given block cipher and an 8-byte IV (the synchro value). Panics unless `len(iv) == 8`. The cipher's S-box (via `c.SBox()`) is reused automatically when key meshing re-keys the cipher. |
| `(*CNT) XORKeyStream(dst, src []byte)` | XORs `src` into `dst` using the CNT keystream, advancing the generator state. `dst` may overlap `src` exactly (or not at all). Panics if `dst` is shorter than `src`. Output length equals input length — CNT is a stream mode with no padding. |

`*CNT` matches the single-method shape of
[`crypto/cipher.Stream`](https://pkg.go.dev/crypto/cipher#Stream), so it drops
into any code written against that interface. State (the counter, the
partial-gamma offset, and the CryptoPro meshing byte counter) persists across
`XORKeyStream` calls — construct one `*CNT` per connection/message, not per
call, and stream an arbitrary byte sequence through it in any number of calls
at any split points; the result is identical to a single call over the
concatenated input.

## Usage

```go
import (
	"github.com/tarantool/go-gostcrypto/gost28147"
	"github.com/tarantool/go-gostcrypto/gost28147cnt"
)

c := gost28147.NewCipher(key, gost28147.SboxCryptoProA) // key must be 32 bytes
stream := gost28147cnt.NewCNT(c, iv)                    // iv must be 8 bytes

ciphertext := make([]byte, len(plaintext))
stream.XORKeyStream(ciphertext, plaintext)
```

The root `gostcrypto` facade also exposes this mode directly as
`NewGOST28147_CNT(key, iv []byte) (cipher.Stream, error)`, fixed to the
CryptoPro-A S-box.

## Standards

- [RFC 5830](rfc/rfc5830.txt) §6 — "Counter Mode" (*gammirovaniye*): the gamma generation algorithm and the C1/C2 constants (Appendix A).
- [RFC 4357](rfc/rfc4357.txt) §2.3.2 — CryptoPro key meshing (the 1024-byte re-keying extension mandated by the TLS GOST suites).
- [RFC 9189](rfc/rfc9189.txt) §4 — GOST cipher suites for TLS 1.2 that pair this mode with the GOST 28147-89 IMIT MAC.
- GOST 28147-89 — the underlying Soviet/Russian block cipher standard (see the sibling [`gost28147`](../gost28147) package).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

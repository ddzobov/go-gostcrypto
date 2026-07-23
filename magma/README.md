# magma — Magma 64-bit block cipher (GOST R 34.12-2015 / RFC 8891)

`package magma` is the 64-bit Magma block cipher: a pure-Go, clean-room
implementation of the Russian national standard **GOST R 34.12-2015**,
republished in English as **RFC 8891**. It is a plain block transform — CTR,
OMAC/CMAC, MGM and key-export modes are layered on top by other packages in
this module.

Import path: `github.com/tarantool/go-gostcrypto/magma`

## API

| Symbol | Description |
|---|---|
| `BlockSize` | `8` — the block size in bytes (64 bits). |
| `KeySize` | `32` — the key size in bytes (256 bits). |
| `NewCipher(key []byte) *Cipher` | Constructs a `Cipher` from a 32-byte key. Panics unless `len(key) == 32`. |
| `(*Cipher) Encrypt(dst, src []byte)` | Encrypts one 8-byte block. Panics if `src`/`dst` is shorter than `BlockSize`. Safe to call in place (`Encrypt(buf, buf)`). |
| `(*Cipher) Decrypt(dst, src []byte)` | Decrypts one 8-byte block using the reversed subkey schedule. Same length contract as `Encrypt`; safe in place. |
| `(*Cipher) BlockSize() int` | Returns `8`. |
| `MagmaEncrypt(key, pt []byte) []byte` | Convenience one-shot: constructs a `Cipher` and encrypts a single block. |
| `MagmaDecrypt(key, ct []byte) []byte` | Convenience one-shot: constructs a `Cipher` and decrypts a single block. |

`*Cipher` satisfies [`crypto/cipher.Block`](https://pkg.go.dev/crypto/cipher#Block)
(asserted at compile time in `guard_test.go`: `var _ cipher.Block = (*magma.Cipher)(nil)`),
so it drops into any mode package built against that interface. Unlike the
underlying `gost28147` core, Magma fixes its S-box — `NewCipher` takes no
S-box parameter.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/magma"

c := magma.NewCipher(key) // key must be 32 bytes

ciphertext := make([]byte, magma.BlockSize)
c.Encrypt(ciphertext, plaintext) // plaintext must be 8 bytes

recovered := make([]byte, magma.BlockSize)
c.Decrypt(recovered, ciphertext)
```

`Cipher` is a raw single-block primitive — for a real message, wrap it in a
mode: `ctracpkm` for CTR-ACPKM keystream encryption, `omac` for CMAC
authentication, `mgm` for MGM AEAD, or `kexp15`/`keg` for GOST TLS key export.

## Standards

- [RFC 8891](rfc/rfc8891.txt) — "GOST R 34.12-2015: Block Cipher 'Magma'" — the primary specification implemented here.
- GOST R 34.12-2015 — the Russian national standard itself; RFC 8891 is its English republication (no local copy of the Russian-language standard in this repo).
- [RFC 5830](../gost28147/rfc/rfc5830.txt) — GOST 28147-89, the legacy Feistel core Magma is built on (little-endian numbering; see [`../gost28147/DESIGN.md`](../gost28147/DESIGN.md)).
- [RFC 4357](../gost28147/rfc/rfc4357.txt) §2 — S-box parameter sets and OIDs; Magma fixes the tc26-Z set (`id-tc26-gost-28147-param-Z`, OID `1.2.643.7.1.2.5.1.1`).
- [RFC 9189](../gost28147cnt/rfc/rfc9189.txt) §4.4 — GOST cipher suites for TLS 1.2, including the Magma-CTR-OMAC suite (`0xC101`).
- [RFC 9367](../kuznyechik/rfc/rfc9367.txt) — GOST cipher suites for TLS 1.2 (additional): suite `0xC101` `GOST2012-MAGMA-MAGMAOMAC`, GOST18 key transport, ACPKM.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

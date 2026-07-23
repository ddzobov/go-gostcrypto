# gost28147 — GOST 28147-89 block cipher (RFC 5830)

`package gost28147` is the 64-bit-block, 256-bit-key GOST 28147-89 Feistel
block cipher core: the key schedule, the round function, the 32-round
encrypt/decrypt schedule, and the two named S-box parameter sets. It is a
plain block transform — the CNT counter stream, IMIT MAC, and CryptoPro key
wrap are layered on top by other packages in this module. GOST 28147-89 is
distinct from its 2015 re-standardization "Magma" (fixed S-box, big-endian
block convention), which lives in `package magma`.

Import path: `github.com/tarantool/go-gostcrypto/gost28147`

## API

| Symbol | Description |
|---|---|
| `BlockSize` | `8` — the block size in bytes (64 bits). |
| `KeySize` | `32` — the key size in bytes (256 bits). |
| `SBox` | `[8][16]byte` — eight rows of sixteen nibbles; row `i` substitutes nibble `i` of a 32-bit word (row 0 = lowest nibble). |
| `SboxCryptoProA` | `id-Gost28147-89-CryptoPro-A-ParamSet` (OID `1.2.643.2.2.31.1`). |
| `SboxTC26Z` | `id-tc26-gost-28147-param-Z` (OID `1.2.643.7.1.2.5.1.1`). |
| `NewCipher(key []byte, sbox SBox) *Cipher` | Builds a `Cipher` from a 32-byte key and an S-box. Panics unless `len(key) == 32`. |
| `(*Cipher) Encrypt(dst, src []byte)` | Encrypts one 8-byte block. Panics if `src`/`dst` is shorter than `BlockSize`. Safe to call in place (`Encrypt(buf, buf)`). |
| `(*Cipher) Decrypt(dst, src []byte)` | Decrypts one 8-byte block using the reversed key schedule. Same length contract as `Encrypt`; safe in place. |
| `(*Cipher) BlockSize() int` | Returns `8`. |
| `(*Cipher) SBox() SBox` | Returns the S-box the cipher was constructed with — used by streaming modes (e.g. `gost28147cnt`) to rebuild the cipher during CryptoPro key meshing. |

`*Cipher` satisfies [`crypto/cipher.Block`](https://pkg.go.dev/crypto/cipher#Block)
(asserted at compile time in `guard_test.go`: `var _ cipher.Block = (*gost28147.Cipher)(nil)`),
so it drops into any mode package built against that interface.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/gost28147"

c := gost28147.NewCipher(key, gost28147.SboxCryptoProA) // key must be 32 bytes

ciphertext := make([]byte, gost28147.BlockSize)
c.Encrypt(ciphertext, plaintext) // plaintext must be 8 bytes

recovered := make([]byte, gost28147.BlockSize)
c.Decrypt(recovered, ciphertext)
```

`Cipher` is a raw single-block primitive — for a real message, wrap it in a
mode: `gost28147cnt` for the CNT counter/gamma stream, `gost28147imit` for the
IMIT MAC, or `keywrap` for the CryptoPro key wrap. Use `SboxCryptoProA` for
GOST 2001 suites and `SboxTC26Z` for GOST 2012 suites, matching the S-box
selection this module's root facade applies per suite.

## Standards

- [RFC 5830](rfc/rfc5830.txt) — GOST 28147-89 encryption, decryption, and MAC algorithms: §4 (substitution box, round function), §5 (ECB / 32-round schedule), §8 (16-round IMIT MAC generation).
- [RFC 4357](rfc/rfc4357.txt) §2 — S-box parameter sets and OIDs (CryptoPro-A, tc26-Z); §2.3.2 CryptoPro key meshing.
- [RFC 9189](rfc/rfc9189.txt) — GOST cipher suites for TLS 1.2 (context for the S-box selection per suite and IMIT-4 truncation).
- [RFC 5831](rfc/rfc5831.txt) — GOST R 34.11-94 hash function (context for the related, but separate, R34.11-94-CryptoPro S-box).

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

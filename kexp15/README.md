# kexp15 — KExp15 key-export envelope (R 1323565.1.017-2018)

`package kexp15` implements KExp15, the GOST key-transport envelope that wraps
a shared secret for authenticated, encrypted transport under two independent
export keys: `CEK_MAC = OMAC(K_Exp_MAC, IV || S)`, then
`SExp = CTR-Encrypt(K_Exp_ENC, IV, S || CEK_MAC)`. It layers the sibling
[`omac`](../omac/README.md) and [`ctracpkm`](../ctracpkm) packages over
Kuznyechik or Magma. Only the export (wrap) direction is implemented; KImp15
(unwrap) is out of scope.

Import path: `github.com/tarantool/go-gostcrypto/kexp15`

## API

| Symbol | Description |
|---|---|
| `type KexpVariant int` | Selects the underlying R 34.12-2015 block cipher. |
| `KexpKuznyechik` | 128-bit-block variant: `iv_len=8`, `mac_len=16`, `block=16`. RFC 9189 suite `0xC100` (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`). |
| `KexpMagma` | 64-bit-block variant: `iv_len=4`, `mac_len=8`, `block=8`. RFC 9189 suite `0xC101` (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`). |
| `Kexp15(variant KexpVariant, sharedKey, cipherKey, macKey, iv []byte) ([]byte, error)` | Wraps `sharedKey` (`S`) under the independent export keys `cipherKey` (`K_Exp_ENC`, CTR) and `macKey` (`K_Exp_MAC`, OMAC), with the half-block `iv`. Returns `len(sharedKey)+mac_len` bytes. `cipherKey`/`macKey` must be 32 bytes each, `iv` must be `block/2` bytes (8 for Kuznyechik, 4 for Magma), and `sharedKey` must be non-empty; any violation returns an error. |

## Usage

```go
import (
	"github.com/tarantool/go-gostcrypto/kexp15"
)

wrapped, err := kexp15.Kexp15(kexp15.KexpKuznyechik, sharedKey, cipherKey, macKey, iv)
if err != nil {
	// handle error
}
// wrapped is len(sharedKey)+16 bytes: CTR-Encrypt(cipherKey, iv||0*8, sharedKey || OMAC(macKey, iv||sharedKey))
```

`cipherKey` and `macKey` must each be independent 32-byte keys; reusing an
`iv` across two wraps under the same key pair breaks the construction's
security guarantee (RFC 9189 §8.2.1).

## Standards

- [R 1323565.1.017-2018](rfc/R1323565.1.017-2018.pdf) — the TC26 recommendation defining KExp15 / KImp15.
- [RFC 9189](rfc/rfc9189.txt) §8.2.1 — "KExp15 and KImp15 algorithms", the GOST 2012 TLS 1.2 construction (suites `0xC100`/`0xC101`).
- [RFC 9367](rfc/rfc9367.txt) — the GOST TLS 1.3 specification; noted here because it does **not** use KExp15 (its suites `0xC103`–`0xC106` use MGM AEAD key-share instead).
- [RFC 4493](rfc/rfc4493.txt) — the AES-CMAC algorithm, the OMAC1/CMAC construction this envelope calls.
- [RFC 8645](rfc/rfc8645.txt) — re-keying mechanisms for symmetric keys; fixes the 64-bit CMAC reduction constant `Rb = 0x1b` used for the Magma variant.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

# keywrap — CryptoPro Key Wrap (RFC 4357 §6.3 / §6.5)

`package keywrap` wraps a 32-byte GOST 28147-89 session key (the CEK) under a
32-byte key-encryption key (the KEK), producing the 44-byte CryptoPro key-wrap
blob defined in RFC 4357 §6.3. It composes the CryptoPro KEK diversification
step (§6.5) with a GOST 28147-89 ECB encrypt and IMIT MAC over the diversified
key. This is the key-transport primitive behind the TLS 1.2 GOST cipher suites
whose key exchange is `GOST_KEY_TRANSPORT` (RFC 9189 §4.1).

Import path: `github.com/tarantool/go-gostcrypto/keywrap`

## API

| Symbol | Description |
|---|---|
| `Sbox` | Alias for [`gost28147.SBox`](../gost28147/README.md) — the 8×16 S-box the wrap, its diversification step, and its MAC all run under. |
| `SboxTC26Z` | `id-tc26-gost-28147-param-Z` (OID `1.2.643.7.1.2.5.1.1`) — re-exported from `gost28147`; use for GOST R 34.10-2012 certificates (TLS suites `0xFF85` / `0xC102`). |
| `SboxCryptoProA` | `id-Gost28147-89-CryptoPro-A-ParamSet` (OID `1.2.643.2.2.31.1`) — re-exported from `gost28147`; use for GOST R 34.10-2001 certificates (TLS suite `0x0081`). |
| `KeyWrapCryptoPro(sbox Sbox, kek, ukm, sessionKey []byte) ([]byte, error)` | Wraps `sessionKey` (32 bytes) under `kek` (32 bytes) with the given S-box and 8-byte `ukm`, per RFC 4357 §6.3. Returns the 44-byte `UKM(8) \| CEK_ENC(32) \| CEK_MAC(4)` blob. Returns an error (not a panic) on any wrong-sized argument. |
| `Diversify(sbox Sbox, kek, ukm []byte) []byte` | The CryptoPro KEK diversification step alone (RFC 4357 §6.5) — returns the 32-byte diversified key `KEK(UKM)`. Exposed for callers that need the intermediate key (e.g. test-vector cross-checks). Unlike `KeyWrapCryptoPro`, it **panics** on a wrong-sized `kek`/`ukm` rather than returning an error. |

There is no exported type: `keywrap` is a pair of pure functions over byte
slices, not a streaming accumulator. Key unwrap (RFC 4357 §6.4, the inverse
operation) is not implemented — this module only ever wraps, on the sending
side of `GOST_KEY_TRANSPORT`.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/keywrap"

// kek: 32-byte KEK (e.g. the VKO-derived shared secret)
// ukm: 8-byte user keying material (e.g. the first 8 bytes of client_random)
// sessionKey: 32-byte CEK (e.g. the TLS premaster secret)
wrapped, err := keywrap.KeyWrapCryptoPro(keywrap.SboxTC26Z, kek, ukm, sessionKey)
if err != nil {
	// handle wrong-sized input
}
// wrapped is 44 bytes: UKM(8) | CEK_ENC(32) | CEK_MAC(4)
```

Pick `SboxTC26Z` or `SboxCryptoProA` by the peer certificate's public-key
algorithm — see [DESIGN.md](DESIGN.md) for the selection rule.

## Standards

- [RFC 4357](rfc/rfc4357.txt) §6.3 — CryptoPro Key Wrap; §6.5 — CryptoPro KEK Diversification Algorithm; §1.1 — `gost28147IMIT` definition.
- [RFC 5830](rfc/rfc5830.txt) — GOST 28147-89 block cipher and IMIT MAC, the primitives this wrap builds on.
- [RFC 7836](rfc/rfc7836.txt) — VKO GOST R 34.10-2012, one of the two KEK sources feeding this wrap.
- [RFC 9189](rfc/rfc9189.txt) §4.1 — `GOST_KEY_TRANSPORT`, the TLS 1.2 key-exchange method this wrap implements; also the source of the S-box-by-certificate-type selection rule.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

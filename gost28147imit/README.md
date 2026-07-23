# gost28147imit — GOST 28147-89 IMIT MAC + CryptoPro key meshing (RFC 5830 / RFC 4357)

`package gost28147imit` computes the **IMIT** (имитовставка / "imitovstavka"),
the keyed message-authentication code defined inside GOST 28147-89 and
republished as RFC 5830 §8. It is a CBC-MAC built on a *16-round* truncation of
the GOST 28147-89 block transform, with CryptoPro key meshing (RFC 4357
§2.3.2) applied every 1024 processed bytes.

Import path: `github.com/tarantool/go-gostcrypto/gost28147imit`

## API

| Symbol | Description |
|---|---|
| `IMIT(key, msg []byte) []byte` | One-shot MAC: CryptoPro-A S-box, zero IV, CryptoPro key meshing, truncated to the 4-byte TLS tag length (RFC 9189 §4.2). `key` must be 32 bytes and `msg` non-empty; both violations panic. |
| `SeqMACBlock(key []byte, sbox gost28147.SBox, block []byte) []byte` | Runs the 16-round `SeqMAC` transform of one 8-byte block from a zero initial state, returning the 8-byte result. Exposes the 16-round step that the [`gost28147`](../gost28147) cipher's public `Encrypt`/`Decrypt` (always 32 rounds) cannot reach — used by callers that drive their own streaming IMIT (e.g. a TLS record protector) block-by-block. `key` must be 32 bytes, `block` exactly 8; both panic otherwise. |

There is no exported type: `gost28147imit` is a pair of pure functions, not a
streaming accumulator. `IMIT` is one-shot only, over the CryptoPro-A S-box; it
does not implement `hash.Hash` and has no `Write`/`Sum`/`Reset`. A caller that
needs a streaming MAC (persisting state across writes, or a different S-box)
drives `SeqMACBlock` directly and keeps its own chaining state, key-meshing
counter, and finalization logic — as the sibling `gostls` TLS module's record
protector does.

## Usage

```go
import "github.com/tarantool/go-gostcrypto/gost28147imit"

key := make([]byte, 32) // 32-byte GOST 28147-89 key
tag := gost28147imit.IMIT(key, message) // 4-byte TLS-truncated IMIT
```

For a non-default S-box, a non-zero IV, or persistence across multiple
messages (streaming), build the MAC from `SeqMACBlock` directly — see
[DESIGN.md](DESIGN.md) for the chaining, padding, and key-meshing rules that
must be reproduced around it.

## Standards

- [RFC 5830](rfc/rfc5830.txt) §8 — "Generation of an Imitovstavka (MAC)"; the IMIT construction over the GOST 28147-89 block core (§5–§7 of the same RFC).
- [RFC 4357](rfc/rfc4357.txt) §2.3.2 — CryptoPro key meshing; §6.3 — CryptoPro KEK wrap (the non-zero-IV IMIT use handled outside this package).
- [RFC 9189](rfc/rfc9189.txt) §4.2 — GOST cipher suites for TLS 1.2: the IMIT-4 truncation this package's `IMIT` implements.
- [RFC 5246](rfc/rfc5246.txt) §6.2.3.1 — TLS 1.2 per-record MAC input framing, assembled by the record-layer protector, not by this package.
- GOST 28147-89 — the Russian national standard itself, republished in English as RFC 5830.

## Documentation

- [DESIGN.md](DESIGN.md) — algorithm description, specification, implementation notes, and test vectors.

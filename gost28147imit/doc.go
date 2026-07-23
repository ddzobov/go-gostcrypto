// Package gost28147imit is a clean-room, pure-Go implementation of the GOST
// 28147-89 IMIT MAC (RFC 5830 §8) with CryptoPro key meshing (RFC 4357
// §2.3.2) and the gost-engine finalization order. It is built strictly from
// DESIGN.md (and its sibling cipher doc) without
// consulting gogost or any GOST implementation source.
//
// The IMIT is a CBC-MAC whose per-block transform is the GOST 28147-89
// encryption step truncated to 16 rounds (the SeqMAC schedule), with the
// MAC-specific "natural" octet ordering (no half-swap, unlike the 32-round
// cipher). The S-box constants are reused from the sibling cleanroom
// gost28147 package; the 16-round transform is implemented here directly
// because that package only exposes the 32-round Encrypt/Decrypt.
//
// # References
//
//   - RFC 5830: https://github.com/tarantool/go-gostcrypto/blob/master/gost28147imit/rfc/rfc5830.txt
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/gost28147imit/rfc/rfc4357.txt
package gost28147imit

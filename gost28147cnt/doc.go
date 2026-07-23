// Package gost28147cnt is a clean-room, pure-Go implementation of the GOST
// 28147-89 CNT (counter / gamma, *gammirovaniye*) stream mode, built strictly
// from DESIGN.md without consulting gogost,
// internal/gost, or tls/internal/record implementation source.
//
// CNT produces a keystream ("gamma") by ECB-encrypting a counter that is
// advanced by two fixed additive constants between blocks; the gamma is XORed
// with the plaintext. Encryption and decryption are the same operation
// (RFC 5830 §6). The underlying single-block ECB transform is reused from the
// sibling gost28147 package — CNT borrows only E_K(block)->block.
//
// This implementation supports arbitrary-length streaming across calls: the
// partial-block gamma tail is carried correctly between XORKeyStream calls,
// which is the whole point (the gogost gost28147.CTR cannot stream — see the
// guide's delta D4). CryptoPro key meshing (RFC 4357 §2.3.2) is applied every
// 1024 bytes of keystream, matching the TLS GOST suites.
//
// # References
//
//   - RFC 5830: https://github.com/tarantool/go-gostcrypto/blob/master/gost28147cnt/rfc/rfc5830.txt
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/gost28147cnt/rfc/rfc4357.txt
package gost28147cnt

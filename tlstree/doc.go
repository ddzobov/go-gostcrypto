// Package tlstree is a clean-room, pure-Go implementation of the TLSTREE
// per-record key-diversification function used by the GOST TLS 1.2
// CTR-OMAC cipher suites (RFC 9189 §8.1 / §8.1.1).
//
// Given a fixed 32-byte root key and a 64-bit TLS record sequence number i,
// TLSTREE deterministically derives a 32-byte per-record key by chaining three
// invocations of KDF_GOSTR3411_2012_256 (RFC 7836 §4.5), each level keyed on a
// progressively wider-masked slice of i:
//
//	K1 = KDF(K_root, "level1", STR_8(i & C_1))
//	K2 = KDF(K1,     "level2", STR_8(i & C_2))
//	K3 = KDF(K2,     "level3", STR_8(i & C_3))   // the result
//
// KDF_GOSTR3411_2012_256(K, label, seed) = HMAC_Streebog256(
//
//	K, 0x01 | label | 0x00 | seed | 0x01 | 0x00).
//
// The masks C_1/C_2/C_3 differ per suite (Kuznyechik vs Magma) and bound the
// number of records protected under one leaf key (64 for Kuznyechik, 4096 for
// Magma).
//
// This implementation is GPL-free: it imports only the clean-room
// streebog package and the Go standard library. It does NOT carry
// gogost's documented zero-key startup trap — a fresh Derive(seqNum) for any
// seqNum returns the correct leaf key on the first call.
//
// # References
//
//   - RFC 9189: https://github.com/tarantool/go-gostcrypto/blob/master/tlstree/rfc/rfc9189.txt
//   - RFC 7836: https://github.com/tarantool/go-gostcrypto/blob/master/tlstree/rfc/rfc7836.txt
package tlstree

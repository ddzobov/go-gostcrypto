// Package gostr341194 is a clean-room, pure-Go implementation of the
// GOST R 34.11-94 legacy hash function (CryptoPro parameter set), built
// strictly from DESIGN.md and RFC 5831 (§3/§5/§6) without
// consulting gogost, gost-engine, or internal/gost implementation source.
//
// It reuses the in-tree clean-room GOST 28147-89 block cipher
// (github.com/tarantool/go-gostcrypto/gost28147) for the inner ECB encryptions; it
// does NOT reimplement 28147. The hash CryptoPro S-box
// (id-GostR3411-94-CryptoProParamSet, OID 1.2.643.2.2.30.1) is a DIFFERENT
// table from the cipher S-boxes and is transcribed here from the guide.
//
// # Byte-order convention
//
// RFC 5831 §3 numbers symbols right-to-left: the rightmost byte of a 256-bit
// word is byte #1. This implementation stores every block so that array index i
// holds byte #(i+1), i.e. the message bytes are used in their natural order
// (no per-block reversal, no digest reversal). The transforms A, P, ψ and the
// constant C3 are defined directly on this numbering. This matches gogost /
// gost-engine output bit-for-bit on all non-empty inputs.
//
// # Empty-input behavior (guide D1)
//
// For an empty message, gogost and gost-engine DISAGREE. This implementation
// matches the gost-engine / Tarantool result (3f25bc1f…), NOT gogost
// (981e5f3c…): when the total length is zero it inserts an extra compression
// with the all-zero block before the length and checksum blocks.
//
// # References
//
//   - RFC 5831: https://github.com/tarantool/go-gostcrypto/blob/master/gostr341194/rfc/rfc5831.txt
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/gostr341194/rfc/rfc4357.txt
package gostr341194

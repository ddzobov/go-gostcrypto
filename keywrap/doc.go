// Package keywrap is a clean-room, pure-Go implementation of the CryptoPro
// KeyWrap algorithm together with the CryptoPro KEK diversification step
// (RFC 4357 §6.3 / §6.5). It is built strictly from
// DESIGN.md (and the cited RFCs) without consulting
// gogost, internal/gost, or the TLS record layer implementation.
//
// The wrap encrypts a 32-byte GOST 28147-89 session key (CEK) under a 32-byte
// key-encryption key (KEK) and produces a 44-byte blob laid out as
//
//	UKM(8) | CEK_ENC(32) | CEK_MAC(4)
//
// where CEK_ENC is the ECB encryption of CEK under the UKM-diversified key
// KEK(UKM), and CEK_MAC is the 4-byte GOST 28147-89 IMIT of CEK keyed with
// KEK(UKM) and started from the non-zero chaining state IV = UKM.
//
// The block cipher, its S-boxes, and CFB feedback are reused from / mirror the
// sibling cleanroom gost28147 package; the IMIT here is implemented inline
// because the wrap MAC needs an arbitrary 8-byte initial state (IV = UKM), an
// arbitrary S-box, exactly four full blocks, and NO key meshing or zero
// padding block — none of which the sibling gost28147imit.IMIT entry point
// exposes (guide §D5).
//
// # References
//
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/keywrap/rfc/rfc4357.txt
package keywrap

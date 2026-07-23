// Package kdftree implements KDF_TREE_GOSTR3411_2012_256, the counter-mode
// key-derivation function defined in RFC 7836 §4.4 (also R 50.1.113-2016 §4.5),
// built on HMAC over Streebog-256 (GOST R 34.11-2012, 256-bit output).
//
// This is a clean-room implementation built strictly from
// DESIGN.md and the cited RFCs. It reuses the
// sibling clean-room Streebog-256 hash (github.com/tarantool/go-gostcrypto/streebog)
// and the standard library crypto/hmac. It contains no GOST-licensed code and
// no build tags.
//
// # References
//
//   - RFC 7836: https://github.com/tarantool/go-gostcrypto/blob/master/kdftree/rfc/rfc7836.txt
package kdftree

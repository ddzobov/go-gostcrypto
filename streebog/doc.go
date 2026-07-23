// Package streebog is a clean-room, pure-Go implementation of the Streebog
// hash function (GOST R 34.11-2012, RFC 6986) for both the 256-bit and
// 512-bit output variants.
//
// The implementation follows RFC 6986 directly. All 512-bit state vectors are
// held as little-endian byte buffers ([64]byte with index 0 == a_0, the least
// significant byte, matching the RFC's a_63||...||a_0 numbering reversed). The
// two output sizes share the entire compression machinery and differ only in
// the initialization vector and a final truncation.
//
// # References
//
//   - RFC 6986: https://github.com/tarantool/go-gostcrypto/blob/master/streebog/rfc/rfc6986.txt
package streebog

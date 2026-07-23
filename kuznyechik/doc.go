// Package kuznyechik is a clean-room pure-Go implementation of the
// Kuznyechik (GOST R 34.12-2015 / RFC 7801) 128-bit block cipher.
//
// It is derived solely from the specification in
// DESIGN.md (which republishes RFC 7801)
// and imports no GOST backend.
//
// # Side channels
//
// This implementation is table-driven and NOT constant-time: it indexes lookup
// tables by secret state bytes, exposing cache-timing side channels. This
// matches the gogost/gost-engine references and the software-AES norm. See
// SECURITY.md for the full timing model and why it is accepted for this
// reference cipher.
//
// # References
//
//   - RFC 7801: https://github.com/tarantool/go-gostcrypto/blob/master/kuznyechik/rfc/rfc7801.txt
package kuznyechik

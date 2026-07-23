// Package gost28147 is a clean-room, pure-Go implementation of the GOST
// 28147-89 block cipher core (ECB single-block encrypt/decrypt, 32-round),
// built strictly from DESIGN.md without consulting
// gogost or any GOST implementation source. No build tags, no gogost import.
//
// # References
//
//   - RFC 5830: https://github.com/tarantool/go-gostcrypto/blob/master/gost28147/rfc/rfc5830.txt
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/gost28147/rfc/rfc4357.txt
package gost28147

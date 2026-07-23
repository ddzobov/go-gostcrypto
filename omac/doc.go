// Package omac implements the GOST R 34.13-2015 MAC mode (OMAC1 / CMAC,
// RFC 4493 / NIST SP 800-38B) over any crypto/cipher.Block.
//
// CMAC is a CBC-MAC variant that fixes CBC-MAC's length-extension weakness
// by XORing the final block with one of two key-derived subkeys: K1 for a
// complete final block, K2 for a padded one. The construction is identical
// for both GOST block ciphers; only the block size, the GF(2^n) reduction
// constant Rb, and the (optionally truncated) tag length differ.
//
// This is a clean-room re-implementation from DESIGN.md plus
// RFC 4493; it imports no GOST backend and carries no build tags.
//
// # References
//
//   - RFC 4493: https://github.com/tarantool/go-gostcrypto/blob/master/omac/rfc/rfc4493.txt
//   - GOST R 34.13-2015: https://github.com/tarantool/go-gostcrypto/blob/master/omac/rfc/GOST_R_34.13-2015.pdf
package omac

// Package mgm implements the Multilinear Galois Mode (MGM) AEAD construction
// defined in RFC 9058 (and R 1323565.1.026-2019), the GOST analogue of
// AES-GCM. It works over any cipher.Block with a 64-bit (Magma) or 128-bit
// (Kuznyechik) block size.
//
// This is a clean-room implementation written from the RFC / guide only.
//
// # References
//
//   - RFC 9058: https://github.com/tarantool/go-gostcrypto/blob/master/mgm/rfc/rfc9058.txt
//   - R 1323565.1.026-2019: https://github.com/tarantool/go-gostcrypto/blob/master/mgm/rfc/R1323565.1.026-2019.pdf
package mgm

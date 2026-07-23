// Package gostcrypto provides pure-Go GOST cryptographic primitives and
// GOST-signed X.509 support.
//
// The package is a clean-room, BSD-2-Clause implementation with zero
// third-party dependencies (built with CGO_ENABLED=0). No GPL code is linked
// and none appears in this module's go.mod/go.sum.
//
// # Primitives
//
//   - Streebog (GOST R 34.11-2012, 256/512-bit) and legacy GOST R 34.11-94 hashes.
//   - Kuznyechik and Magma block ciphers (GOST R 34.12-2015) and GOST 28147-89.
//   - GOST R 34.10 sign/verify and VKO key agreement over the standard curves.
//   - Modes and MACs: CTR, CTR-ACPKM, OMAC, MGM, IMIT, KDFTree, TLSTree, KEG,
//     KExp15 and CryptoPro key wrap.
//
// The root gostcrypto package is a stable []byte-in/[]byte-out facade that
// delegates to the primitive subpackages. Those subpackages (streebog, kuznyechik,
// magma, …) are also importable directly for the idiomatic [crypto/cipher.Block]
// and [hash.Hash] APIs. GOST-signed X.509 parsing and verification lives in the
// [github.com/tarantool/go-gostcrypto/x509gost] package.
//
// # Quick Example
//
//	digest := gostcrypto.Streebog256([]byte("hello"))
//
//	ciphertext, err := gostcrypto.KuznyechikEncrypt(key, plaintext)
//	if err != nil {
//	    // handle error
//	}
//	plaintext, err = gostcrypto.KuznyechikDecrypt(key, ciphertext)
//
// GOST wire format is little-endian (LE(X)||LE(Y) public keys, s||r signatures)
// while the underlying math and the RFC tables are big-endian; the facade
// handles the conversion so callers work in the wire byte order throughout.
package gostcrypto

// Package keg implements KEG ("key export generation"), the GOST 2012 TLS 1.2
// key-derivation step from R 1323565.1.020-2018 §6.4.5.1, used by the RFC 9189 /
// RFC 9367 GOST cipher suites (engine function gost_keg).
//
// KEG turns a VKO Diffie-Hellman shared secret into the 64-byte symmetric key
// block that gost_kexp15 then uses to wrap the TLS pre-master secret. It produces
// only the key block; it does not do the wrapping.
//
// This is a clean-room implementation built strictly from
// DESIGN.md. It reuses the sibling clean-room packages vko
// (VKO 2012-256) and kdftree (KDF_TREE_GOSTR3411_2012_256) and imports
// no gogost code.
//
// # References
//
//   - RFC 9189: https://github.com/tarantool/go-gostcrypto/blob/master/keg/rfc/rfc9189.txt
//   - R 1323565.1.020-2018: https://github.com/tarantool/go-gostcrypto/blob/master/keg/rfc/R1323565.1.020-2018.pdf
package keg

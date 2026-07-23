// Package vko implements the VKO (ВКО) Diffie-Hellman-style key agreement
// for GOST elliptic-curve keys, in both the GOST R 34.10-2001 (RFC 4357 §5.2)
// and GOST R 34.10-2012 (RFC 7836 §4.3) flavours.
//
// One party combines its own private scalar d, the peer's public point Q, and
// a little-endian UKM integer into a single curve point, then hashes that
// point's coordinates (LE(X)||LE(Y)) to produce a Key Encryption Key (KEK).
// The agreement is symmetric: KEK(d_A, Q_B, UKM) == KEK(d_B, Q_A, UKM).
//
// This is a pure-Go, clean-room reimplementation built strictly from
// DESIGN.md. It reuses the sibling clean-room
// packages gost3410curves (curve arithmetic), streebog (GOST R 34.11-2012),
// and gostr341194 (GOST R 34.11-94 CryptoPro) and imports no gogost code.
//
// # References
//
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/vko/rfc/rfc4357.txt
//   - RFC 7836: https://github.com/tarantool/go-gostcrypto/blob/master/vko/rfc/rfc7836.txt
package vko

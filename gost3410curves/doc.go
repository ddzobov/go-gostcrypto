// Package gost3410curves is a clean-room implementation of the GOST R 34.10
// elliptic-curve parameter sets (CryptoPro 2001 + TC26 2012) and the core
// short-Weierstrass affine point arithmetic that consumes them.
//
// The parameters (p, a, b, q, x, y) are transcribed verbatim from
// DESIGN.md §2.4 (sourced from RFC 4357 §11 and
// RFC 7836 §5 / Appendix A). All constants are big-endian integers and are
// never byte-reversed: per §3.1 only key/signature *wire* serialization is
// little-endian, the curve constants stay big-endian.
//
// Twisted-Edwards sets (tc26-256-A, tc26-512-C) are stored in their
// birationally-equivalent short-Weierstrass form per §3.3 — the (e,d) pair is
// omitted since signature/VKO never touch it.
//
// # References
//
//   - RFC 4357: https://github.com/tarantool/go-gostcrypto/blob/master/gost3410curves/rfc/rfc4357.txt
//   - RFC 7836: https://github.com/tarantool/go-gostcrypto/blob/master/gost3410curves/rfc/rfc7836.txt
package gost3410curves

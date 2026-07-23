// Package gost3410sign is a clean-room implementation of the GOST R 34.10-2012
// (and the math-identical 34.10-2001) elliptic-curve digital signature
// algorithm: sign and verify over a short-Weierstrass GOST curve.
//
// It is implemented strictly from DESIGN.md and the
// RFCs it cites (RFC 7091 §6.1/§6.2 for the sign/verify equations, §5.3 for the
// big-endian hash-to-integer convention). It reuses the sibling clean-room
// package gost3410curves for all curve arithmetic (Curve, Point,
// ScalarMult, Base, IsOnCurve) and never imports gogost.
//
// Encoding conventions (the part most likely to bite, per the guide):
//
//   - Private key Raw: PointSize bytes, LITTLE-endian, reduced mod q on load.
//   - Public key Raw:  2·PointSize bytes, LE(X) || LE(Y).
//   - Signature Raw:   2·PointSize bytes, pad(s) || pad(r), each BIG-endian
//     within its half. Note: s FIRST, r SECOND (not the RFC's R||S writing).
//   - Digest:          read BIG-endian (big.Int.SetBytes of the bytes as-handed),
//     never byte-reversed.
//
// # References
//
//   - RFC 7091: https://github.com/tarantool/go-gostcrypto/blob/master/gost3410sign/rfc/rfc7091.txt
//   - RFC 5832: https://github.com/tarantool/go-gostcrypto/blob/master/gost3410sign/rfc/rfc5832.txt
package gost3410sign

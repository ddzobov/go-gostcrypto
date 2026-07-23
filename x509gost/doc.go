// Package x509gost provides GOST-aware X.509 certificate parsing and
// signature verification. It builds on the clean-room pure-Go primitives
// via the gostcrypto facade — no build tags, no third-party dependencies.
//
// # References
//
//   - RFC 9215: https://github.com/tarantool/go-gostcrypto/blob/master/x509gost/rfc/rfc9215.txt
//   - RFC 4491: https://github.com/tarantool/go-gostcrypto/blob/master/x509gost/rfc/rfc4491.txt
package x509gost

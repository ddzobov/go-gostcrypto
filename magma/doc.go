// Package magma is a clean-room implementation of the GOST R 34.12-2015
// 64-bit block cipher "Magma" (RFC 8891), built from the clean-room guide
// (DESIGN.md, colocated in this package) only.
//
// Magma is the GOST 28147-89 core pinned to:
//   - the fixed tc26 param-Z S-box, and
//   - RFC 8891's big-endian (MSB-first) byte/word numbering.
//
// The implementation realises the big-endian numbering exactly as the spec
// guide describes: reverse the four bytes within each key word (M1), reverse
// the whole 8-byte block on input and output (M2), and run an otherwise
// little-endian 28147-89 core with the tc26-Z S-box (M3).
//
// # References
//
//   - RFC 8891: https://github.com/tarantool/go-gostcrypto/blob/master/magma/rfc/rfc8891.txt
package magma

// Package kexp15 implements the GOST KExp15 key-export envelope
// (R 1323565.1.017-2018), as specified by RFC 9189 §8.2.1. The construction
// is OMAC-then-CTR:
//
//	CEK_MAC = OMAC(K_Exp_MAC, IV || S)      (truncated to mac_len)
//	SExp    = CTR-Encrypt(K_Exp_ENC, IV_full, S || CEK_MAC)
//
// It is pure Go: it sits on the clean-room sibling packages
// {omac,ctracpkm,kuznyechik,magma} and imports no gogost.
//
// # References
//
//   - RFC 9189: https://github.com/tarantool/go-gostcrypto/blob/master/kexp15/rfc/rfc9189.txt
//   - R 1323565.1.017-2018: https://github.com/tarantool/go-gostcrypto/blob/master/kexp15/rfc/R1323565.1.017-2018.pdf
package kexp15

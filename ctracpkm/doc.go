// Package ctracpkm implements GOST R 34.13-2015 CTR (gamma counter) mode and
// the RFC 8645 ACPKM intra-record key-meshing layered on top of it.
//
// This is a clean-room re-implementation built strictly from
// DESIGN.md plus the cited RFCs (RFC 8645, GOST R
// 34.13-2015). It imports no gogost and carries no build tags.
//
// CTR turns a block cipher into a stream cipher: each plaintext byte is XORed
// with a keystream ("gamma") byte produced by encrypting a monotonically
// increasing counter block. ACPKM re-derives the cipher key after every
// sectionSize bytes of keystream by encrypting the fixed public constant D
// under the current key. The counter is never reset by ACPKM — only the key
// changes.
//
// # Batched keystream
//
// When the block cipher implements EncryptBlocks(dst, src []byte) (e.g.
// kuznyechik.Cipher), full-block keystream runs are generated in one batched
// call instead of block by block. A cipher may additionally implement the fused
// CTRXORBlocks (the experimental SIMD Kuznyechik does), which generates the
// sliced counters and XORs the keystream in one pass — preferred when present.
// This is purely an internal optimisation: the output and the carried state are
// identical to the per-block path, the batch is bounded to the current ACPKM
// section so it never crosses a rekey, and it degrades to the per-block loop for
// partial gamma, short tails, and ciphers without the methods (e.g. Magma).
//
// # References
//
//   - RFC 8645: https://github.com/tarantool/go-gostcrypto/blob/master/ctracpkm/rfc/rfc8645.txt
//   - GOST R 34.13-2015: https://github.com/tarantool/go-gostcrypto/blob/master/ctracpkm/rfc/GOST_R_34.13-2015.pdf
package ctracpkm

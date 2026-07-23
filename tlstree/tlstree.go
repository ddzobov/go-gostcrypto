package tlstree

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/tarantool/go-gostcrypto/streebog"
)

// KeySize is the size in bytes of the root key, every intermediate key, and the
// derived leaf key. KDF_GOSTR3411_2012_256 always produces 256 bits.
const KeySize = 32

// Per-suite TLSTREE mask constants C_1/C_2/C_3 (RFC 9189 §8.1.1). Each masks
// off the low varying bits of the record sequence number at one chain level.
const (
	// Kuznyechik (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC, 0xC100).
	kuznyechikC1 = 0xFFFFFFFF00000000 // 32 low varying bits.
	kuznyechikC2 = 0xFFFFFFFFFFF80000 // 19 low varying bits.
	kuznyechikC3 = 0xFFFFFFFFFFFFFFC0 // 6 low varying bits, window = 64 records.

	// Magma (TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC, 0xC101).
	magmaC1 = 0xFFFFFFC000000000 // 38 low varying bits.
	magmaC2 = 0xFFFFFFFFFE000000 // 25 low varying bits.
	magmaC3 = 0xFFFFFFFFFFFFF000 // 12 low varying bits, window = 4096 records.
)

// KDF labels (RFC 9189 §8.1): the 6 ASCII bytes "levelN".
var (
	labelLevel1 = []byte("level1")
	labelLevel2 = []byte("level2")
	labelLevel3 = []byte("level3")
)

// TLSTree holds the root key and the three big-endian mask constants for a
// particular suite's constant set.
type TLSTree struct {
	root [KeySize]byte
	c1   uint64
	c2   uint64
	c3   uint64
}

// NewTLSTreeKuznyechikCTROMAC builds a TLSTree for the
// TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC suite (0xC100).
//
// Constants (RFC 9189 §8.1.1):
//
//	C_1 = 0xFFFFFFFF00000000  (32 low varying bits)
//	C_2 = 0xFFFFFFFFFFF80000  (19 low varying bits)
//	C_3 = 0xFFFFFFFFFFFFFFC0  (6 low varying bits, window = 64 records)
//
// master must be exactly 32 bytes; otherwise NewTLSTreeKuznyechikCTROMAC panics.
func NewTLSTreeKuznyechikCTROMAC(master []byte) *TLSTree {
	return newTree(master, kuznyechikC1, kuznyechikC2, kuznyechikC3)
}

// NewTLSTreeMagmaCTROMAC builds a TLSTree for the
// TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC suite (0xC101).
//
// Constants (RFC 9189 §8.1.1):
//
//	C_1 = 0xFFFFFFC000000000  (38 low varying bits)
//	C_2 = 0xFFFFFFFFFE000000  (25 low varying bits)
//	C_3 = 0xFFFFFFFFFFFFF000  (12 low varying bits, window = 4096 records)
//
// master must be exactly 32 bytes; otherwise NewTLSTreeMagmaCTROMAC panics.
func NewTLSTreeMagmaCTROMAC(master []byte) *TLSTree {
	return newTree(master, magmaC1, magmaC2, magmaC3)
}

func newTree(master []byte, c1, c2, c3 uint64) *TLSTree {
	if len(master) != KeySize {
		panic("tlstree: master key must be exactly 32 bytes")
	}

	t := &TLSTree{c1: c1, c2: c2, c3: c3}
	copy(t.root[:], master)

	return t
}

// Derive returns the 32-byte leaf key for the given TLS record sequence number.
//
// The result is a freshly allocated, non-aliasing slice on every call. This
// implementation always runs the full three-level KDF chain (no caching), so it
// is correct on the very first call for any seqNum — it does not reproduce
// gogost's zero-key startup trap.
func (t *TLSTree) Derive(seqNum uint64) []byte {
	var seed [8]byte

	binary.BigEndian.PutUint64(seed[:], seqNum&t.c1)

	k1 := kdf(t.root[:], labelLevel1, seed[:])

	binary.BigEndian.PutUint64(seed[:], seqNum&t.c2)

	k2 := kdf(k1[:], labelLevel2, seed[:])

	binary.BigEndian.PutUint64(seed[:], seqNum&t.c3)

	k3 := kdf(k2[:], labelLevel3, seed[:])

	out := make([]byte, KeySize)
	copy(out, k3[:])

	return out
}

// kdf computes KDF_GOSTR3411_2012_256(key, label, seed) (RFC 7836 §4.5):
//
//	HMAC_Streebog256(key, 0x01 | label | 0x00 | seed | 0x01 | 0x00)
//
// Because the requested output is 256 bits = one Streebog block, this is a
// single HMAC with the counter fixed at 0x01 and the length suffix 0x01 0x00
// (= L = 256 bits in network byte order, leading zero stripped).
func kdf(key, label, seed []byte) [KeySize]byte {
	h := hmac.New(streebog.New256, key)
	h.Write([]byte{0x01})
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(seed)
	h.Write([]byte{0x01, 0x00})

	var out [KeySize]byte

	copy(out[:], h.Sum(nil))

	return out
}

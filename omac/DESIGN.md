# OMAC1 / CMAC — GOST R 34.13-2015 MAC mode

This document describes the GOST MAC mode implemented by `package omac`: what it
is, its specification, the notable points of this implementation, and the test
vectors that pin it. For the public API and a usage example see the
[package README](README.md).

## What it is

GOST R 34.13-2015 **MAC mode** ("режим выработки имитовставки", §5.6) is exactly
**OMAC1 = CMAC** ([RFC 4493](rfc/rfc4493.txt), NIST SP 800-38B) instantiated with
a GOST block cipher instead of AES. It is a CBC-MAC variant that fixes CBC-MAC's
length-extension weakness by XORing the final block with one of two derived
subkeys (`K1` for a complete final block, `K2` for a padded one).

It is the **same algorithm for both ciphers**; only the block size, the GF
reduction constant `Rb`, and the (truncated) tag length differ:

| Quantity | Kuznyechik (Grasshopper) | Magma |
|---|---|---|
| Block size `n` | 16 bytes (128 bit) | 8 bytes (64 bit) |
| Key size | 32 bytes (256 bit) | 32 bytes (256 bit) |
| `Rb` (GF reduction) | `0x87` | `0x1b` |
| Full CMAC width | 16 bytes | 8 bytes |
| Truncated tag (TLS/std) | 8 bytes (CTR-OMAC) / 16 | 4 bytes (KAT) / 8 |

The mode is plain CMAC with truncation: the reference gost-engine computes it
through OpenSSL's standard `CMAC_*` routines and truncates the result.

### Where this module uses it

- **TLS record protection for [RFC 9189](../tlstree/rfc/rfc9189.txt) GOST
  suites** — Kuznyechik-CTR-OMAC (`0xC100`) and Magma-CTR-OMAC (`0xC101`). The
  per-record protector uses the **full** block width (`16` for Kuznyechik, `8`
  for Magma). See the CTR half in [`../ctracpkm/DESIGN.md`](../ctracpkm/DESIGN.md).
- **kexp15 key-export wrapper** — computes `mac = OMAC(mac_key, iv || shared_key)`
  truncated to `macLen`, then CTR-encrypts `shared_key || mac`. See
  [`../kexp15/DESIGN.md`](../kexp15/DESIGN.md).

## Specification

### CMAC subkey derivation (RFC 4493 §2.3)

Two subkeys `K1`, `K2` are derived from the cipher key before processing any
message. Let `E_K` be the block cipher under key `K`, `n` the block size in
bits, `0^n` the all-zero block, and `Rb` the per-block-size GF(2^n) reduction
constant ([RFC 4493](rfc/rfc4493.txt) §2.3, "Subkey Generation Algorithm"):

```
1.  L = E_K(0^n)
2.  if MSB(L) == 0  then  K1 = L << 1
    else                  K1 = (L << 1) XOR Rb
3.  if MSB(K1) == 0 then  K2 = K1 << 1
    else                  K2 = (K1 << 1) XOR Rb
```

`<<` is a **left shift of the whole block treated as one big-endian bit string**
(MSB = the most-significant bit of byte 0). `MSB(X)` is that same leading bit.
`Rb` is a small constant XORed into the **last (lowest-order) byte** when the
shift overflows the top bit — the standard "multiply-by-x in GF(2^n)" operation.

> **Endianness caution.** GOST is little-endian in many other places (key
> scalars, curve points, CTR nonce intuition). The CMAC shift is the opposite: a
> **big-endian** GF(2^n) shift. Byte 0 holds the most-significant bits; the carry
> from `byte[i]` flows into `byte[i-1]`. Reusing GOST's usual little-endian habit
> here produces wrong subkeys.

### The `Rb` reduction constants — per block size

`Rb` is the low byte of the irreducible polynomial that defines GF(2^n):

- **128-bit block (Kuznyechik): `Rb = 0x87`** — polynomial
  `x^128 + x^7 + x^2 + x + 1` ([RFC 4493](rfc/rfc4493.txt) §2.3, which defines
  CMAC for the 128-bit AES block; the same constant applies to any 128-bit cipher).
- **64-bit block (Magma): `Rb = 0x1b`** — polynomial `x^64 + x^4 + x^3 + x + 1`
  ([RFC 8645](../ctracpkm/rfc/rfc8645.txt) §6.3.6, OMAC-ACPKM-Master, which fixes
  `R_64 = 0^59|11011`, i.e. binary `11011 = 0x1b`; also the standard 64-bit CMAC
  constant in SP 800-38B).

In both cases the constant is a single byte; the rest of the `Rb` block is zero,
so it only ever affects the last byte of the shifted value.

### MAC computation (RFC 4493 §2.4 = GOST R 34.13-2015 §5.6)

Split the message `M` into `n`-bit blocks `M_1 … M_m` (the last block `M_m*`
possibly shorter). [RFC 4493](rfc/rfc4493.txt) §2.4, "MAC Generation Algorithm":

```
1.  (K1, K2) = subkeys  (above)
2.  if M is a multiple of n and non-empty:
        M_last = M_m  XOR  K1                 # complete final block
    else (incl. empty message):
        M_last = padding(M_m*) XOR K2         # incomplete / empty final block
        where padding(x) = x || 0x80 || 0x00…  (pad to n bits)
3.  X = 0^n
    for i = 1 .. m-1:
        X = E_K( X XOR M_i )                  # CBC chain
    T = E_K( X XOR M_last )
4.  MAC = MSB_tlen(T)                          # truncate to tag length
```

The whole construction is CBC-MAC over `M_1 … M_{m-1}`, then a final block that
is `M_last = M_m ⊕ K1` (complete) or `pad(M_m*) ⊕ K2` (incomplete). GOST R
34.13-2015 §5.6 specifies exactly this with `R = E_K(0)` and the same two-subkey
selection; the padding (single `1` bit then zeros, i.e. byte `0x80`) is GOST's
pad-mode 2.

## Implementation notes

Points where a naive reading diverges from the standard; each is exercised by a
test vector below.

1. **`Rb` is chosen by block size.** `0x87` for a 16-byte block, `0x1b` for an
   8-byte block; any other block size is rejected. The 64-bit constant is the
   spot most often gotten wrong — RFC 4493 only states `0x87`; the 64-bit value
   comes from [RFC 8645](../ctracpkm/rfc/rfc8645.txt) §6.3.6.

2. **The shift is big-endian over the whole block.** A one-bit left shift of the
   entire block, carrying each byte's top bit down into the previous byte; if the
   original MSB was 1, `Rb` is XORed into the **last** byte. A little-endian shift
   (carry flowing the other way, `Rb` in byte 0) is the classic bug.

3. **A buffered full block is a legal, intentional state.** `Write` deliberately
   does not flush a full block if it is the trailing data — it keeps up to `n`
   bytes buffered so `Sum` can distinguish "exactly `n` unprocessed bytes" (the
   `K1` path) from "fewer than `n`" (the `K2`/padding path). Flushing the full
   final block early, then padding an empty block with `K2`, yields a wrong tag
   on every block-aligned message.

4. **Padding is `0x80` then zeros** (GOST pad-mode 2 = RFC 4493 padding). The
   empty-message case writes `0x80` at index 0. This is unrelated to the GOST R
   34.11-94 empty-input quirk; CMAC's empty-message handling is unambiguous.

5. **Truncation takes the leading `tagSize` bytes (MSB).** `New` validates
   `1 ≤ tagSize ≤ block size`. The RFC 9189 CTR-OMAC suites use the full width
   (16/8); the published standard KATs truncate to 8/4; kexp15 truncates to its
   own `macLen`.

6. **`Sum` is non-destructive.** It snapshots the running CBC state and the
   buffer and operates on copies, so the receiver survives repeated `Sum` and
   later `Write` — mirroring OpenSSL's EVP "finalize-on-copy" semantics (the same
   property documented for [IMIT](../gost28147imit/DESIGN.md)). Required so a
   protector can MAC, then keep streaming.

7. **The block cipher is used in the encrypt direction throughout**, including
   for `L = E_K(0)` and every CBC step. CMAC never decrypts; verification
   recomputes the tag and compares in constant time at the caller.

## Test vectors

### Kuznyechik OMAC, engine-oracle vector

```
cipher:    Kuznyechik (16-byte block)
key (32B): AA × 32   (all bytes 0xAA)
message:   "hello"   (5 ASCII bytes: 68 65 6c 6c 6f)  — partial final block → K2 path
tag (16B): 96e6c1913fd788e3922e617fdd341edf   (full, untruncated)
```

Because `"hello"` is shorter than a block, this vector also exercises the
`K2`/padding branch end-to-end.

### Standard GOST R 34.13-2015 KATs (truncated)

- **Kuznyechik, [GOST R 34.13-2015](rfc/GOST_R_34.13-2015.pdf) A.1.6:**
  ```
  key (32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
  P  (64B):  1122334455667700ffeeddccbbaa9988
             00112233445566778899aabbcceeff0a
             112233445566778899aabbcceeff0a00
             2233445566778899aabbcceeff0a0011
  tag (8B):  336f4d296059fbe3      (leading 8 bytes of the 16-byte CMAC)
  ```
  `P` is a multiple of the block size → **`K1`** (complete-block) path.

- **Magma, [GOST R 34.13-2015](rfc/GOST_R_34.13-2015.pdf) A.2.6:**
  ```
  key (32B): ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  P  (32B):  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
  tag (4B):  154e7210              (leading 4 bytes of the 8-byte CMAC)
  ```
  `P` is a multiple of 8 → **`K1`** path; truncated to 4 bytes.

### Property coverage

The test suite also pins the streaming contract: two consecutive `Sum`s return
equal bytes; `Write half1; Sum; Write half2; Sum` equals a fresh OMAC over the
concatenation (proving `Sum` does not mutate state and that split `Write`s match
a one-shot `Write`).

## Conformance testing

The in-package tests (`omac/omac_test.go`) anchor the fixed vectors above. In
addition, a differential fuzz harness compares this implementation against an
independent reference over random keys and message lengths — including
split-point variance and the empty-message `K2` path — for both the 128-bit
(Kuznyechik) and 64-bit (Magma) block sizes. OMAC is deterministic, so this is a
direct differential comparison rather than a round-trip.

```sh
go test ./omac/
```

## References

- **[RFC 4493](rfc/rfc4493.txt)** — "The AES-CMAC Algorithm" (D. Song et al.,
  June 2006).
  - §2.3 — Subkey generation (`L = E_K(0^n)`, `K1`/`K2`, `Rb = 0x87`, big-endian `<< 1`).
  - §2.4 — MAC generation (CBC chain, `K1` complete vs `K2` padded final block, `MSB_tlen` truncation).
  - §2.1 — Basic definitions: `Rb` and the GF(2^128) `<< 1` operation.
- **[RFC 8645](../ctracpkm/rfc/rfc8645.txt)** — "Re-keying Mechanisms for
  Symmetric Keys" (CryptoPro, 2019). §6.3.6 fixes the 64-bit reduction constant
  `Rb = 0x1b`.
- **[GOST R 34.13-2015](rfc/GOST_R_34.13-2015.pdf)** — "Block cipher operation
  modes". §5.6 (MAC mode, `R = E_K(0)`, two-subkey selection, pad-mode 2); A.1.6
  (Kuznyechik KAT); A.2.6 (Magma KAT).
- **NIST SP 800-38B** — "The CMAC Mode for Authentication" (equivalent definition
  of OMAC1/CMAC).
- **[RFC 7801](../kuznyechik/rfc/rfc7801.txt)** / **[RFC 8891](../magma/rfc/rfc8891.txt)**
  — the Kuznyechik and Magma block ciphers.

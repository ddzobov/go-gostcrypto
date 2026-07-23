# CryptoPro Key Wrap — RFC 4357 §6.3 / §6.5

This document describes the CryptoPro key-wrap algorithm implemented by
`package keywrap`: what it is, its specification, the notable points of this
implementation, and the test vectors that pin it. For the public API and a
usage example see the [package README](README.md).

## What it is

The CryptoPro key-wrap algorithm encrypts a 32-byte (256-bit) GOST 28147-89
session key (the **CEK** — content-encryption key) under a 32-byte GOST
28147-89 key-encryption key (the **KEK**), producing a 44-byte wrapped blob. It
is the key-transport primitive used by the TLS 1.2 GOST cipher suites whose key
exchange is `GOST_KEY_TRANSPORT` (RFC 9189 §4.1): the TLS premaster secret is
the CEK, and the VKO-derived shared secret is the KEK.

Two RFC 4357 sub-algorithms compose:

- **RFC 4357 §6.5 — CryptoPro KEK Diversification.** Given the 32-byte KEK and
  an 8-byte UKM (user keying material), derives a per-UKM key `KEK(UKM)` via
  eight rounds of GOST 28147-89 CFB encryption. The bit pattern of each UKM
  byte selects how the eight current-key 32-bit words are summed into a fresh
  CFB IV.
- **RFC 4357 §6.3 — CryptoPro Key Wrap.** Diversifies the KEK, ECB-encrypts the
  CEK under `KEK(UKM)`, computes a 4-byte GOST 28147-89 IMIT (MAC) over the CEK
  with `IV = UKM`, and concatenates `UKM | CEK_ENC | CEK_MAC`.

RFC 4357 §6.4 (Key Unwrap, the inverse operation) is not implemented — this
package only ever wraps, matching the sending side of `GOST_KEY_TRANSPORT`.

GOST / standard identity:

- Block cipher: [GOST 28147-89](../gost28147/DESIGN.md) ("Magma legacy"),
  64-bit block, 256-bit key.
- IMIT MAC: GOST 28147-89 imitovstavka, a CBC-MAC-like construction defined in
  RFC 4357 §1.1 Terminology (`gost28147IMIT`); the general-purpose one-shot
  entry point lives in [`gost28147imit`](../gost28147imit/DESIGN.md), but this
  wrap needs a non-zero initial chaining state and no key meshing (see
  "Implementation notes" below), so it implements the 16-round MAC transform
  inline rather than calling that package.
- KEK source: VKO GOST R 34.10-2001 (RFC 4357 §5.2) or VKO GOST R 34.10-2012
  (RFC 7836), depending on the certificate's public-key algorithm.

### Where this module uses it

`keywrap` is a leaf package within this module: no other package here composes
it. It builds directly on [`gost28147`](../gost28147/README.md) for the block
cipher, its two named S-boxes, and CFB-style keystream feedback.

Its real consumer is the sibling `gostls` TLS module, which calls
`KeyWrapCryptoPro` on the client side of the GOST 2001 and GOST 2012 key-
transport suites (RFC 9189 §4.1, suite IDs `0x0081`, `0xFF85`, `0xC102`): the
44-byte output is split so that `wrapped[8:40]` becomes the encrypted
`GOST_KEY_INFO` and `wrapped[40:44]` becomes its IMIT MAC.

## Specification

All sizes are fixed:

| Quantity | Size |
|---|---|
| Block (GOST 28147-89) | 8 bytes |
| KEK | 32 bytes |
| CEK (session key) | 32 bytes |
| UKM | 8 bytes |
| Diversified key `KEK(UKM)` | 32 bytes |
| CEK_ENC | 32 bytes |
| CEK_MAC (IMIT, truncated) | 4 bytes |
| Wrapped output | 44 bytes |

### RFC 4357 §6.5 — KEK Diversification (normative)

> "Given a random 64-bit UKM and a GOST 28147-89 key K, this algorithm creates
> a new GOST 28147-89 key K(UKM)." (RFC 4357 §6.5)

The algorithm:

1. `K[0] = K` (the input KEK).
2. UKM is processed byte-by-byte. For round `i = 0 .. 7`, treat the current
   key `K[i]` as eight little-endian 32-bit words `w[0..7]`. Form two 32-bit
   sums: for each word index `j = 0 .. 7`, if bit `j` of `ukm[i]` is set, add
   `w[j]` into `S1`; otherwise add `w[j]` into `S2` (both sums mod 2^32).
3. Build the 8-byte CFB IV `S[i] = LE32(S1) || LE32(S2)`.
4. `K[i+1] = encryptCFB(S[i], K[i], K[i])` — CFB-encrypt the 32-byte current
   key under itself, with IV `S[i]`. The output replaces the key in place.
5. After 8 rounds, `K(UKM) = K[8]`.

Each round re-keys the cipher with the key it is about to transform (a
"self-keyed" step): round `i` uses `K[i]` both as the CFB plaintext and as the
cipher key that encrypts it.

### RFC 4357 §6.3 — Key Wrap (normative)

> 1. "For a unique symmetric KEK or a KEK produced by VKO GOST R 34.10-94,
>    generate 8 octets at random. Call the result UKM."
> 2. "Diversify KEK, using the CryptoPro KEK Diversification Algorithm,
>    described in Section 6.5. Call the result KEK(UKM)."
> 3. "Compute a 4-byte checksum value, gost28147IMIT (UKM, KEK(UKM), CEK). Call
>    the result CEK_MAC."
> 4. "Encrypt CEK in ECB mode using KEK(UKM). Call the ciphertext CEK_ENC."
> 5. "The wrapped content-encryption key is (UKM | CEK_ENC | CEK_MAC)."
> (RFC 4357 §6.3)

Here `gost28147IMIT(UKM, KEK(UKM), CEK)` means: the GOST 28147-89 IMIT MAC of
the message `CEK` (32 bytes = 4 full blocks), keyed with `KEK(UKM)`, using the
**non-zero IV `UKM`** as the MAC's initial chaining state, truncated to its 4
least-significant (first) bytes. In TLS, the UKM is not freshly random — the
caller derives it from `client_random` (its first 8 bytes), so step 1 is
supplied by the caller rather than generated by this package.

### Wrap output layout

```
offset:  0        8                              40        44
        +--------+------------------------------+----------+
        |  UKM   |          CEK_ENC             | CEK_MAC  |
        | 8 B    |          32 B                |  4 B     |
        +--------+------------------------------+----------+
```

The 8 UKM bytes at `[0:8]` are a verbatim copy of the input UKM: the RFC layout
requires UKM to travel with the wrapped key so the receiver can re-diversify.

### S-box selection rule

GOST 28147-89 is parameterized by an 8×16 S-box. The wrap and *all* its
sub-primitives (diversification CFB, ECB encrypt, IMIT MAC) use the **same**
S-box, selected by the peer certificate's public-key algorithm:

- **GOST R 34.10-2012 certificate** → `id-tc26-gost-28147-param-Z`
  (`SboxTC26Z`), cipher param OID `1.2.643.7.1.2.5.1.1`.
- **GOST R 34.10-2001 certificate** → CryptoPro-A (`SboxCryptoProA`), cipher
  param OID `1.2.643.2.2.31.1`.

This selection is a TLS/`GOST_KEY_TRANSPORT` convention (RFC 9189 §4.1), not
part of RFC 4357 itself — RFC 4357 predates the 2012 suites and only ever used
CryptoPro-A. The two S-boxes' concrete byte tables live in
[`gost28147`](../gost28147/README.md), which this package re-exports both of
(`keywrap.SboxTC26Z`, `keywrap.SboxCryptoProA`) so callers rarely need to
import `gost28147` directly.

## Implementation notes

Points where a naive reading of the RFC text most often goes wrong; each is
exercised by a test vector below.

1. **Word/sum endianness in diversification is little-endian.** RFC 4357 §6.5
   describes the sum over "components" abstractly, but the concrete rule is:
   read each 32-bit word of the current key **little-endian**, and pack `S1`,
   `S2` back **little-endian** into the 8-byte CFB IV. A reimplementer who
   packs big-endian here produces a wrong `KEK(UKM)`, and every downstream byte
   of the wrap differs.

2. **Bit-selection order is LSB-first, `mask = 1 << j`.** The UKM bit that
   routes word `j` into `S1` vs `S2` is bit `j` (the `j`-th least-significant
   bit) of `ukm[i]` — round index `i` selects which UKM byte, word index `j`
   selects both the word *and* the bit within that byte. An off-by-one or
   MSB-first read silently corrupts the derived IV.

3. **Sum accumulators wrap mod 2^32.** `S1` and `S2` are 32-bit unsigned sums;
   overflow is expected and simply wraps, not an error condition.

4. **Each diversification round is self-keyed.** The CFB step re-keys the
   cipher with the *current* (already partially diversified) key, then
   CFB-encrypts that same key buffer in place under the freshly computed IV;
   CFB feedback uses the just-produced ciphertext block as the next block's
   IV.

5. **The wrap's IMIT MAC uses a non-zero IV = UKM, and exactly four blocks —
   no padding, no key meshing.** Two things distinguish it from a "default"
   IMIT call:
   - The MAC's initial chaining state is `UKM`, not zero.
   - The CEK is exactly 32 bytes (four whole 8-byte blocks), so the MAC
     processes four blocks with no partial-block padding and no extra
     all-zero finalization block. CryptoPro key meshing (RFC 4357 §2.3.2)
     only triggers every 1024 processed bytes — far more than this MAC ever
     sees — so meshing plays no role in key wrap. This is exactly the
     divergence from `gost28147imit`'s general-purpose `IMIT` entry point:
     that function always starts from a zero IV and applies meshing past its
     threshold, neither of which this wrap wants, which is why the MAC here
     is implemented as its own small inline transform rather than calling
     into the sibling package.

6. **MAC truncation takes the leading 4 bytes, not the last.** The IMIT's
   8-byte running state is `LE32(n1) || LE32(n2)`; the wrap's 4-byte
   `CEK_MAC` is `LE32(n1)`, the first half.

7. **The diversified key, never the raw KEK, drives both the ECB encrypt and
   the MAC.** Diversification happens once per wrap; its 32-byte output
   `KEK(UKM)` is the key for every subsequent step.

8. **ECB encrypt of the CEK is four independent 8-byte blocks** — no chaining,
   no IV; each block encrypts on its own under `KEK(UKM)`.

## Test vectors

### In-repo KAT

Captured from a reference GOST engine's `keyWrapCryptoPro` on the **tc26-Z**
S-box (`keywrap/keywrap_test.go`).

Inputs:

```
kek     = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20  (32 B)
ukm     = 0102030405060708                                                  (8 B)
session = 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f  (32 B)
sbox    = tc26-Z
```

Expected:

```
KEK(UKM)  = c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18   (32 B)
CEK_ENC   = 940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1   (32 B)  -> wrapped[8:40]
CEK_MAC   = e77d8bc3                                                           (4 B)   -> wrapped[40:44]
UKM       = 0102030405060708                                                   (8 B)   -> wrapped[0:8]
```

Full 44-byte wrapped output:

```
0102030405060708 940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1 e77d8bc3
```

`keywrap_test.go` pins this vector at three granularities: `TestDiversify_KAT`
(the intermediate `KEK(UKM)` alone), `TestIMIT4_KAT` (the 4-byte MAC alone,
keyed with `KEK(UKM)` and `IV = UKM`), and `TestKeyWrapCryptoPro_KAT` (the full
44-byte blob plus each field). `TestKeyWrapCryptoPro_BadSizes` and
`TestDiversify_PanicOnBadSizes` cover the two different failure modes:
`KeyWrapCryptoPro` returns an error, `Diversify` panics.

This KAT only exercises the tc26-Z S-box path (suites `0xFF85` / `0xC102`);
there is no pinned vector here for the CryptoPro-A path (suite `0x0081`).

## Conformance testing

The pinned KAT above anchors `keywrap_test.go`. Beyond that, this primitive has
no differential fuzz target inside this repository: it is a from-scratch
reimplementation of RFC 4357 §6.3/§6.5, and most general-purpose GOST
implementations either skip KEK diversification entirely or hardcode a single
S-box, so an independent reference implementation covering both S-boxes and
the diversification step is needed to fuzz against. Where such a reference is
available, the useful differential check is: drive a random 32-byte KEK,
8-byte UKM, and 32-byte session key through both implementations for each
S-box (tc26-Z and CryptoPro-A) and assert byte-for-byte equality of the full
44-byte blob — the KAT above seeds that corpus and is the only vector known to
cover CryptoPro-A's sibling suite family end-to-end today.

```sh
go test ./keywrap/
```

## References

- **RFC 4357** — "Additional Cryptographic Algorithms for Use with GOST 28147-89..."
  - [§6.3](rfc/rfc4357.txt) — CryptoPro Key Wrap.
  - [§6.4](rfc/rfc4357.txt) — CryptoPro Key Unwrap (inverse; not implemented here).
  - [§6.5](rfc/rfc4357.txt) — CryptoPro KEK Diversification Algorithm.
  - [§1.1](rfc/rfc4357.txt) — `gost28147IMIT` (GOST 28147-89 IMIT MAC) definition, in Terminology.
- **[RFC 9189](rfc/rfc9189.txt)** §4.1 — `GOST_KEY_TRANSPORT` (TLS 1.2 use of this wrap; S-box-by-certificate-type selection).
- **[RFC 7836](rfc/rfc7836.txt)** — VKO GOST R 34.10-2012 (one of the two KEK sources).
- **[RFC 5830](rfc/rfc5830.txt)** — GOST 28147-89 block cipher and IMIT MAC.
- GOST R 34.10-2001 / GOST R 34.10-2012 — the public-key algorithms behind the
  KEK, whose certificate type selects the wrap's S-box (no local copy of
  either standard in this repo).
- [`../gost28147/DESIGN.md`](../gost28147/DESIGN.md) — the block cipher this
  wrap's ECB encrypt, CFB diversification, and IMIT MAC all build on.
- [`../gost28147imit/DESIGN.md`](../gost28147imit/DESIGN.md) — the
  general-purpose IMIT MAC this package deliberately does not call (see
  "Implementation notes" above), described there in full.

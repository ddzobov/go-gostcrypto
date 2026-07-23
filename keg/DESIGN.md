# KEG — key export generation (R 1323565.1.020-2018)

This document describes KEG as implemented by `package keg`: what it is, its
specification, the notable points of this implementation, and the test
vectors that pin it. For the public API and a usage example see the
[package README](README.md).

## What it is

KEG ("key export generation") is the GOST 2012 TLS 1.2 key-derivation step
that turns a Diffie-Hellman-style shared secret into the 64-byte symmetric key
block used to *export* (wrap) the TLS pre-master secret. It is specified in
**R 1323565.1.020-2018 §6.4.5.1** and used by the GOST 2012 cipher suites of
**RFC 9189** (e.g. `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` /
`_MAGMA_CTR_OMAC`, suite IDs `0xC102`/`0xC103`, and the RFC 9367 follow-ons
`0xC100`/`0xC101`).

KEG sits between two other primitives and feeds a third:

```
VKO 2012-256           (RFC 7836 §4.3, shared-secret agreement)   ──┐
                                                                    ├──►  KEG  ──►  64-byte expkeys
KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.4)                        ──┘                │
                                                                                       ├─ expkeys[ 0:32] = MAC key
                                                                                       └─ expkeys[32:64] = cipher key
```

KEG itself is a thin assembly of those two steps — it produces only the
64-byte key block; wrapping the pre-master secret with that block is a
separate step (`kexp15`, KExp15 key wrap).

### Where this module uses it

- The `vko` package supplies the VKO 2012-256 shared-secret step and the
  `gost3410curves` package supplies the GOST R 34.10-2012 curve arithmetic —
  see [`../gost3410curves/DESIGN.md`](../gost3410curves/DESIGN.md).
- The `kdftree` package supplies the KDF tree expansion —
  see [`../kdftree/DESIGN.md`](../kdftree/DESIGN.md). Both VKO and the KDF
  tree finalize through Streebog-256; see
  [`../streebog/DESIGN.md`](../streebog/DESIGN.md).
- The 64-byte output is consumed by the `kexp15` package: `expkeys[:32]` is
  the MAC key and `expkeys[32:]` the cipher key it feeds into KExp15's
  OMAC/CTR steps; the IV is `ukmSource[24:24+ivLen]`, taken by the caller —
  KEG does not produce or consume an IV itself.
- In an RFC 9189 TLS handshake, `ukmSource` is
  `Streebog256(client_random ‖ server_random)` and the sibling `gostls` TLS
  module is the caller that assembles it, invokes `KEG2012_256`, and splits
  and wires the two halves of the result.

## Specification

### Inputs

| Name | Size | Meaning |
|---|---|---|
| `ukmSource` | 32 bytes | UKM material. In RFC 9189 TLS this is `Streebog256(client_random ‖ server_random)` (a 64-byte concatenation reduced to a 32-byte digest). |
| `serverPub` | 64 bytes | Peer's GOST 2012-256 public key, raw `LE X ‖ LE Y`. |
| `clientPriv` | 32 bytes | Local GOST 2012-256 private key, little-endian scalar. |
| `curve` | — | The GOST R 34.10-2012 256-bit curve the keys live on — whatever curve the server certificate uses, including the CryptoPro paramsets signalled GC256B/C/D (RFC 9189). `nil` defaults to TC26 ParamSet A (OID `1.2.643.7.1.2.1.1.1`). A 512-bit curve is rejected: the 512-bit KEG is a distinct algorithm not implemented here. |

### Step 1 — UKM adjustment

Only the **first 16 bytes** of `ukmSource` feed VKO, and they are
byte-reversed:

```
real_ukm[0..15] = 0
if ukm_source[0..15] == 16 zero bytes:
    real_ukm[15] = 1                      // avoid a zero VKO scalar factor
else:
    real_ukm = reverse(ukm_source[0..15])
```

The all-zero special case sets `real_ukm = 00…00 01` (16 bytes) so the VKO
scalar factor is never 0, which would otherwise make the shared secret
degenerate.

### Step 2 — VKO 2012-256 shared secret

```
tmpkey[0..31] = VKO_GOSTR3411_2012_256(pub_key, priv_key, real_ukm, ukm_size=16)
```

VKO (RFC 7836 §4.3) computes:

1. `scalar = (UKM · d) mod q`, where `d` is the private key and `q` the
   curve order. The net effect — after the byte-reversal in Step 1 and the
   little-endian scalar read inside VKO — is that `scalar` equals the
   **big-endian** reading of `ukmSource[0:16]`. This double-reversal is easy
   to "simplify away" by accident; what matters is the net integer, which
   the test vector below pins.
2. `(X, Y) = scalar · pub_key`, an EC point multiply that must clear the
   curve's cofactor (TC26 256-bit ParamSet A has cofactor 4) exactly once —
   whether that happens implicitly inside the point-multiply routine or via
   an explicit scalar adjustment before it, applying it twice or not at all
   produces a wrong but plausible-looking `tmpkey`; only the known-answer
   test below catches it.
3. Serialize `databuf = LE(X, half_len) ‖ LE(Y, half_len)`, where `half_len`
   is the field byte length (32 for the 256-bit case). GOST is little-endian
   here, in a spot where most ECC code defaults to big-endian.
4. `tmpkey = Streebog256(databuf)`.

Output `tmpkey` is 32 bytes; see [`../vko`](../vko) for the shared-secret
implementation this step delegates to.

### Step 3 — KDFTree expansion to 64 bytes

```
keyout[0..63] = KDF_TREE_GOSTR3411_2012_256(
                    key   = tmpkey,            // 32 bytes
                    label = "kdf tree",        // 8 ASCII bytes, no NUL
                    seed  = ukm_source[16:24], // 8 bytes
                    keyout_len = 64,
                    representation = 1)
```

`KDF_TREE_GOSTR3411_2012_256` (RFC 7836 §4.4) computes, for each iteration
`i = 1 .. keyout_len/32`:

```
block_i = HMAC_Streebog256( key,
              I2BE(i, representation)   // representation=1 ⇒ single byte i
            ‖ label                     // "kdf tree"
            ‖ 0x00                      // one zero separator byte
            ‖ seed                      // ukm_source[16:24]
            ‖ L )                       // big-endian bit-length, leading zeros stripped
keyout[(i-1)*32 : i*32] = block_i
```

For the 64-byte KEG output there are exactly **2 iterations** (`i = 1, 2`).
The length field `L` is `be32(keyout_len * 8)` = `be32(512)` = `00 00 02 00`,
with leading zero bytes stripped down to the two bytes `02 00`. So each HMAC
message is exactly 20 bytes:

```
i(1) ‖ "kdf tree"(8) ‖ 0x00(1) ‖ seed(8) ‖ 0x02 0x00(2)
```

with `i ∈ {0x01, 0x02}`. See
[`../kdftree/DESIGN.md`](../kdftree/DESIGN.md) for the general-purpose KDF
tree this specializes.

### Output split

The 64-byte result is consumed as two 32-byte keys:

```
expkeys[ 0:32] = MAC key      (fed to kexp15 as the OMAC/IMIT key)
expkeys[32:64] = cipher key   (fed to kexp15 as the CTR/encrypt key)
```

The **MAC key comes first** — this is the order KExp15 expects, and getting
it backwards silently produces a wrong wrap that still has the right shape.

### Sizes / constants summary

| Quantity | Value |
|---|---|
| `ukmSource` length | 32 bytes (exactly) |
| VKO UKM length (`real_ukm`) | 16 bytes (`ukmSource[0:16]`, reversed) |
| KDF seed | `ukmSource[16:24]`, 8 bytes |
| (IV, consumed downstream by KExp15) | `ukmSource[24:24+ivLen]` — *not* part of KEG |
| VKO output (`tmpkey`) | 32 bytes |
| KEG output (`expkeys`) | 64 bytes |
| KDF label | `"kdf tree"` (8 bytes, no NUL terminator) |
| KDF separator | `0x00` |
| KDF length suffix `L` | `0x02 0x00` (512 bits, big-endian, leading zeros stripped) |
| KDF representation | 1 (one-byte iteration counter) |
| KDF hash | Streebog-256 (GOST R 34.11-2012-256) inside HMAC |

## Implementation notes

Points where a naive reading of the spec is easy to get backwards; each is
exercised by a test vector below.

1. **UKM is read as a big-endian integer, net of two reversals.** The scalar
   fed into VKO equals `bigEndianInt(ukmSource[0:16])`, arrived at via a
   byte-reversal in Step 1 followed by a little-endian read inside VKO. A
   from-scratch implementation must match the *net* integer rather than
   "simplifying" by dropping one of the reversals — the test vector below
   pins the net value.

2. **All-zero-UKM special case.** If `ukmSource[0:16]` is 16 zero bytes, the
   last byte of `real_ukm` is set to `1` instead of leaving it zero. Without
   this the VKO scalar factor would be `0` and the agreement would degenerate
   to the identity point. Easy to miss; there is a dedicated deterministic
   test for it.

3. **Cofactor multiplication inside VKO.** TC26 256-bit ParamSet A has
   cofactor 4. The cofactor must be applied to the scalar exactly once,
   whichever layer does it. A double-application or a missing application
   both yield a plausible-looking, wrong `tmpkey`; only the known-answer test
   catches it, since the output still has the right shape.

4. **VKO point serialization is little-endian, X then Y.**
   `databuf = LE(X) ‖ LE(Y)` — GOST is little-endian here, in a place most
   ECC code defaults to big-endian. Transposing the X/Y order or serializing
   big-endian both change `tmpkey` silently.

5. **The KDF length field is variable-width and leading-zeros-stripped, not
   a fixed 4 bytes.** A generic KDF_TREE implementation would encode the
   512-bit length as `00 00 02 00`; KEG strips the leading zero bytes down to
   `02 00`. This 2-byte form is correct for KEG's fixed 64-byte output but is
   not the general rule for every `keyout_len`.

6. **The KDF iteration counter width is `representation`, not a fixed 4
   bytes.** KEG always calls with `representation = 1`, so the counter is a
   single byte `i` (`0x01`, `0x02`), not a 4-byte big-endian integer. A
   4-byte counter would change every HMAC input and break every KAT.

7. **The KDF label has no NUL terminator; a separate `0x00` separator
   follows it.** The HMAC message is `i ‖ label ‖ 0x00 ‖ seed ‖ L`. The
   `0x00` is an explicit separator byte, not a C-string terminator folded
   into the 8-byte label — `"kdf tree"` is exactly 8 bytes and the separator
   is a ninth, distinct byte.

8. **MAC-key / cipher-key ordering is a call-site convention, not part of
   KEG's output format.** KEG just yields 64 flat bytes; the
   `[:32]`=MAC / `[32:]`=cipher split is documented here so a caller does not
   swap the halves when wiring KExp15.

9. **No known Streebog empty-input divergence affects this primitive.**
   Streebog-2012 (not the older -94 hash) is used throughout, and neither the
   VKO finalize (a 64-byte `databuf`) nor any HMAC message KEG builds is ever
   empty, so the well-known GOST R 34.11-94 empty-input finalization quirk
   that affects some other primitives in this module does not apply here.

## Test vectors

### Complete runnable vector (256-bit, TC26 ParamSet A)

Curve: GOST R 34.10-2012 256-bit, TC26 ParamSet A (OID `1.2.643.7.1.2.1.1.1`).

```
priv A (LE, 32 B):
  9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d
pub A  (LE X ‖ LE Y, 64 B):
  a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c
  6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4
priv B (LE, 32 B):
  bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607
pub B  (LE X ‖ LE Y, 64 B):
  c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888
  8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602

ukm_source (32 B):
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    → real_ukm  = reverse(00..0f) = 0f0e0d0c0b0a09080706050403020100
    → kdf seed  = ukm_source[16:24] = 1011121314151617

KEG output expkeys (64 B), symmetric for (privA,pubB) and (privB,pubA):
  bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900
  39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b

  → MAC key    expkeys[ 0:32] = bc2b44f5…9d671900
  → cipher key expkeys[32:64] = 39eb73d0…2db1e62b
```

This vector was cross-checked against a GOST-engine OpenSSL derive oracle and
also exercises pair symmetry: `KEG(pubB, privA, ukm) == KEG(pubA, privB, ukm)`.

### Zero-UKM special case

A second KAT fixes `ukm_source = 32 × 0x00`, which forces
`real_ukm = 00…00 01` (Step 1's all-zero branch) and produces a distinct,
pinned 64-byte output — proving the special case is wired in and not
accidentally bypassed.

### Property coverage

The test suite also pins: pair symmetry for a non-zero UKM (already shown
above), rejection of every `ukmSource` length other than exactly 32 bytes
(`ErrUKMSourceLen`), pass-through of bad-key errors from the underlying VKO
step (wrong-length or off-curve public key, wrong-length or zero private
key), correct operation on a non-TC26-A 256-bit curve (a CryptoPro paramset)
matching the same output the TC26-A vector would give if the keys were valid
on both curves, and rejection of a 512-bit curve (`ErrCurve512`).

## Conformance testing

The in-package tests (`keg/keg_test.go`) anchor the fixed vectors above:
both KAT directions, the MAC/cipher split, pair symmetry, the zero-UKM
special case, the exact-32-byte `ukmSource` contract, bad-key error
pass-through, non-TC26-A curve handling, and 512-bit curve rejection.

In addition, a differential fuzz harness compares this implementation
against an independent reference implementation over randomly generated
keypairs and UKMs — including the zero-UKM and an all-`0xFF` UKM edge case —
checking byte-identical 64-byte outputs and pair symmetry for every draw.
Because KEG assembles two already-verified primitives (VKO and the KDF
tree) rather than exposing new low-level state, this differential comparison
plus the pinned KATs above are the primary correctness evidence for this
package.

```sh
go test ./keg/
```

## References

- **R 1323565.1.020-2018 §6.4.5.1** — KEG ("key export generation") definition.
- **[RFC 9189](rfc/rfc9189.txt)** — *GOST Cipher Suites for TLS 1.2*. Defines the suites that consume KEG's output via KExp15 key transport.
- **draft-smyshlyaev-tls12-gost-suites** — predecessor of RFC 9189; same KEG/KExp15 wiring.
- **[RFC 7836](rfc/rfc7836.txt)** — *Guidelines on the Cryptographic Algorithms to Accompany GOST*.
  - §4.3 — VKO_GOSTR3411_2012_256.
  - §4.4 — KDF_TREE_GOSTR3411_2012_256 (§4.5 is the simpler single-block KDF_GOSTR3411_2012_256, not used here).
- **R 50.1.113-2016** — the KDF_TREE / KDF_GOSTR3411_2012_256 standard.
- **[RFC 6986](rfc/rfc6986.txt)** — *GOST R 34.11-2012 (Streebog)* hash function, used inside both VKO and the KDF tree. See [`../streebog/DESIGN.md`](../streebog/DESIGN.md).
- **[RFC 7091](rfc/rfc7091.txt)** — GOST R 34.10-2012, the signature/key-pair scheme and curve family. See [`../gost3410curves/DESIGN.md`](../gost3410curves/DESIGN.md).

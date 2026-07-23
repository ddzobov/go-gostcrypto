# GOST 28147-89 IMIT MAC + CryptoPro key meshing

This document describes the IMIT MAC implemented by `package gost28147imit`:
what it is, its specification, the notable points of this implementation, and
the test vectors that pin it. For the public API and a usage example see the
[package README](README.md).

## What it is

The **IMIT** (имитовставка / "imitovstavka", an authentication tag) is the
keyed message-authentication code defined inside **GOST 28147-89**
("выработка имитовставки") and republished as **RFC 5830 §8**. It is a
CBC-MAC built on the GOST 28147-89 block cipher, but with a *16-round*
transform per block instead of the cipher's 32 rounds. Deployments that
process more than 1024 bytes under one key (TLS application records, file
MACs) additionally apply **CryptoPro key meshing** (RFC 4357 §2.3.2): every
1024 bytes of processed full blocks, the key is re-derived. TLS truncates the
8-byte IMIT to **4 bytes** (RFC 9189 §4.2).

This document specifies the MAC layer only. It depends on the GOST 28147-89
block primitive — the key schedule, S-boxes, little-endian octet↔word
packing, the round function `f`, and especially the 16-round `SeqMAC`
schedule — which are specified in the sibling document
[`../gost28147/DESIGN.md`](../gost28147/DESIGN.md). That
document has the CryptoPro-A and tc26-Z S-box byte tables and the 16-round
schedule; this one concentrates on the MAC chaining, finalization, and
key-meshing logic layered on top.

**Dimensions**

| Quantity | Value | Source |
|---|---|---|
| Block size | 8 bytes (64 bit) | RFC 5830 §6 |
| Key size | 32 bytes (256 bit) | RFC 5830 §6 |
| Rounds per MAC block | 16 (`SeqMAC`) | RFC 5830 §8 |
| Full IMIT tag | 1–8 bytes | RFC 5830 §8 |
| TLS tag (truncated) | 4 bytes | RFC 9189 §4.2 |
| Key-meshing period | 1024 processed bytes | RFC 4357 §2.3.2 |
| Meshing constant | 32 bytes (§2.3 below) | RFC 4357 §2.3.2 |

### Where this module uses it

- The `gostcrypto` facade exposes a one-shot `GOST28147_IMIT(key, msg)`
  (4-byte tag with meshing) and a `SeqMACBlock` wrapper over this package's
  function of the same name.
- The sibling `gostls` TLS module drives a *streaming* MAC directly from
  `SeqMACBlock`, whose state persists across TLS records — replicating
  OpenSSL's EVP digest-sign semantics (finalize-on-copy, a deferred last
  block, and meshing). It serves TLS suites **0x0081**
  (`GOST2001-GOST89-GOST89`, CryptoPro-A S-box) and **0xFF85**
  (`GOST2012-GOST8912-GOST8912`, tc26-Z S-box).
- A non-zero-IV IMIT for `GOST_KEY_TRANSPORT` key wrap is **not** handled by
  this package; it is implemented inline by this module's `keywrap` package
  (see [`../keywrap/DESIGN.md`](../keywrap/DESIGN.md)),
  which needs the UKM as the initial chaining state rather than a zero IV.

## Specification

### 1. The per-block transform (16-round `SeqMAC`)

IMIT runs the GOST 28147-89 encryption step but stops after 16 rounds (two
forward subkey passes over `X[0..7]`, no reverse pass), versus the cipher's 32
rounds:

```
SeqMAC = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7]
```

RFC 5830 §8 states the imitovstavka uses the first 16 cycles of the basic
encryption step. The 16-round transform is not reachable through any public
cipher encrypt/decrypt API (those are hardwired to 32 rounds), which is why
this package surfaces it directly as `SeqMACBlock` — a caller building its own
streaming MAC drives the round function from the sibling cipher document
(§2–§3 there) through this exposed step rather than the full cipher.

**Octet ordering inside the MAC block (subtle — differs from the cipher).**
The MAC block reads the 8-byte state buffer little-endian as `n1 =
state[0..3]`, `n2 = state[4..7]`, runs 16 rounds, then writes back `state[0..3]
= n1, state[4..7] = n2` — **natural** order, no half-swap. The 32-round cipher,
by contrast, writes its output halves *swapped* (see
[`../gost28147/DESIGN.md`](../gost28147/DESIGN.md)). A MAC
implementation that reuses the cipher's swapped pack/unpack verbatim will
produce wrong tags.

### 2. IMIT chaining (CBC-MAC)

RFC 5830 §8: maintain an 8-byte running state `S` (the "buffer"), initialized
to the IV (all zeros for the raw MAC; the UKM for key transport, RFC 4357).
For each 8-byte plaintext block `P`:

```
S ← MACBLOCK( S XOR P )      # MACBLOCK = the 16-round transform of §1
```

The tag is the leading `s` bytes of `S` after the last block (`s ≤ 8`; TLS
uses `s = 4`).

### 2.1 Final / partial-block padding

Three padding rules govern the trailing bytes:

1. **Full blocks** are processed as in §2.
2. **A trailing partial block (1–7 bytes)** is zero-padded to 8 bytes and
   processed as one more MAC block.
3. **The trailing zero-block rule (total length 1–8 bytes inclusive).** If
   the whole message fits before any full block has been processed (i.e.
   total length ≤ 8 bytes), one extra **all-zero 8-byte block** is appended
   **after** the (zero-padded) data block — the data block is processed
   first, the all-zero block last. This also fires for an exactly-8-byte
   message: it is one full block, but since no *other* block preceded it, the
   trailing all-zero block is still appended.

   **Net rule:** any message of length 1–8 bytes gets one extra trailing
   all-zero block, processed after the (zero-padded) data block. A message of
   length ≥ 9 (at least one full block followed by more) does not get the
   trailing zero block.

### 2.2 Worked example of the padding rule

Order is left to right — the leftmost block is fed first.

| Message length | Blocks fed to MACBLOCK (in order) |
|----------------|-----------------------------------|
| 0 bytes        | (no blocks fed — not a meaningful MAC; this package rejects it) |
| 1–7 bytes      | `P‖0-pad`, then `00000000_00000000` (data first, trailing zero block, rule 3) |
| 8 bytes        | `P`, then `00000000_00000000` (one full block, then trailing zero block, rule 3) |
| 9–15 bytes     | `P0` (full), then `P1‖0-pad` (no trailing zero block) |
| 16 bytes       | `P0`, `P1` (no trailing zero block) |

The trailing all-zero block fires only when the total length is 1–8 bytes. It
does not fire once a full block has been processed ahead of the final one
(length ≥ 9).

### 2.3 CryptoPro key meshing (RFC 4357 §2.3.2)

After every **1024 bytes of processed full blocks**, before processing the
next block, the key is re-derived. The derivation **ECB-decrypts a 32-byte
meshing constant `C` with the current key**, four 8-byte blocks at a time, and
the result becomes the new key:

```
newKey[0..7]   = GOST_ECB_Decrypt(currentKey, C[0..7])
newKey[8..15]  = GOST_ECB_Decrypt(currentKey, C[8..15])
newKey[16..23] = GOST_ECB_Decrypt(currentKey, C[16..23])
newKey[24..31] = GOST_ECB_Decrypt(currentKey, C[24..31])
currentKey     = newKey
```

`GOST_ECB_Decrypt` here is the **32-round** cipher decrypt, not the 16-round
MAC step. For the IMIT/MAC path the running MAC state buffer is **not**
re-encrypted or otherwise touched across the mesh — only the key changes.

The 32-byte meshing constant `C`:

```
69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
```

Meshing applies identically to both the CryptoPro-A S-box (suite 0x0081) and
the tc26-Z S-box (suite 0xFF85) — the S-box only changes which cipher the ECB
decrypt uses; the constant and the 1024-byte period are the same.

### 2.4 The meshing counter and its wrap

A counter tracks bytes of *full blocks* processed, advanced by 8 per block,
and wrapped modulo 1024 after each block. The mesh fires when the counter
equals 1024, checked **before** processing the next block:

```
process(data):
    if count == 1024:  mesh()
    macBlock(state, data)          # XOR + 16 rounds
    count = count % 1024 + 8        # advance, wraps to 8, not 0
```

**The wrap is `count % 1024 + 8`, not `count = 0`** — so immediately after a
mesh at `count == 1024`, the counter becomes `1024 % 1024 + 8 = 8`, and the
next mesh is again a full 1024 bytes (128 blocks) later.

## Implementation notes

Points where a naive reading diverges from the standard; each is exercised by
a test vector below.

1. **16-round `SeqMAC`, not the 32-round cipher (RFC 5830 §8).** IMIT is 16
   rounds; the cipher is 32. Reusing the 32-round schedule for the MAC
   silently produces a plausible-looking but wrong 8-byte value. The
   key-meshing ECB *decrypt* of §2.3, by contrast, *does* use the 32-round
   schedule — the two "16 rounds vs. 32 rounds" rules apply to different
   parts of the construction and are easy to cross.

2. **MAC octet ordering is natural; the cipher's is swapped.** The cipher
   writes output halves swapped; the MAC block writes them natural
   (`state[0..3]=n1, state[4..7]=n2`). Reusing the cipher's swapped
   pack/unpack inside the MAC yields wrong tags. See §1 above.

3. **Finalize-on-copy: finalizing must not mutate a running streaming MAC.**
   OpenSSL's `EVP_DigestSignFinal` copies the digest context, finalizes the
   copy, and frees it — the original is left writable, holding the state from
   the last update. With a persistent TLS record context, the next record's
   MAC continues from where the previous one left off. A correct streaming
   MAC's finalize step must snapshot `(state, buffer, bufferLen, count)`, run
   the padding logic on the snapshot, and return the tag, leaving the
   receiver untouched for further writes — the same finalize-on-copy property
   documented for [OMAC](../omac/DESIGN.md).

4. **Deferred last block: process while strictly more than one block
   remains.** A streaming driver processes full blocks while more than 8
   bytes remain unprocessed — strictly greater than 8, not "8 or more" —
   buffering the trailing 1–8 bytes, *including* a complete 8-byte block, for
   the next write or the final call. A complete but unprocessed 8-byte buffer
   is therefore a valid intermediate state. Using "≥ 8" instead would shift
   the block-processing boundary by one block relative to the reference, and
   with it the key-meshing boundary — silently corrupting the tag once a
   stream crosses a 1024-byte boundary. This distinction only matters for a
   streaming driver; a one-shot call over the whole message in hand produces
   the same result regardless of when each block is processed, only *when*
   changes, not *whether*.

5. **Trailing zero block for short messages, lengths 1–8 (§2.1 rule 3).** If
   no full block has been processed ahead of the final one (the whole message
   is ≤ 8 bytes) and a partial remains, one all-zero block is appended
   **after** the (zero-padded) data block, not before it. This also fires for
   exactly-8-byte input.

6. **CryptoPro key meshing every 1024 bytes (RFC 4357 §2.3.2).** The raw
   CBC-MAC construction, without meshing, matches this package's output only
   up to 1024 bytes and diverges afterward — meshing must ECB-*decrypt* the
   constant `C` (§2.3) with the current key, never re-encrypt the MAC state,
   and wrap the counter as `count % 1024 + 8` (§2.4), not to zero.

7. **TLS framing and 4-byte truncation are the record protector's job, not
   the MAC's.** The MAC primitive takes a key and an opaque byte string. The
   TLS MAC input — `seq_num(8) ‖ type(1) ‖ version(2) ‖ length(2) ‖
   plaintext` (RFC 5246 §6.2.3.1 / RFC 9189) — is assembled by the record-layer
   protector, not by this package's `IMIT`. The 8-byte IMIT is then truncated
   to its leading **4 bytes** (RFC 9189 §4.2). This package keeps the MAC
   generic (up to 8 bytes) and truncates only at the call site (`IMIT`
   returns the 4-byte TLS form directly; a caller needing the full 8-byte tag
   or a different truncation drives `SeqMACBlock` itself).

8. **Key-transport IMIT uses a non-zero IV (UKM), and no meshing.** The
   CryptoPro KEK wrap (RFC 4357 §6.3) computes the IMIT over a 32-byte session
   key with `iv = ukm` (8 bytes), not zeros; the wrapped data is exactly 32
   bytes (< 1024), so meshing never fires. This path is implemented inline in
   this module's `keywrap` package rather than through this package's `IMIT`,
   because it needs the UKM as the initial chaining state — this package's
   `IMIT` always uses a zero IV and rejects an empty message rather than
   emitting a key-independent, forgeable constant tag.

## Test vectors

All tags below are 4-byte TLS-truncated IMIT, IV = all zeros, unless noted
otherwise. V1, V2, and V3 are cross-checked against the reference OpenSSL GOST
engine (`gost-engine`, `gost-mac`/`gost-mac-12`).

### V1. 1024 bytes, no meshing (CryptoPro-A)

```
S-box:       CryptoPro-A (1.2.643.2.2.31.1)
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
                   = 30313233343536373839616263646566 30313233343536373839616263646566
message:           "12345670" repeated 128 times  (exactly 1024 bytes, ASCII)
IMIT-4 tag:        2ee8d13d
full IMIT-8 tag:   2ee8d13dff7f037d
```

1024 bytes sits exactly at the meshing boundary but does **not** trigger a
mesh (the check is `count == 1024` *before* a block, and the last block
advances `count` to 1024 *after* finalizing) — so this is the largest input
still equal to the meshing-free MAC.

### V2. >1024 bytes, meshing exercised (CryptoPro-A)

```
S-box:       CryptoPro-A
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
message:           ("12345670" repeated 8 times, then a "\n" byte) repeated 4096 times
                   = 4096 * 65 = 266240 bytes
IMIT-4 tag:        5efab81f
```

This input crosses the 1024-byte boundary 260 times, so an implementation
that omits key meshing or wraps the counter incorrectly will not produce
`5efab81f`.

### V3. Short single- and double-block tags (CryptoPro-A; exercises §2.1)

Key is the V1 key, `"0123456789abcdef0123456789abcdef"` (32B ASCII):

```
msg "12345"             (5 bytes, partial)          -> 77a62d81
msg "12345670"          (8 bytes, one full block)   -> ac2b5ad6
msg "1234567012345670"  (16 bytes, two full blocks) -> 7862d83a
```

The 5-byte and 8-byte rows exercise the trailing all-zero block (§2.1 rule
3); the 16-byte case (two full blocks) does not.

### V4. tc26-Z, 1024 bytes, no meshing (`gost-mac-12`)

```
S-box:       tc26-Z (id-tc26-gost-28147-param-Z)
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
message:           "12345670" repeated 128 times  (1024 bytes)
IMIT-4 tag:        be4453ec
full IMIT-8 tag:   be4453ec1ec327be
```

1024 bytes is the largest meshing-free tc26-Z input for the same reason as
V1: the deferred-block rule means the 128th block is only processed at
finalization, and the mesh check is never reached at exactly 1024 bytes.

### V4b. tc26-Z, 1032 bytes, meshing fires once

```
S-box:       tc26-Z (id-tc26-gost-28147-param-Z)
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
message:           "12345670" repeated 129 times  (1032 bytes)
IMIT-4 tag:        d498623c
full IMIT-8 tag:   d498623c81b21a86
```

This is the primary tc26-Z meshing coverage point: a regression that
hardcodes the CryptoPro-A S-box for the ECB-decrypt step during meshing would
produce a different, wrong tag here.

### V5. `SeqMACBlock` step-1 raw chaining state

```
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
block:             "12345670"
CryptoPro-A state: 832e9da41b6e6d6b
tc26-Z state:      611451608741d776
```

The state returned by `SeqMACBlock` is the *raw* 16-round chaining state
before finalization. It differs from the finalized IMIT of `"12345670"`
(`ac2b5ad6…`) because finalization for an 8-byte input appends a trailing
all-zero block (§2.1 rule 3).

## Conformance testing

The in-package tests (`gost28147imit/imit_test.go`, `gost28147imit/guard_test.go`)
pin all vectors above (`TestIMIT_GuideVectors` for V1–V3, `TestIMIT_TC26Z_1024B_NoMesh`
and `TestIMIT_TC26Z_1032B_Mesh` for V4/V4b, `TestSeqMACBlock_GuideStep1KAT` for V5),
plus `TestIMIT_EngineTclVectors` (additional engine-sourced vectors),
`TestSeqMACBlock_StreamingMatchesIMIT` (a streaming `SeqMACBlock` driver agrees
with the one-shot `IMIT`), and guard tests for bad key/block lengths and the
empty-message panic.

In addition, a differential fuzz harness compares this implementation against
an independent reference implementation over random keys and message lengths
— including all lengths 1–16 bytes and sizes that cross the meshing boundary
— for both S-boxes. IMIT is deterministic, so this is a direct differential
comparison rather than a round-trip.

```sh
go test ./gost28147imit/
```

## References

- **[RFC 5830](rfc/rfc5830.txt)** — "GOST 28147-89: Encryption, Decryption,
  and Message Authentication Code (MAC) Algorithms."
  - §8 — IMIT generation (the 16-round MAC).
  - §5–§7 — the block cipher it builds on (specified in full in
    [`../gost28147/DESIGN.md`](../gost28147/DESIGN.md)).
- **[RFC 4357](rfc/rfc4357.txt)** — "Additional Cryptographic Algorithms for
  Use with GOST 28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R
  34.11-94 Algorithms."
  - §2.3.2 — CryptoPro key meshing.
  - §6.3 — CryptoPro KEK wrap (the non-zero-IV IMIT use, handled by
    `keywrap`).
- **[RFC 9189](rfc/rfc9189.txt)** §4.2 — GOST cipher suites for TLS 1.2:
  IMIT-4 MAC truncation and the GOST-CNT record MAC.
- **[RFC 5246](rfc/rfc5246.txt)** §6.2.3.1 — TLS 1.2 per-record MAC input
  framing (`seq ‖ type ‖ version ‖ length ‖ fragment`), assembled by the
  record-layer protector.
- **GOST 28147-89** — Russian Federal Standard, block cipher + IMIT MAC (the
  normative source republished as RFC 5830).

**Sibling document**

- [`../gost28147/DESIGN.md`](../gost28147/DESIGN.md) — the
  GOST 28147-89 block core: key schedule, S-box byte tables (CryptoPro-A,
  tc26-Z), round function `f`, little-endian octet↔word packing, the
  32-round encrypt/decrypt, and the 16-round `SeqMAC` schedule that the IMIT
  MAC here depends on.
- [`../keywrap/DESIGN.md`](../keywrap/DESIGN.md) — the
  non-zero-IV IMIT used for CryptoPro key transport.

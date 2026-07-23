# Security: `ScalarMult` is not constant-time

`Curve.ScalarMult` is a left-to-right double-and-add over `math/big`. It is
correct and matches gogost/gost-engine bit-for-bit, but it **leaks the scalar
through timing and cache behaviour**. Two call sites feed it *secret* scalars:

- `gost3410sign` — the per-signature nonce `k`.
- `vko` / `keg` — the private key `d`.

`gost3410sign.VerifyDigest` uses only *public* scalars, so it is not
affected. For a reference / interop-validation implementation this is
acceptable and documented. For a **production signer or key-agreement
backend**, use the constant-time `ScalarMultCT` (via `ScalarMultSecret` and
`Curve.ConstantTime`) instead — see [EXPERIMENT-ct.md](EXPERIMENT-ct.md) for
what it covers and its honest limits. It is opt-in, not yet the default at
any call site. The rest of this file records what a constant-time
implementation needs, for context on what `ScalarMultCT` actually does.

## Why the loop fix alone is not enough

`math/big` is itself **not constant-time**: `Add`, `Mul`, `Mod`, `ModInverse`,
etc. run in operand-dependent time (limb count, conditional normalisation).
Replacing the double-and-add with a Montgomery ladder removes the
branch-on-scalar-bit leak but leaves the field-level leak intact — it looks
like a fix without being one. A real fix needs constant-time field
arithmetic, so `math/big` has to go from the hot path entirely.

## What a constant-time implementation needs

1. **Fixed-size limb field arithmetic, Montgomery form.**
   - Represent `GF(p)` elements as fixed arrays of `uint64` (4 limbs for the
     256-bit curves, 8 limbs for the 512-bit curves) in Montgomery domain.
   - Constant-time `add`/`sub`: full-width add/sub then an unconditional
     conditional-subtract / conditional-add of `p` selected by a carry mask —
     no data-dependent branches.
   - Montgomery multiply + reduce (CIOS or FIPS) with no early-exit; squaring
     can share the path.
   - **No fast reduction.** Unlike NIST P-256 (pseudo-Mersenne), the GOST
     primes have no special form, so use generic Montgomery reduction. This is
     the main reason an existing stdlib field (`crypto/elliptic` nistec,
     `filippo.io/nistec`) cannot be reused as-is — only its *structure* can.
   - Constant-time inversion by Fermat exponentiation `a^(p-2)` with a fixed
     addition chain (or a constant-time binary-GCD à la `bernstein-yang`), NOT
     `big.Int.ModInverse` (binary GCD, data-dependent).

2. **Constant-time point arithmetic.**
   - Use Jacobian (or projective) coordinates to avoid a per-addition field
     inversion; invert once at the end.
   - Use **complete** short-Weierstrass addition formulas (Renes–Costello–
     Batina, 2015) so `Add` and `Double` need no special-case branches for the
     identity / equal points — branches there leak.

3. **Constant-time scalar multiplication.**
   - Either a Montgomery ladder (one `Add` + one `Double` per bit with a
     constant-time conditional swap), or a fixed-window method (e.g. 4-bit)
     with a **constant-time table lookup** — scan every table entry and select
     with an arithmetic mask; never index memory by a secret nibble.
   - Iterate the **full bit length** of the group order every time, regardless
     of the scalar's leading zeros.
   - Optionally blind the scalar (`k + r·q` for random `r`) and/or randomise
     projective coordinates as defence-in-depth.

4. **Per-curve coverage.** All of the above must work for both the 256-bit and
   the 512-bit GOST curves (different limb counts and primes). The cofactor-4
   curves additionally need the cofactor applied — see
   `../vko/DESIGN.md` D2; do it with a constant-time scalar
   multiply, not a `math/big` `Lsh`.

## Verification

- Keep the existing KAT and differential tests: the constant-time
  implementation must still equal `ScalarMult` (which itself matches
  gogost/gost-engine) bit-for-bit.
- Add a timing-leakage check: a `dudect`/`ctgrind`-style statistical test, or
  build the field/scalar paths under `valgrind --tool=memcheck` with secrets
  marked uninitialised (`ctgrind`) so any secret-dependent branch/memory
  access is flagged.

This is exactly the verification regime `ScalarMultCT` was built against —
see [EXPERIMENT-ct.md](EXPERIMENT-ct.md) for the differential fuzz, dudect,
and ctgrind results.

## References

- Renes, Costello, Batina, "Complete addition formulas for prime order
  elliptic curves" (EUROCRYPT 2016).
- `crypto/elliptic/internal/nistec` and `filippo.io/nistec` — structure for a
  constant-time Go EC field/point layer (different primes).
- `filippo.io/bigmod` — constant-time `math/big`-shaped modular arithmetic, a
  candidate drop-in for the field layer.
- BearSSL "Constant-Time Crypto" notes; "ctgrind" (Adam Langley).

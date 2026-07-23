# GOST-signed X.509 — certificate parsing and chain verification

This document describes what `package x509gost` does: the certificate wire
format it parses, the chain-building and path-validation rules `Verify`
applies, the implementation notes worth knowing, and the fixtures that pin it.
For the public API and a usage example see the
[package README](README.md).

## What it is

`x509gost` extends Go's standard `crypto/x509` to understand certificates
signed with GOST R 34.10-2001 or GOST R 34.10-2012 (256- or 512-bit), as
profiled onto the base X.509 certificate format
([RFC 5280](rfc/rfc5280.txt)) by [RFC 4491](rfc/rfc4491.txt) (GOST R
34.10-94/2001) and [RFC 9215](rfc/rfc9215.txt) (GOST R 34.10-2012). The
stdlib's `crypto/x509` recognizes none of the GOST OIDs, so it parses a
GOST-signed certificate's structure correctly (extensions, SANs, validity,
Subject/Issuer, `RawTBSCertificate`) but reports
`SignatureAlgorithm == UnknownSignatureAlgorithm` and cannot verify the
signature or build a trust chain. This package always runs the stdlib parser
first — so every non-GOST field stays exactly as `crypto/x509` computes it —
and additionally walks the DER to classify the signature and public-key
algorithm OIDs, extract the raw GOST public key, and (via `Verify`) build and
validate a GOST certificate chain.

It builds entirely on the module's own pure-Go primitives through the
top-level `github.com/tarantool/go-gostcrypto` facade:
[`gost3410sign`](../gost3410sign/DESIGN.md) for signature verification (via
`gost.VerifyDigestOnCurve`) and key generation, [`gost3410curves`](../gost3410curves/DESIGN.md)
for curve/OID resolution (`gost.CurveByOID`) and point sizes, and
[`streebog`](../streebog/DESIGN.md) / `gostr341194` for the TBSCertificate
digest. No third-party ASN.1 or crypto library is used; DER is walked with
`encoding/asn1` and a handful of package-local structs mirroring the relevant
pieces of `TBSCertificate` and `SubjectPublicKeyInfo`.

A certificate that is neither GOST-signed nor GOST-keyed passes straight
through: `ParseCertificate` returns a `*Certificate` with only `.Stdlib` and
`.Raw` set, and `.Verify` delegates entirely to `x509.Certificate.Verify`.

## Specification

### Recognized OIDs

Three independent OID families are checked, each against a fixed set of
values (`oids.go`):

| Family | OIDs | Source |
|---|---|---|
| Signature (`signwithdigest`) | `id-GostR3410-2001-GostR3411` (1.2.643.2.2.3), `id-tc26-signwithdigest-gost3410-12-256` (1.2.643.7.1.1.3.2), `id-tc26-signwithdigest-gost3410-12-512` (1.2.643.7.1.1.3.3) | RFC 4491 §2.1; RFC 9215 §2 |
| Public key | `id-GostR3410-2001` (1.2.643.2.2.19), `id-tc26-gost3410-12-256` (1.2.643.7.1.1.1.1), `id-tc26-gost3410-12-512` (1.2.643.7.1.1.1.2) | RFC 4491 §2.1; RFC 9215 §4.1 |
| Hash | `id-GostR3411-94` (1.2.643.2.2.9), `id-tc26-gost3411-12-256` (1.2.643.7.1.1.2.2), `id-tc26-gost3411-12-512` (1.2.643.7.1.1.2.3) | RFC 4357; RFC 9215 §3 |
| Curve parameter set | CryptoPro-A/B/C (1.2.643.2.2.35.{1,2,3}); TC26 256-bit paramSet A/B/C/D (1.2.643.7.1.2.1.1.{1,2,3,4}); TC26 512-bit paramSet A/B/C (1.2.643.7.1.2.1.2.{1,2,3}) | RFC 4357; RFC 7091 |

`ParseCertificate` classifies the outer `SignatureAlgorithm` OID and the SPKI
`AlgorithmIdentifier.Algorithm` OID independently. A GOST signature OID paired
with a non-GOST public-key OID is rejected (a malformed or adversarial
combination the RFCs don't define); a non-GOST signature OID paired with a
GOST public-key OID is accepted (`HasGOSTPubKey == true`, `IsGOST == false`) —
this is the real-world "RSA-signed cert carrying a GOST key" shape covered by
the `testdata/certs/server_gost*.crt` fixtures.

### SPKI parameters: curve OID extraction

Per RFC 4491 §2.1 (GOST R 34.10-2001) and RFC 9215 §4.2 (GOST R 34.10-2012),
`SubjectPublicKeyInfo.algorithm.parameters` holds a
`GostR3410-2001-ParamSet`/`GostR3410-2012-PublicKeyParameters` SEQUENCE whose
first element is the public-key curve parameter OID (the second, optional,
element is a digest parameter set). RFC 7091 §2 also allows a bare OID with no
enclosing SEQUENCE. `parseCurveOID` tries both: a bare `OID` first, then a
`SEQUENCE { OID, ... }`, taking the first element. Certificates produced by
Tarantool-EE 3.5.0 use the SEQUENCE form; the bare-OID branch is defensive for
other producers. Once the curve OID is known, `gost.CurveByOID` resolves it to
a `*gost3410curves.Curve` (see [gost3410curves/DESIGN.md](../gost3410curves/DESIGN.md)
for the full OID-to-curve table), which supplies the point size used to
validate and disambiguate the public key encoding below.

### SPKI public key: LE(X)||LE(Y), OCTET-STRING or raw

Per RFC 4491 §2.1 / RFC 9215 §4.3, the BIT STRING value of
`SubjectPublicKeyInfo.subjectPublicKey` is a DER `OCTET STRING` whose content
is the raw key: for GOST R 34.10-2012, `2·N` bytes (`N` = 32 for the 256-bit
curve family, 64 for 512-bit) holding the little-endian X coordinate followed
by the little-endian Y coordinate. Some producers omit the `OCTET STRING`
wrapper and place the raw bytes directly in the BIT STRING.
`extractGOSTPubKeyBytes` disambiguates by *length*, not by "which parse
succeeds first": it only accepts an `OCTET STRING` parse when the inner value
is exactly `wantLen` bytes (`2 · curve.PointSize()`), otherwise it falls back
to treating the whole BIT STRING value as the raw key — and either way rejects
a result that isn't exactly `wantLen` bytes. A length-only heuristic without
this care would let a ~2⁻¹⁶ fraction of raw keys whose leading bytes happen to
look like a plausible `OCTET STRING` header be silently mis-parsed into a
shorter, wrong key.

### Signature digest: the signwithdigest OID, not the subject key

RFC 9215 §2 ties the hash used over `TBSCertificate` to the *signature*
(`signwithdigest`) OID, independent of the subject public key's own OID/curve
family:

| `SigGOSTAlgo` (signature OID) | Digest |
|---|---|
| `AlgoR341001` | GOST R 34.11-94 (CryptoPro parameters) |
| `AlgoR341012_256` | Streebog-256 |
| `AlgoR341012_512` | Streebog-512 |

A 256-bit subject key signed by a 512-bit CA therefore has `GOSTAlgo ==
AlgoR341012_256` (subject key family — drives key parsing / VKO-KEX) but
`SigGOSTAlgo == AlgoR341012_512` (drives the hash used to verify this
certificate's own signature). `Certificate.GOSTAlgo` and `.SigGOSTAlgo` are
kept as two separate fields specifically so a caller cannot accidentally use
the subject-key strength to pick the verification digest — see the
`leaf256_signedby512.crt` fixture below, which only verifies with this
distinction respected.

### Verify: chain building and path validation

`(*Certificate).Verify` branches on `IsGOST`:

- **Non-GOST leaf** — delegates entirely to `x509.Certificate.Verify`, then
  re-wraps each returned chain's certificates in `*x509gost.Certificate`
  (`Stdlib` set, GOST fields zero).
- **GOST leaf** — validated directly by this package:
  1. Validity period (`NotBefore`/`NotAfter` against `opts.CurrentTime` or
     `time.Now()`) and, if `opts.DNSName` is set, `x509.VerifyHostname` — both
     using the stdlib-parsed fields, since the stdlib parser gets these right
     for GOST certs too.
  2. Extended key usage: `opts.KeyUsages` is enforced with the *documented*
     semantics on `VerifyOptions.KeyUsages` — pass when the request is empty,
     when it contains `ExtKeyUsageAny`, when the leaf has no EKU extension at
     all, or when the leaf itself asserts `anyExtendedKeyUsage` (RFC 5280
     §4.2.1.12), or when any single requested usage is present. Unlike a
     common stdlib convenience, an empty `KeyUsages` does **not** imply
     `ServerAuth` here.
  3. Chain construction: a depth-bounded (`maxGOSTChainDepth == 8`, leaf
     included) recursive search tries to terminate the chain at a
     `GOSTRoots` entry that directly signed the current certificate, or else
     bridges through a `GOSTIntermediates` entry and recurses. "Signed" means
     `signerOf`: `parent.Stdlib.RawSubject == child.Stdlib.RawIssuer`
     (byte-for-byte, RFC 5280 §4.1.2.4), `parent` currently valid, `parent`
     permitted to sign (`BasicConstraints.IsCA` / `KeyUsage.KeyCertSign` when
     those extensions are present — absent extensions are permitted,
     matching the permissive posture common GOST CAs need), and
     `verifyGOSTSignature(child, parent)` succeeding. A `GOSTRoots` entry
     byte-identical to the leaf is trusted as a one-element chain by
     provision (RFC 5280 §6.1) — no self-signature check is performed on it —
     so a cross-signed CA placed directly in the pool doesn't abort the whole
     search; a tampered self-signed cert still fails because no *other*
     signer verifies it either. Non-GOST entries encountered in either pool
     are skipped and only surface as the dedicated "mixed chain" error if the
     search finds no all-GOST path at all.
  4. Path validation (`validateGOSTChainConstraints`), applied to every
     certificate in the assembled chain — the RFC 5280 checks the stdlib
     applies on the non-GOST path that the GOST-specific walk above would
     otherwise skip:
     - **Unhandled critical extensions** (RFC 5280 §4.2, MUST-reject): any
       cert (leaf included) with a nonempty
       `Stdlib.UnhandledCriticalExtensions` is rejected.
     - **`pathLenConstraint`**: for a CA with `BasicConstraintsValid &&
       MaxPathLen >= 0`, the number of intermediates strictly between it and
       the leaf must not exceed `MaxPathLen`.
     - **Name constraints** (RFC 5280 §4.2.1.10): every CA's *present*
       `PermittedDNSDomains`/`ExcludedDNSDomains`,
       `PermittedIPRanges`/`ExcludedIPRanges`,
       `PermittedEmailAddresses`/`ExcludedEmailAddresses`, and
       `PermittedURIDomains`/`ExcludedURIDomains` are matched against the
       `DNSNames`/`IPAddresses`/`EmailAddresses`/`URIs` of every certificate
       below it in the chain. An absent constraint family imposes nothing; an
       empty *permitted* list of a present family means "everything of that
       type permitted" (mirrors stdlib). The matcher logic in
       `constraints.go` (`matchDomainConstraint`, `matchIPConstraint`,
       `matchEmailConstraint`, `matchURIConstraint`,
       `domainToReverseLabels`, `parseRFC2821Mailbox`, `domainNameValid`) is
       adapted directly from Go's stdlib `crypto/x509/constraints.go` and
       `crypto/x509/verify.go` (BSD-3-Clause, compatible with this module's
       BSD-2-Clause license) — no GPL source was consulted for this file.

`Verify`'s returned chains mirror `x509.Certificate.Verify`'s shape:
`[][]*Certificate`, leaf-first, root-last.

## Implementation notes

1. **The stdlib parser always runs first, unconditionally.** Even for a
   GOST-signed certificate, `ParseCertificate` calls `x509.ParseCertificate`
   before doing any GOST-specific DER walking, so extensions, SANs, validity,
   and `RawTBSCertificate`/`RawSubject`/`RawIssuer` are exactly what the
   stdlib computes (`SignatureAlgorithm` will read
   `UnknownSignatureAlgorithm` for a GOST cert — that's expected and is what
   `IsGOST`/`SigGOSTAlgo` are for).

2. **The TBSCertificate digest must be byte-reversed before verification.**
   GOST signing treats the hash as a little-endian integer ("alpha" in GOST R
   34.10 §6.1), but `gost.VerifyDigestOnCurve` reads the digest big-endian
   (RFC 7091 §5.3 / `gost3410sign.VerifyDigest`). A `hash.Hash.Sum` output is
   in the natural (big-endian-displayed) order, so `verifyGOSTSignature`
   reverses the digest bytes before calling `VerifyDigestOnCurve`. This was
   established empirically against certificates produced by OpenSSL 3 +
   gost-engine 3.0.3 (an implementation independent of this module): with the
   reversed digest they verify, with the raw digest they don't
   (`TestVerify_GOST_ExternalFixture`, `TestVerify_GOST_ExternalChain`).

3. **The public key is always `LE(X) || LE(Y)`, matched by length, not by
   which ASN.1 parse succeeds first.** See "SPKI public key" above —
   `extractGOSTPubKeyBytes` requires the parsed result to be exactly
   `2 · curve.PointSize()` bytes regardless of which of the two encodings
   produced it.

4. **`SigGOSTAlgo` picks the digest; `GOSTAlgo` never does.** The mixed-
   strength case (256-bit leaf key, 512-bit signing CA) is a real scenario
   covered by `leaf256_signedby512.crt`: using the subject key's OID to pick
   the hash (Streebog-256) fails; using the signature OID (Streebog-512)
   succeeds. Any change that starts branching on `GOSTAlgo` for hash
   selection would silently break this fixture.

5. **A `GOSTRoots` entry is trusted by provision, not by a self-signature
   check.** The chain builder does not verify that a root candidate signed
   itself before accepting it as a terminus — it is trusted the same way
   `crypto/x509`'s `CertPool` trusts a root. This is deliberate: an earlier
   version ran a self-signature check on every root match and aborted the
   *entire* search on the first failure, so placing a cross-signed CA
   (signed by a different key than its own) in the pool made verification
   fail even when a valid path through another root existed. The recursive
   search still rejects a genuinely tampered self-signed certificate, because
   no valid signer for it exists anywhere in the pool.

6. **Name-constraint and EKU semantics on the GOST path match stdlib's,
   including stdlib's quirks.** `VerifyOptions.KeyUsages` does *not* default
   an empty slice to `ServerAuth` (a convenience some callers expect from
   `x509.VerifyOptions` in other contexts) — an empty request means
   unconstrained. `issuerIsCA` treats *absent* `BasicConstraints`/`KeyUsage`
   extensions as permissive (common in older GOST CAs that predate strict
   RFC 5280 profiles), matching this package's overall
   permissive-when-unset posture, while a *present* extension is enforced
   exactly.

7. **Chain search is depth-bounded (`maxGOSTChainDepth = 8`, leaf
   included).** A hierarchy deeper than that will not verify; this keeps the
   recursive search finite against pathological or adversarial intermediate
   pools.

## Test vectors

Fixtures live under `testdata/certs/` (described in
[`testdata/certs/README.md`](testdata/certs/README.md), left in place):

- **`ca.crt`, `server_gost.crt`, `server_gost2001.crt`** — an RSA CA and two
  RSA-signed leaves that carry GOST public keys (2012/256-bit and
  2001, respectively) in their SPKI. Captured from a Tarantool-EE interop
  harness (OpenSSL + gost-engine). These exercise the mixed case —
  `HasGOSTPubKey == true`, `IsGOST == false` — parsed via the stdlib
  signature path.
- **`gost256_selfsigned.crt`, `gost512_selfsigned.crt`** — self-signed
  certificates actually GOST-signed by an independent implementation
  (OpenSSL 3 + gost-engine 3.0.3), regenerable with `generate.sh`. These pin
  the certificate wire format itself (signature BIT STRING ordering, the
  `LE(X)||LE(Y)` public key encoding, signwithdigest-vs-pubkey OID handling)
  against a producer that shares none of this package's code, and the
  512-bit one is the only fixture that exercises the Streebog-512 signature
  verification branch.
- **`ca512.crt`, `leaf256_signedby512.crt`** — a 512-bit GOST CA and a
  256-bit leaf it signs with `signwithdigest-512`. This is the mixed-strength
  fixture: it only verifies when the TBSCertificate digest is chosen from
  the signature OID (Streebog-512), not the subject-key OID (Streebog-256).

Beyond the checked-in fixtures, the in-package test suite builds its own
minimal DER certificates on the fly (`certbuilder_test.go`, a test-only
helper — not part of the exported API) to cover cases the static fixtures
don't reach: malformed/truncated DER, GOST-signature-with-non-GOST-pubkey
rejection, expired/not-yet-valid certificates, wrong-signer rejection,
tampered signatures, `pathLenConstraint` enforcement, unhandled critical
extensions, name-constraint permitted/excluded DNS matching, EKU matching
(including `anyExtendedKeyUsage`), multi-level GOST intermediate chains, and
mixed GOST/non-GOST pool ordering. `verify_curve_coverage_test.go` walks
every curve OID `gost.CurveByOID` supports; `key_encoding_roundtrip_test.go`
round-trips SPKI/PKCS#8 PEM/DER encodings across all covered GOST curve
families (2001 CryptoPro A/B/C, 2012/256 TC26 A/B/C/D, 2012/512 TC26 A/B/C).

## Conformance testing

```sh
go test ./x509gost/
```

In addition to the fixed fixtures above, `FuzzParseCertificate`
(`fuzz_test.go`) fuzzes `ParseCertificate` over arbitrary byte input to check
that malformed DER is rejected with an error rather than panicking.

## References

- **[RFC 9215](rfc/rfc9215.txt)** — "Using the GOST R 34.10-2012 and GOST R
  34.11-2012 Algorithms with the Internet X.509 Public Key Infrastructure."
  §2 (signature OIDs, signature-value octet-to-bit-string conversion), §3
  (hash OIDs), §4.1–4.3 (public-key OIDs, parameters SEQUENCE, LE(X)||LE(Y)
  encoding), §4.4 (permitted KeyUsage values).
- **[RFC 4491](rfc/rfc4491.txt)** — "Using the GOST R 34.10-94, GOST R
  34.10-2001, and GOST R 34.11-94 Algorithms with the Internet X.509 Public
  Key Infrastructure Certificate and CRL Profile" (updates RFC 3279). §2.1
  (signature and public-key OIDs, SPKI parameters SEQUENCE).
- **[RFC 5280](rfc/rfc5280.txt)** — "Internet X.509 Public Key Infrastructure
  Certificate and Certificate Revocation List (CRL) Profile." §4.1.2.4
  (Issuer/Subject byte-for-byte matching), §4.2 (critical-extension
  MUST-reject), §4.2.1.10 (name constraints), §4.2.1.12 (extended key usage,
  `anyExtendedKeyUsage`), §6.1 (path validation, trust-anchor provision).
- **[RFC 7091](../gost3410curves/rfc/rfc7091.txt)** — defines the
  `signwithdigest`/public-key OIDs and curve parameter sets for GOST R
  34.10-2012 that RFC 9215 builds on.
- **[gost3410sign/DESIGN.md](../gost3410sign/DESIGN.md)** — the signature
  verification (`VerifyDigestOnCurve`) this package calls, including its own
  digest byte-order convention.
- **[gost3410curves/DESIGN.md](../gost3410curves/DESIGN.md)** — the curve
  parameter sets and OID table behind `gost.CurveByOID`.
- **[streebog/DESIGN.md](../streebog/DESIGN.md)** — the GOST R 34.11-2012
  (Streebog) hash used for the 2012/256 and 2012/512 signature digests.

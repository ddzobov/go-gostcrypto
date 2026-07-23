# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

## [v0.1.0] - 2026-07-23

First public release of go-gostcrypto: a pure-Go, BSD-2-Clause,
zero-dependency clean-room implementation of the GOST cryptographic
primitives and GOST-signed X.509, behind a stable `[]byte` facade plus
directly importable primitive subpackages.

### Added

- Initial public release of `go-gostcrypto`: pure-Go, BSD-2-Clause,
  clean-room GOST cryptographic primitives with zero third-party dependencies.
- Hashes: Streebog (GOST R 34.11-2012, 256/512-bit) and legacy GOST R 34.11-94.
- Block ciphers: Kuznyechik and Magma (GOST R 34.12-2015) and GOST 28147-89.
- Signatures and key agreement: GOST R 34.10 sign/verify and VKO over the
  standard curves.
- Modes and MACs: CTR, CTR-ACPKM, OMAC, MGM, IMIT, KDFTree, TLSTree, KEG,
  KExp15 and CryptoPro key wrap.
- GOST-signed X.509 parsing and verification (`x509gost`).
- Stable `[]byte`-in/`[]byte`-out facade in the root `gostcrypto` package,
  delegating to the directly importable primitive subpackages.

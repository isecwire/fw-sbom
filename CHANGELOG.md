# Changelog

## [1.1.0] - 2026-04-03
### Added
- VEX (Vulnerability Exploitability eXchange) document generation alongside SBOM
- SBOM merge mode (--merge) to combine multiple SBOMs into one
- Component age analysis — flag packages with known EOL dates
- JSON Schema validation of generated SBOMs (--validate)
- Machine-readable summary to stderr when --quiet is used
- Support for scanning Docker/OCI image tarballs directly
### Changed
- Improved OpenSSL version detection accuracy (now handles 1.x and 3.x patterns)
- CycloneDX output updated to spec 1.6
- Faster scanning with parallel file analysis (rayon)
### Fixed
- False positive on "BusyBox" string appearing in documentation files
- Incorrect SHA-256 for symlinked files

## [1.0.0] - 2026-03-20
### Added
- Stable release, production ready
- IEC 62443 CRA compliance attestation header in SBOM output
- Confidence threshold filtering (--min-confidence)
- Component deduplication across detection methods
- Exit code 1 when high-severity components found
### Changed
- Signature database finalized at 54 entries
- SPDX output fully validates against official schema
### Fixed
- Unicode handling in package metadata files

## [0.3.0] - 2026-03-01
### Added
- SBOM diff mode comparing two SBOMs
- CPE/CVE enrichment with built-in database
- Dependency graph output in DOT format
- Kernel config security analysis
- Crypto library detection (AES S-box, SHA constants)
### Changed
- Analyzer now returns structured AnalysisResult
- ELF analysis includes security hardening flags (PIE, RELRO, NX)

## [0.2.0] - 2026-02-15
### Added
- Deep ELF binary analysis (SONAME, NEEDED, build-id, compiler detection)
- License detection engine with SPDX identifier scanning
- Colored terminal output with progress spinner
- Filesystem metadata extraction (os-release, openwrt_release)
- 54 package signatures (up from 20)
- Exclude patterns (--exclude)
### Changed
- CLI restructured with new flags
- Confidence scoring per component

## [0.1.0] - 2025-12-15
### Added
- Initial release
- Firmware directory scanning with string signature matching
- 20 embedded package signatures
- ELF dynamic library detection
- opkg/dpkg metadata parsing
- SPDX 2.3 and CycloneDX 1.5 JSON output
- SHA-256 component hashing
- PURL identifiers

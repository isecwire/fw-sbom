use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A single software component discovered in firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Package name (e.g. "openssl", "busybox").
    pub name: String,
    /// Detected version string, if any.
    pub version: Option<String>,
    /// SHA-256 hash of the file where this component was detected.
    pub sha256: String,
    /// SPDX license identifier, if known.
    pub license: Option<String>,
    /// Package URL (purl) following the purl spec.
    pub purl: Option<String>,
    /// Relative path of the file within the firmware tree.
    pub file_path: String,
    /// Type of detection that identified this component.
    pub detection_method: DetectionMethod,
    /// Confidence score (0.0 to 1.0) for this detection.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// CPE identifier, if enriched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Known CVE identifiers associated with this component version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_cves: Option<Vec<String>>,
}

fn default_confidence() -> f64 {
    0.5
}

/// How a component was identified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionMethod {
    /// Found via string signature in a binary.
    StringSignature,
    /// Found via ELF dynamic library linkage.
    ElfDynamic,
    /// Found via package manager metadata (opkg, dpkg, etc.).
    PackageManager,
    /// Found via deep ELF analysis (.comment, .dynamic sections).
    ElfDeep,
    /// Found via license file scanning.
    LicenseFile,
    /// Found via filesystem metadata (os-release, etc.).
    FilesystemMeta,
    /// Found via crypto constant detection.
    CryptoConstant,
    /// Found via kernel config analysis.
    KernelConfig,
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMethod::StringSignature => write!(f, "string-signature"),
            DetectionMethod::ElfDynamic => write!(f, "elf-dynamic"),
            DetectionMethod::PackageManager => write!(f, "package-manager"),
            DetectionMethod::ElfDeep => write!(f, "elf-deep"),
            DetectionMethod::LicenseFile => write!(f, "license-file"),
            DetectionMethod::FilesystemMeta => write!(f, "filesystem-meta"),
            DetectionMethod::CryptoConstant => write!(f, "crypto-constant"),
            DetectionMethod::KernelConfig => write!(f, "kernel-config"),
        }
    }
}

/// Confidence levels for each detection method.
pub fn method_confidence(method: &DetectionMethod) -> f64 {
    match method {
        DetectionMethod::PackageManager => 0.95,
        DetectionMethod::ElfDeep => 0.75,
        DetectionMethod::ElfDynamic => 0.70,
        DetectionMethod::LicenseFile => 0.65,
        DetectionMethod::FilesystemMeta => 0.90,
        DetectionMethod::KernelConfig => 0.85,
        DetectionMethod::CryptoConstant => 0.60,
        DetectionMethod::StringSignature => 0.50,
    }
}

/// Top-level SBOM document wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    /// Name of the firmware / product.
    pub name: String,
    /// Version of the firmware / product.
    pub version: String,
    /// Timestamp of SBOM generation (RFC 3339).
    pub created: String,
    /// Tool that generated this SBOM.
    pub tool: String,
    /// Unique document identifier.
    pub document_id: String,
    /// All discovered components.
    pub components: Vec<Component>,
    /// Distro information if detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distro_info: Option<DistroInfo>,
    /// ELF dependency edges: (binary_path, library_name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency_edges: Option<Vec<DependencyEdge>>,
}

/// Distribution / OS information extracted from filesystem metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistroInfo {
    pub id: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub build_id: Option<String>,
}

/// A single dependency edge: binary -> library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub binary_path: String,
    pub library: String,
    pub soname: Option<String>,
}

/// ELF metadata extracted from deep analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfMetadata {
    pub path: String,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub build_id: Option<String>,
    pub compiler: Option<String>,
    pub is_pie: bool,
    pub has_relro: bool,
    pub has_stack_canary: bool,
    pub has_nx: bool,
}

/// Result of SBOM diff comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDiff {
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
    pub version_changed: Vec<VersionChange>,
    pub unchanged_count: usize,
}

/// A component entry in the diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
}

/// A version change between two SBOMs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionChange {
    pub name: String,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
}

/// Supported SBOM output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    Spdx,
    CycloneDx,
}

impl std::fmt::Display for SbomFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SbomFormat::Spdx => write!(f, "spdx"),
            SbomFormat::CycloneDx => write!(f, "cyclonedx"),
        }
    }
}

impl std::str::FromStr for SbomFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "spdx" => Ok(SbomFormat::Spdx),
            "cyclonedx" => Ok(SbomFormat::CycloneDx),
            other => Err(format!(
                "unknown SBOM format '{}', expected 'spdx' or 'cyclonedx'",
                other
            )),
        }
    }
}

/// License detection result from scanning files.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LicenseDetection {
    pub file_path: String,
    pub spdx_id: String,
    pub confidence: f64,
    pub source: LicenseSource,
}

/// Where a license was detected.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum LicenseSource {
    /// Detected from a LICENSE/COPYING file.
    DedicatedFile,
    /// Detected from SPDX header in source code.
    SpdxHeader,
    /// Mapped from a known package name.
    PackageMapping,
}

/// CPE dictionary entry for vulnerability enrichment.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CpeEntry {
    pub package_pattern: String,
    pub vendor: String,
    pub product: String,
    pub cpe_prefix: String,
    /// Known vulnerable version ranges (simplified).
    pub known_cves: Vec<CveHint>,
}

/// A CVE hint for a particular version range.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CveHint {
    pub cve_id: String,
    pub affected_versions: String,
    pub severity: String,
}

/// Kernel security configuration analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSecurityConfig {
    pub stack_protector: Option<bool>,
    pub aslr: Option<bool>,
    pub selinux: Option<bool>,
    pub apparmor: Option<bool>,
    pub seccomp: Option<bool>,
    pub modules_disabled: Option<bool>,
    pub hardened_usercopy: Option<bool>,
    pub fortify_source: Option<bool>,
}

/// Aggregated analysis statistics.
#[derive(Debug, Clone, Default)]
pub struct AnalysisStats {
    pub files_scanned: usize,
    pub elf_binaries: usize,
    pub components_found: usize,
    pub by_method: HashMap<String, usize>,
    pub by_license: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn component_creation_and_field_access() {
        let c = Component {
            name: "openssl".to_string(),
            version: Some("3.1.0".to_string()),
            sha256: "abc123".to_string(),
            license: Some("Apache-2.0".to_string()),
            purl: Some("pkg:generic/openssl@3.1.0".to_string()),
            file_path: "usr/lib/libssl.so.3".to_string(),
            detection_method: DetectionMethod::ElfDynamic,
            confidence: 0.7,
            cpe: None,
            known_cves: None,
        };

        assert_eq!(c.name, "openssl");
        assert_eq!(c.version.as_deref(), Some("3.1.0"));
        assert_eq!(c.sha256, "abc123");
        assert_eq!(c.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(c.purl.as_deref(), Some("pkg:generic/openssl@3.1.0"));
        assert_eq!(c.file_path, "usr/lib/libssl.so.3");
        assert_eq!(c.detection_method, DetectionMethod::ElfDynamic);
        assert!((c.confidence - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn component_with_no_version() {
        let c = Component {
            name: "zlib".to_string(),
            version: None,
            sha256: "def456".to_string(),
            license: None,
            purl: Some("pkg:generic/zlib".to_string()),
            file_path: "usr/lib/libz.so".to_string(),
            detection_method: DetectionMethod::StringSignature,
            confidence: 0.5,
            cpe: None,
            known_cves: None,
        };

        assert!(c.version.is_none());
        assert!(c.license.is_none());
        assert_eq!(c.detection_method, DetectionMethod::StringSignature);
    }

    #[test]
    fn component_clone_is_independent() {
        let c1 = Component {
            name: "busybox".to_string(),
            version: Some("1.36.1".to_string()),
            sha256: "aaa".to_string(),
            license: Some("GPL-2.0-only".to_string()),
            purl: None,
            file_path: "bin/busybox".to_string(),
            detection_method: DetectionMethod::StringSignature,
            confidence: 0.5,
            cpe: None,
            known_cves: None,
        };
        let mut c2 = c1.clone();
        c2.name = "modified".to_string();
        assert_eq!(c1.name, "busybox");
        assert_eq!(c2.name, "modified");
    }

    #[test]
    fn sbom_format_parse_spdx() {
        let fmt: SbomFormat = "spdx".parse().unwrap();
        assert_eq!(fmt, SbomFormat::Spdx);
    }

    #[test]
    fn sbom_format_parse_spdx_case_insensitive() {
        let fmt: SbomFormat = "SPDX".parse().unwrap();
        assert_eq!(fmt, SbomFormat::Spdx);

        let fmt: SbomFormat = "Spdx".parse().unwrap();
        assert_eq!(fmt, SbomFormat::Spdx);
    }

    #[test]
    fn sbom_format_parse_cyclonedx() {
        let fmt: SbomFormat = "cyclonedx".parse().unwrap();
        assert_eq!(fmt, SbomFormat::CycloneDx);
    }

    #[test]
    fn sbom_format_parse_cyclonedx_case_insensitive() {
        let fmt: SbomFormat = "CycloneDX".parse().unwrap();
        assert_eq!(fmt, SbomFormat::CycloneDx);
    }

    #[test]
    fn sbom_format_parse_unknown_returns_error() {
        let result: Result<SbomFormat, String> = "xml".parse();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown SBOM format"));
    }

    #[test]
    fn sbom_format_display() {
        assert_eq!(format!("{}", SbomFormat::Spdx), "spdx");
        assert_eq!(format!("{}", SbomFormat::CycloneDx), "cyclonedx");
    }

    #[test]
    fn purl_with_version() {
        let purl = "pkg:generic/openssl@3.1.0";
        assert!(purl.starts_with("pkg:generic/"));
        assert!(purl.contains('@'));
        assert!(purl.ends_with("3.1.0"));
    }

    #[test]
    fn purl_without_version() {
        let purl = "pkg:generic/openssl";
        assert!(purl.starts_with("pkg:generic/"));
        assert!(!purl.contains('@'));
    }

    #[test]
    fn detection_method_equality() {
        assert_eq!(DetectionMethod::StringSignature, DetectionMethod::StringSignature);
        assert_eq!(DetectionMethod::ElfDynamic, DetectionMethod::ElfDynamic);
        assert_eq!(DetectionMethod::PackageManager, DetectionMethod::PackageManager);
        assert_ne!(DetectionMethod::StringSignature, DetectionMethod::ElfDynamic);
    }

    #[test]
    fn detection_method_display() {
        assert_eq!(format!("{}", DetectionMethod::StringSignature), "string-signature");
        assert_eq!(format!("{}", DetectionMethod::PackageManager), "package-manager");
        assert_eq!(format!("{}", DetectionMethod::ElfDeep), "elf-deep");
    }

    #[test]
    fn sbom_document_creation() {
        let doc = SbomDocument {
            name: "test-firmware".to_string(),
            version: "1.0.0".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            tool: "fw-sbom 0.2.0".to_string(),
            document_id: "test-uuid-1234".to_string(),
            components: vec![],
            distro_info: None,
            dependency_edges: None,
        };

        assert_eq!(doc.name, "test-firmware");
        assert_eq!(doc.version, "1.0.0");
        assert!(doc.components.is_empty());
    }

    #[test]
    fn component_serializes_to_json() {
        let c = Component {
            name: "curl".to_string(),
            version: Some("8.0.0".to_string()),
            sha256: "abcdef".to_string(),
            license: Some("MIT".to_string()),
            purl: Some("pkg:generic/curl@8.0.0".to_string()),
            file_path: "usr/bin/curl".to_string(),
            detection_method: DetectionMethod::StringSignature,
            confidence: 0.5,
            cpe: None,
            known_cves: None,
        };

        let json_str = serde_json::to_string(&c).unwrap();
        assert!(json_str.contains("\"name\":\"curl\""));
        assert!(json_str.contains("\"version\":\"8.0.0\""));
        assert!(json_str.contains("\"confidence\":0.5"));
    }

    #[test]
    fn confidence_levels_are_ordered() {
        let pkg = method_confidence(&DetectionMethod::PackageManager);
        let elf_deep = method_confidence(&DetectionMethod::ElfDeep);
        let elf_dyn = method_confidence(&DetectionMethod::ElfDynamic);
        let sig = method_confidence(&DetectionMethod::StringSignature);

        assert!(pkg > elf_deep);
        assert!(elf_deep > sig);
        assert!(elf_dyn > sig);
    }

    #[test]
    fn sbom_diff_serializes() {
        let diff = SbomDiff {
            added: vec![DiffEntry {
                name: "curl".to_string(),
                version: Some("8.0.0".to_string()),
                license: Some("MIT".to_string()),
            }],
            removed: vec![],
            version_changed: vec![VersionChange {
                name: "openssl".to_string(),
                old_version: Some("3.0.0".to_string()),
                new_version: Some("3.1.0".to_string()),
            }],
            unchanged_count: 5,
        };
        let json = serde_json::to_string(&diff).unwrap();
        assert!(json.contains("curl"));
        assert!(json.contains("openssl"));
    }
}

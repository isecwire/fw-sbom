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


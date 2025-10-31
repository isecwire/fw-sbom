//! SBOM merge engine.
//!
//! Loads multiple SBOM files (SPDX 2.3 or CycloneDX 1.5/1.6 JSON),
//! merges their component lists, deduplicates by name+version, and
//! outputs a single unified SBOM.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::models::{Component, DetectionMethod, SbomDocument, SbomFormat};
use crate::sbom;

/// Load an SBOM file and extract components from it.
/// Supports both SPDX 2.3 and CycloneDX 1.5/1.6 JSON formats.
pub fn load_sbom_components(path: &Path) -> Result<Vec<Component>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading SBOM: {}", path.display()))?;

    let doc: Value = serde_json::from_str(&content)
        .with_context(|| format!("parsing JSON from {}", path.display()))?;

    if doc.get("spdxVersion").is_some() {
        load_spdx_components(&doc)
    } else if doc.get("bomFormat").is_some() {
        load_cyclonedx_components(&doc)
    } else {
        bail!(
            "unrecognized SBOM format in {}: expected SPDX or CycloneDX JSON",
            path.display()
        );
    }
}

/// Extract components from an SPDX 2.3 JSON document.
fn load_spdx_components(doc: &Value) -> Result<Vec<Component>> {
    let packages = doc
        .get("packages")
        .and_then(|p| p.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    let mut components = Vec::with_capacity(packages.len());

    for pkg in packages {
        let name = pkg
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let version = pkg
            .get("versionInfo")
            .and_then(|v| v.as_str())
            .and_then(|v| if v == "NOASSERTION" { None } else { Some(v) })
            .map(|v| v.to_string());

        let license = pkg
            .get("licenseConcluded")
            .and_then(|v| v.as_str())
            .and_then(|v| if v == "NOASSERTION" { None } else { Some(v) })
            .map(|v| v.to_string());

        let sha256 = pkg
            .get("checksums")
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|cs| {
                    if cs.get("algorithm")?.as_str()? == "SHA256" {
                        cs.get("checksumValue")?.as_str().map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();

        let purl = pkg
            .get("externalRefs")
            .and_then(|r| r.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|r| {
                    if r.get("referenceType")?.as_str()? == "purl" {
                        r.get("referenceLocator")?.as_str().map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            });

        components.push(Component {
            name,
            version,
            sha256,
            license,
            purl,
            file_path: String::new(),
            detection_method: DetectionMethod::PackageManager,
            confidence: 0.8,
            cpe: None,
            known_cves: None,
        });
    }

    Ok(components)
}

/// Extract components from a CycloneDX 1.5/1.6 JSON document.
fn load_cyclonedx_components(doc: &Value) -> Result<Vec<Component>> {
    let cdx_components = doc
        .get("components")
        .and_then(|c| c.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    let mut components = Vec::with_capacity(cdx_components.len());

    for comp in cdx_components {
        let name = comp
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let version = comp
            .get("version")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());

        let license = comp
            .get("licenses")
            .and_then(|l| l.as_array())
            .and_then(|arr| arr.first())
            .and_then(|l| l.get("license"))
            .and_then(|l| l.get("id"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());

        let sha256 = comp
            .get("hashes")
            .and_then(|h| h.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|h| {
                    if h.get("alg")?.as_str()? == "SHA-256" {
                        h.get("content")?.as_str().map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();

        let purl = comp
            .get("purl")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());

        components.push(Component {
            name,
            version,
            sha256,
            license,
            purl,
            file_path: String::new(),
            detection_method: DetectionMethod::PackageManager,
            confidence: 0.8,
            cpe: None,
            known_cves: None,
        });
    }

    Ok(components)
}

/// Merge multiple sets of components, deduplicating by (name, version).
/// When duplicates exist, the entry with more metadata wins.
pub fn merge_components(component_sets: Vec<Vec<Component>>) -> Vec<Component> {
    let mut dedup: HashMap<String, Component> = HashMap::new();

    for set in component_sets {
        for comp in set {
            let key = format!(
                "{}@{}",
                comp.name,
                comp.version.as_deref().unwrap_or("unknown")
            );
            dedup
                .entry(key)
                .and_modify(|existing| {
                    // Prefer the entry with more info.
                    if comp.confidence > existing.confidence
                        || (existing.license.is_none() && comp.license.is_some())
                        || (existing.purl.is_none() && comp.purl.is_some())
                    {
                        *existing = comp.clone();
                    }
                })
                .or_insert(comp);
        }
    }

    let mut result: Vec<Component> = dedup.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Merge multiple SBOM files into a single SBOM document.
/// Returns the rendered SBOM string in the requested format.
pub fn merge_sbom_files(
    paths: &[&Path],
    output_format: SbomFormat,
    product_name: &str,
    product_version: &str,
) -> Result<String> {
    if paths.is_empty() {
        bail!("no SBOM files provided for merge");
    }

    let mut all_sets = Vec::with_capacity(paths.len());
    for path in paths {
        let components = load_sbom_components(path)
            .with_context(|| format!("loading SBOM for merge: {}", path.display()))?;
        all_sets.push(components);
    }

    let merged = merge_components(all_sets);

    let doc = SbomDocument {
        name: product_name.to_string(),
        version: product_version.to_string(),
        created: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        tool: format!("fw-sbom {}", env!("CARGO_PKG_VERSION")),
        document_id: Uuid::new_v4().to_string(),
        components: merged,
        distro_info: None,
        dependency_edges: None,
    };

    sbom::generate(&doc, output_format)
}


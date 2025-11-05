//! SBOM comparison / diff engine.
//!
//! Compares two SBOM documents and produces a structured diff showing
//! added, removed, and version-changed components.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::models::{DiffEntry, SbomDiff, SbomDocument, VersionChange};

/// Compare two SBOM JSON files and produce a diff.
pub fn diff_sbom_files(old_path: &Path, new_path: &Path) -> Result<SbomDiff> {
    let old_doc = load_sbom(old_path)
        .with_context(|| format!("loading old SBOM from {}", old_path.display()))?;
    let new_doc = load_sbom(new_path)
        .with_context(|| format!("loading new SBOM from {}", new_path.display()))?;

    Ok(diff_sbom_documents(&old_doc, &new_doc))
}

/// Load an SBOM document from a JSON file.
/// Supports both our native format and SPDX/CycloneDX by extracting component names.
fn load_sbom(path: &Path) -> Result<SbomDocument> {
    let content = fs::read_to_string(path).context("reading SBOM file")?;
    let value: serde_json::Value = serde_json::from_str(&content).context("parsing JSON")?;

    // Try native format first.
    if let Ok(doc) = serde_json::from_value::<SbomDocument>(value.clone()) {
        return Ok(doc);
    }

    // Try SPDX format.
    if value.get("spdxVersion").is_some() {
        return parse_spdx_to_doc(&value);
    }

    // Try CycloneDX format.
    if value.get("bomFormat").is_some() {
        return parse_cyclonedx_to_doc(&value);
    }

    anyhow::bail!("unrecognized SBOM format");
}

/// Parse an SPDX JSON document into our internal SbomDocument.
fn parse_spdx_to_doc(value: &serde_json::Value) -> Result<SbomDocument> {
    let name = value["name"].as_str().unwrap_or("unknown").to_string();
    let packages = value["packages"].as_array();

    let mut components = Vec::new();
    if let Some(pkgs) = packages {
        for pkg in pkgs {
            let pkg_name = pkg["name"].as_str().unwrap_or("unknown");
            let version = pkg["versionInfo"].as_str().and_then(|v| {
                if v == "NOASSERTION" { None } else { Some(v.to_string()) }
            });
            let license = pkg["licenseConcluded"].as_str().and_then(|v| {
                if v == "NOASSERTION" { None } else { Some(v.to_string()) }
            });

            components.push(crate::models::Component {
                name: pkg_name.to_string(),
                version,
                sha256: String::new(),
                license,
                purl: pkg.get("externalRefs")
                    .and_then(|refs| refs.as_array())
                    .and_then(|refs| refs.first())
                    .and_then(|r| r["referenceLocator"].as_str())
                    .map(|s| s.to_string()),
                file_path: String::new(),
                detection_method: crate::models::DetectionMethod::StringSignature,
                confidence: 0.5,
                cpe: None,
                known_cves: None,
            });
        }
    }

    Ok(SbomDocument {
        name,
        version: String::new(),
        created: value["creationInfo"]["created"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        tool: String::new(),
        document_id: String::new(),
        components,
        distro_info: None,
        dependency_edges: None,
    })
}

/// Parse a CycloneDX JSON document into our internal SbomDocument.
fn parse_cyclonedx_to_doc(value: &serde_json::Value) -> Result<SbomDocument> {
    let name = value["metadata"]["component"]["name"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let cdx_components = value["components"].as_array();

    let mut components = Vec::new();
    if let Some(comps) = cdx_components {
        for comp in comps {
            let comp_name = comp["name"].as_str().unwrap_or("unknown");
            let version = comp["version"].as_str().map(|s| s.to_string());
            let license = comp.get("licenses")
                .and_then(|l| l.as_array())
                .and_then(|l| l.first())
                .and_then(|l| l["license"]["id"].as_str())
                .map(|s| s.to_string());

            components.push(crate::models::Component {
                name: comp_name.to_string(),
                version,
                sha256: String::new(),
                license,
                purl: comp["purl"].as_str().map(|s| s.to_string()),
                file_path: String::new(),
                detection_method: crate::models::DetectionMethod::StringSignature,
                confidence: 0.5,
                cpe: None,
                known_cves: None,
            });
        }
    }

    Ok(SbomDocument {
        name,
        version: value["metadata"]["component"]["version"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        created: value["metadata"]["timestamp"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        tool: String::new(),
        document_id: String::new(),
        components,
        distro_info: None,
        dependency_edges: None,
    })
}

/// Compare two SbomDocuments and produce a diff.
pub fn diff_sbom_documents(old: &SbomDocument, new: &SbomDocument) -> SbomDiff {
    // Build maps: name -> (version, license).
    let old_map: HashMap<&str, (Option<&str>, Option<&str>)> = old
        .components
        .iter()
        .map(|c| {
            (
                c.name.as_str(),
                (c.version.as_deref(), c.license.as_deref()),
            )
        })
        .collect();

    let new_map: HashMap<&str, (Option<&str>, Option<&str>)> = new
        .components
        .iter()
        .map(|c| {
            (
                c.name.as_str(),
                (c.version.as_deref(), c.license.as_deref()),
            )
        })
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut version_changed = Vec::new();
    let mut unchanged_count = 0;

    // Find removed and version-changed.
    for (name, (old_ver, old_lic)) in &old_map {
        if let Some((new_ver, _new_lic)) = new_map.get(name) {
            if old_ver != new_ver {
                version_changed.push(VersionChange {
                    name: name.to_string(),
                    old_version: old_ver.map(|s| s.to_string()),
                    new_version: new_ver.map(|s| s.to_string()),
                });
            } else {
                unchanged_count += 1;
            }
        } else {
            removed.push(DiffEntry {
                name: name.to_string(),
                version: old_ver.map(|s| s.to_string()),
                license: old_lic.map(|s| s.to_string()),
            });
        }
    }

    // Find added.
    for (name, (new_ver, new_lic)) in &new_map {
        if !old_map.contains_key(name) {
            added.push(DiffEntry {
                name: name.to_string(),
                version: new_ver.map(|s| s.to_string()),
                license: new_lic.map(|s| s.to_string()),
            });
        }
    }

    // Sort for deterministic output.
    added.sort_by(|a, b| a.name.cmp(&b.name));
    removed.sort_by(|a, b| a.name.cmp(&b.name));
    version_changed.sort_by(|a, b| a.name.cmp(&b.name));

    SbomDiff {
        added,
        removed,
        version_changed,
        unchanged_count,
    }
}

/// Format an SBOM diff as a human-readable string.
#[allow(dead_code)]
pub fn format_diff(diff: &SbomDiff) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "SBOM Diff: {} added, {} removed, {} version-changed, {} unchanged\n",
        diff.added.len(),
        diff.removed.len(),
        diff.version_changed.len(),
        diff.unchanged_count,
    ));
    out.push_str(&"-".repeat(70));
    out.push('\n');

    if !diff.added.is_empty() {
        out.push_str("\nAdded components:\n");
        for entry in &diff.added {
            out.push_str(&format!(
                "  + {} {}\n",
                entry.name,
                entry.version.as_deref().unwrap_or("(no version)")
            ));
        }
    }

    if !diff.removed.is_empty() {
        out.push_str("\nRemoved components:\n");
        for entry in &diff.removed {
            out.push_str(&format!(
                "  - {} {}\n",
                entry.name,
                entry.version.as_deref().unwrap_or("(no version)")
            ));
        }
    }

    if !diff.version_changed.is_empty() {
        out.push_str("\nVersion changes:\n");
        for change in &diff.version_changed {
            out.push_str(&format!(
                "  ~ {} : {} -> {}\n",
                change.name,
                change.old_version.as_deref().unwrap_or("(none)"),
                change.new_version.as_deref().unwrap_or("(none)"),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Component, DetectionMethod, SbomDocument};

    fn make_component(name: &str, version: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: version.map(|s| s.to_string()),
            sha256: String::new(),
            license: Some("MIT".to_string()),
            purl: None,
            file_path: String::new(),
            detection_method: DetectionMethod::StringSignature,
            confidence: 0.5,
            cpe: None,
            known_cves: None,
        }
    }

    fn make_doc(components: Vec<Component>) -> SbomDocument {
        SbomDocument {
            name: "test".to_string(),
            version: "1.0".to_string(),
            created: String::new(),
            tool: String::new(),
            document_id: String::new(),
            components,
            distro_info: None,
            dependency_edges: None,
        }
    }

    #[test]
    fn diff_detects_added_component() {
        let old = make_doc(vec![make_component("curl", Some("8.0"))]);
        let new = make_doc(vec![
            make_component("curl", Some("8.0")),
            make_component("zlib", Some("1.3")),
        ]);

        let diff = diff_sbom_documents(&old, &new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "zlib");
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.unchanged_count, 1);
    }

    #[test]
    fn diff_detects_removed_component() {
        let old = make_doc(vec![
            make_component("curl", Some("8.0")),
            make_component("zlib", Some("1.3")),
        ]);
        let new = make_doc(vec![make_component("curl", Some("8.0"))]);

        let diff = diff_sbom_documents(&old, &new);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].name, "zlib");
        assert_eq!(diff.added.len(), 0);
    }

    #[test]
    fn diff_detects_version_change() {
        let old = make_doc(vec![make_component("openssl", Some("3.0.0"))]);
        let new = make_doc(vec![make_component("openssl", Some("3.1.0"))]);

        let diff = diff_sbom_documents(&old, &new);
        assert_eq!(diff.version_changed.len(), 1);
        assert_eq!(diff.version_changed[0].name, "openssl");
        assert_eq!(diff.version_changed[0].old_version.as_deref(), Some("3.0.0"));
        assert_eq!(diff.version_changed[0].new_version.as_deref(), Some("3.1.0"));
    }

    #[test]
    fn diff_identical_sboms() {
        let old = make_doc(vec![
            make_component("curl", Some("8.0")),
            make_component("zlib", Some("1.3")),
        ]);
        let new = old.clone();

        let diff = diff_sbom_documents(&old, &new);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.version_changed.len(), 0);
        assert_eq!(diff.unchanged_count, 2);
    }

    #[test]
    fn format_diff_output() {
        let diff = SbomDiff {
            added: vec![DiffEntry {
                name: "nginx".to_string(),
                version: Some("1.25.0".to_string()),
                license: Some("BSD-2-Clause".to_string()),
            }],
            removed: vec![DiffEntry {
                name: "lighttpd".to_string(),
                version: Some("1.4.71".to_string()),
                license: Some("BSD-3-Clause".to_string()),
            }],
            version_changed: vec![VersionChange {
                name: "openssl".to_string(),
                old_version: Some("3.0.0".to_string()),
                new_version: Some("3.1.0".to_string()),
            }],
            unchanged_count: 5,
        };

        let output = format_diff(&diff);
        assert!(output.contains("1 added"));
        assert!(output.contains("1 removed"));
        assert!(output.contains("1 version-changed"));
        assert!(output.contains("+ nginx"));
        assert!(output.contains("- lighttpd"));
        assert!(output.contains("~ openssl"));
    }
}

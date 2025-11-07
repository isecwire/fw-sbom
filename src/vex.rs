//! OpenVEX document generation.
//!
//! Produces a VEX (Vulnerability Exploitability eXchange) document that
//! accompanies an SBOM, describing the exploitability status of known
//! vulnerabilities for each component.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::models::Component;

/// VEX status for a given vulnerability / component pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    Affected,
    NotAffected,
    UnderInvestigation,
    Fixed,
}

impl std::fmt::Display for VexStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VexStatus::Affected => write!(f, "affected"),
            VexStatus::NotAffected => write!(f, "not_affected"),
            VexStatus::UnderInvestigation => write!(f, "under_investigation"),
            VexStatus::Fixed => write!(f, "fixed"),
        }
    }
}

/// Justification when a component is marked `not_affected`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

impl std::fmt::Display for VexJustification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VexJustification::ComponentNotPresent => write!(f, "component_not_present"),
            VexJustification::VulnerableCodeNotPresent => write!(f, "vulnerable_code_not_present"),
            VexJustification::VulnerableCodeNotInExecutePath => {
                write!(f, "vulnerable_code_not_in_execute_path")
            }
            VexJustification::VulnerableCodeCannotBeControlledByAdversary => {
                write!(f, "vulnerable_code_cannot_be_controlled_by_adversary")
            }
            VexJustification::InlineMitigationsAlreadyExist => {
                write!(f, "inline_mitigations_already_exist")
            }
        }
    }
}

/// A single VEX statement linking a vulnerability to a product/component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexStatement {
    pub vulnerability_id: String,
    pub status: VexStatus,
    pub justification: Option<VexJustification>,
    pub component_name: String,
    pub component_version: Option<String>,
    pub component_purl: Option<String>,
    pub impact_statement: Option<String>,
}

/// Generate an OpenVEX JSON document for the given components and their
/// known CVE associations. The `sbom_document_id` links this VEX back
/// to the SBOM it accompanies.
pub fn generate_vex_document(
    components: &[Component],
    sbom_document_id: &str,
    product_name: &str,
) -> Value {
    let vex_id = format!("urn:uuid:{}", Uuid::new_v4());
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let statements: Vec<Value> = build_vex_statements(components)
        .into_iter()
        .map(|stmt| {
            let mut obj = json!({
                "vulnerability": {
                    "@id": format!("https://nvd.nist.gov/vuln/detail/{}", stmt.vulnerability_id),
                    "name": stmt.vulnerability_id,
                },
                "products": [
                    {
                        "@id": stmt.component_purl.as_deref().unwrap_or("unknown"),
                        "identifiers": {
                            "purl": stmt.component_purl.as_deref().unwrap_or("unknown"),
                        },
                    }
                ],
                "status": stmt.status.to_string(),
            });

            if let Some(ref justification) = stmt.justification {
                obj.as_object_mut()
                    .unwrap()
                    .insert("justification".to_string(), json!(justification.to_string()));
            }

            if let Some(ref impact) = stmt.impact_statement {
                obj.as_object_mut()
                    .unwrap()
                    .insert("impact_statement".to_string(), json!(impact));
            }

            obj
        })
        .collect();

    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": vex_id,
        "author": "fw-sbom",
        "role": "tool",
        "timestamp": timestamp,
        "version": 1,
        "tooling": format!("fw-sbom {}", env!("CARGO_PKG_VERSION")),
        "statements": statements,
        "metadata": {
            "sbom_document_id": sbom_document_id,
            "product_name": product_name,
        }
    })
}

/// Build VEX statements from components that have known CVEs.
///
/// Components with CVE hints are marked `under_investigation` by default,
/// since we cannot automatically confirm exploitability.
pub fn build_vex_statements(components: &[Component]) -> Vec<VexStatement> {
    let mut statements = Vec::new();

    for comp in components {
        if let Some(ref cves) = comp.known_cves {
            for cve_id in cves {
                statements.push(VexStatement {
                    vulnerability_id: cve_id.clone(),
                    status: VexStatus::UnderInvestigation,
                    justification: None,
                    component_name: comp.name.clone(),
                    component_version: comp.version.clone(),
                    component_purl: comp.purl.clone(),
                    impact_statement: Some(format!(
                        "Component {} {} detected in firmware; exploitability not yet assessed.",
                        comp.name,
                        comp.version.as_deref().unwrap_or("(unknown version)")
                    )),
                });
            }
        }
    }

    statements
}

/// Write VEX document to a file path, deriving the path from the SBOM output path.
pub fn vex_output_path(sbom_path: &std::path::Path) -> std::path::PathBuf {
    let stem = sbom_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("sbom");
    // Strip .spdx or .cdx suffix if present for cleaner naming.
    let clean_stem = stem
        .strip_suffix(".spdx")
        .or_else(|| stem.strip_suffix(".cdx"))
        .unwrap_or(stem);
    let parent = sbom_path.parent().unwrap_or(std::path::Path::new("."));
    parent.join(format!("{}.vex.json", clean_stem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DetectionMethod;

    fn sample_component_with_cves() -> Component {
        Component {
            name: "openssl".to_string(),
            version: Some("3.1.0".to_string()),
            sha256: "abc123".to_string(),
            license: Some("Apache-2.0".to_string()),
            purl: Some("pkg:generic/openssl@3.1.0".to_string()),
            file_path: "usr/lib/libssl.so.3".to_string(),
            detection_method: DetectionMethod::ElfDynamic,
            confidence: 0.7,
            cpe: Some("cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*".to_string()),
            known_cves: Some(vec![
                "CVE-2024-5535".to_string(),
                "CVE-2023-5678".to_string(),
            ]),
        }
    }

    fn sample_component_no_cves() -> Component {
        Component {
            name: "zlib".to_string(),
            version: Some("1.3.1".to_string()),
            sha256: "def456".to_string(),
            license: Some("Zlib".to_string()),
            purl: Some("pkg:generic/zlib@1.3.1".to_string()),
            file_path: "usr/lib/libz.so.1".to_string(),
            detection_method: DetectionMethod::ElfDynamic,
            confidence: 0.7,
            cpe: None,
            known_cves: None,
        }
    }

    #[test]
    fn build_statements_from_component_with_cves() {
        let comp = sample_component_with_cves();
        let stmts = build_vex_statements(&[comp]);
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0].vulnerability_id, "CVE-2024-5535");
        assert_eq!(stmts[0].status, VexStatus::UnderInvestigation);
        assert_eq!(stmts[0].component_name, "openssl");
        assert!(stmts[0].impact_statement.is_some());
    }

    #[test]
    fn build_statements_skips_components_without_cves() {
        let comp = sample_component_no_cves();
        let stmts = build_vex_statements(&[comp]);
        assert!(stmts.is_empty());
    }

    #[test]
    fn generate_vex_document_has_required_fields() {
        let comp = sample_component_with_cves();
        let doc = generate_vex_document(&[comp], "test-sbom-id", "test-product");

        assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
        assert!(doc["@id"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(doc["author"], "fw-sbom");
        assert_eq!(doc["version"], 1);
        assert!(doc["statements"].is_array());
        assert_eq!(doc["statements"].as_array().unwrap().len(), 2);
        assert_eq!(doc["metadata"]["sbom_document_id"], "test-sbom-id");
        assert_eq!(doc["metadata"]["product_name"], "test-product");
    }

    #[test]
    fn vex_statement_contains_vulnerability_and_product() {
        let comp = sample_component_with_cves();
        let doc = generate_vex_document(&[comp], "sbom-1", "fw");
        let stmt = &doc["statements"][0];

        assert!(stmt["vulnerability"]["name"].as_str().unwrap().starts_with("CVE-"));
        assert_eq!(stmt["products"][0]["identifiers"]["purl"], "pkg:generic/openssl@3.1.0");
        assert_eq!(stmt["status"], "under_investigation");
    }

    #[test]
    fn vex_output_path_derives_correctly() {
        let sbom = std::path::Path::new("/tmp/firmware.spdx.json");
        let vex = vex_output_path(sbom);
        assert_eq!(vex, std::path::PathBuf::from("/tmp/firmware.vex.json"));
    }

    #[test]
    fn vex_output_path_handles_cdx_suffix() {
        let sbom = std::path::Path::new("/tmp/firmware.cdx.json");
        let vex = vex_output_path(sbom);
        assert_eq!(vex, std::path::PathBuf::from("/tmp/firmware.vex.json"));
    }

    #[test]
    fn vex_output_path_handles_plain_json() {
        let sbom = std::path::Path::new("/tmp/sbom.json");
        let vex = vex_output_path(sbom);
        assert_eq!(vex, std::path::PathBuf::from("/tmp/sbom.vex.json"));
    }

    #[test]
    fn vex_status_display() {
        assert_eq!(VexStatus::Affected.to_string(), "affected");
        assert_eq!(VexStatus::NotAffected.to_string(), "not_affected");
        assert_eq!(
            VexStatus::UnderInvestigation.to_string(),
            "under_investigation"
        );
        assert_eq!(VexStatus::Fixed.to_string(), "fixed");
    }

    #[test]
    fn empty_components_produce_empty_statements() {
        let doc = generate_vex_document(&[], "sbom-empty", "fw");
        assert_eq!(doc["statements"].as_array().unwrap().len(), 0);
    }
}

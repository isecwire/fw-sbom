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


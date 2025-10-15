use anyhow::Result;
use serde_json::{json, Value};

use crate::models::{Component, DetectionMethod, SbomDocument, SbomFormat};

/// Generate an SBOM document in the requested format.
pub fn generate(doc: &SbomDocument, format: SbomFormat) -> Result<String> {
    let value = match format {
        SbomFormat::Spdx => generate_spdx(doc),
        SbomFormat::CycloneDx => generate_cyclonedx(doc),
    };
    let output = serde_json::to_string_pretty(&value)?;
    Ok(output)
}

/// Generate SPDX 2.3 JSON.
fn generate_spdx(doc: &SbomDocument) -> Value {
    let spdx_id = format!("SPDXRef-DOCUMENT");
    let doc_namespace = format!(
        "https://spdx.org/spdxdocs/{}-{}-{}",
        doc.name, doc.version, doc.document_id
    );

    let packages: Vec<Value> = doc
        .components
        .iter()
        .enumerate()
        .map(|(i, c)| spdx_package(c, i))
        .collect();

    let relationships: Vec<Value> = doc
        .components
        .iter()
        .enumerate()
        .map(|(i, _)| {
            json!({
                "spdxElementId": spdx_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": format!("SPDXRef-Package-{}", i)
            })
        })
        .collect();

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": spdx_id,
        "name": doc.name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": doc.created,
            "creators": [
                format!("Tool: {}", doc.tool),
                "Organization: isecwire GmbH"
            ],
            "licenseListVersion": "3.22"
        },
        "packages": packages,
        "relationships": relationships
    })
}

/// Build a single SPDX package entry.
fn spdx_package(c: &Component, idx: usize) -> Value {
    let spdx_id = format!("SPDXRef-Package-{}", idx);
    let version = c.version.as_deref().unwrap_or("NOASSERTION");
    let license = c.license.as_deref().unwrap_or("NOASSERTION");

    let mut pkg = json!({
        "SPDXID": spdx_id,
        "name": c.name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": license,
        "licenseDeclared": license,
        "copyrightText": "NOASSERTION",
        "checksums": [
            {
                "algorithm": "SHA256",
                "checksumValue": c.sha256
            }
        ],
        "annotations": [
            {
                "annotationType": "REVIEW",
                "annotator": format!("Tool: fw-sbom"),
                "annotationDate": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "comment": format!(
                    "Detected via {} in {} (confidence: {:.0}%)",
                    c.detection_method, c.file_path, c.confidence * 100.0
                )
            }
        ]
    });

    let obj = pkg.as_object_mut().unwrap();

    if let Some(ref purl) = c.purl {
        let mut refs = vec![json!({
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl
        })];

        // Add CPE reference if available.
        if let Some(ref cpe) = c.cpe {
            refs.push(json!({
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": cpe
            }));
        }

        obj.insert("externalRefs".to_string(), json!(refs));
    }

    pkg
}

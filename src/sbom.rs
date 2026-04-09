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
    let spdx_id = "SPDXRef-DOCUMENT".to_string();
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

/// Generate CycloneDX 1.5 JSON.
fn generate_cyclonedx(doc: &SbomDocument) -> Value {
    let components: Vec<Value> = doc.components.iter().map(cyclonedx_component).collect();

    json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", doc.document_id),
        "version": 1,
        "metadata": {
            "timestamp": doc.created,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "fw-sbom",
                        "publisher": "isecwire GmbH",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                ]
            },
            "component": {
                "type": "firmware",
                "name": doc.name,
                "version": doc.version
            }
        },
        "components": components
    })
}

/// Build a single CycloneDX component entry.
fn cyclonedx_component(c: &Component) -> Value {
    let comp_type = match c.detection_method {
        DetectionMethod::ElfDynamic | DetectionMethod::ElfDeep => "library",
        DetectionMethod::CryptoConstant => "library",
        DetectionMethod::KernelConfig | DetectionMethod::FilesystemMeta => "framework",
        _ => "library",
    };

    let mut comp = json!({
        "type": comp_type,
        "name": c.name,
        "hashes": [
            {
                "alg": "SHA-256",
                "content": c.sha256
            }
        ],
        "evidence": {
            "occurrences": [
                {
                    "location": c.file_path
                }
            ]
        },
        "properties": [
            {
                "name": "fw-sbom:confidence",
                "value": format!("{:.2}", c.confidence)
            },
            {
                "name": "fw-sbom:detection-method",
                "value": format!("{}", c.detection_method)
            }
        ]
    });

    let obj = comp.as_object_mut().unwrap();

    if let Some(ref version) = c.version {
        obj.insert("version".to_string(), json!(version));
    }

    if let Some(ref purl) = c.purl {
        obj.insert("purl".to_string(), json!(purl));
        obj.insert("bom-ref".to_string(), json!(purl));
    }

    if let Some(ref cpe) = c.cpe {
        obj.insert("cpe".to_string(), json!(cpe));
    }

    if let Some(ref license) = c.license {
        obj.insert(
            "licenses".to_string(),
            json!([
                {
                    "license": {
                        "id": license
                    }
                }
            ]),
        );
    }

    // Add vulnerability hints if present.
    if let Some(ref cves) = c.known_cves {
        let _vuln_refs: Vec<Value> = cves
            .iter()
            .map(|cve| {
                json!({
                    "id": cve,
                    "source": {
                        "name": "fw-sbom-hint",
                        "url": format!("https://nvd.nist.gov/vuln/detail/{}", cve)
                    }
                })
            })
            .collect();

        obj.insert(
            "properties".to_string(),
            json!([
                {
                    "name": "fw-sbom:confidence",
                    "value": format!("{:.2}", c.confidence)
                },
                {
                    "name": "fw-sbom:detection-method",
                    "value": format!("{}", c.detection_method)
                },
                {
                    "name": "fw-sbom:cve-hints",
                    "value": cves.join(", ")
                }
            ]),
        );
    }

    comp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test SbomDocument with given components.
    fn make_doc(components: Vec<Component>) -> SbomDocument {
        SbomDocument {
            name: "test-firmware".to_string(),
            version: "1.0.0".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            tool: "fw-sbom 0.2.0".to_string(),
            document_id: "test-uuid-1234".to_string(),
            components,
            distro_info: None,
            dependency_edges: None,
        }
    }

    /// Helper to create a sample component.
    fn sample_component(name: &str, version: Option<&str>) -> Component {
        Component {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            sha256: "abcdef1234567890".to_string(),
            license: Some("MIT".to_string()),
            purl: Some(match version {
                Some(v) => format!("pkg:generic/{}@{}", name, v),
                None => format!("pkg:generic/{}", name),
            }),
            file_path: format!("usr/lib/{}", name),
            detection_method: DetectionMethod::StringSignature,
            confidence: 0.5,
            cpe: None,
            known_cves: None,
        }
    }

    // ---- SPDX format tests ----

    #[test]
    fn spdx_output_is_valid_json() {
        let doc = make_doc(vec![sample_component("openssl", Some("3.1.0"))]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let parsed: Value = serde_json::from_str(&output).expect("should be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn spdx_has_required_top_level_fields() {
        let doc = make_doc(vec![sample_component("openssl", Some("3.1.0"))]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["dataLicense"], "CC0-1.0");
        assert_eq!(v["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(v["name"], "test-firmware");
        assert!(v["documentNamespace"]
            .as_str()
            .unwrap()
            .starts_with("https://spdx.org/spdxdocs/"));
        assert!(v["creationInfo"].is_object());
        assert!(v["packages"].is_array());
        assert!(v["relationships"].is_array());
    }

    #[test]
    fn spdx_creation_info_is_correct() {
        let doc = make_doc(vec![]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let info = &v["creationInfo"];
        assert_eq!(info["created"], "2026-01-01T00:00:00Z");
        let creators = info["creators"].as_array().unwrap();
        assert!(creators
            .iter()
            .any(|c| c.as_str().unwrap().contains("fw-sbom")));
        assert!(creators
            .iter()
            .any(|c| c.as_str().unwrap().contains("isecwire")));
    }

    #[test]
    fn spdx_document_namespace_contains_name_and_version() {
        let doc = make_doc(vec![]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let ns = v["documentNamespace"].as_str().unwrap();
        assert!(ns.contains("test-firmware"));
        assert!(ns.contains("1.0.0"));
        assert!(ns.contains("test-uuid-1234"));
    }

    #[test]
    fn spdx_package_fields() {
        let doc = make_doc(vec![sample_component("curl", Some("8.4.0"))]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let pkg = &v["packages"][0];
        assert_eq!(pkg["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(pkg["name"], "curl");
        assert_eq!(pkg["versionInfo"], "8.4.0");
        assert_eq!(pkg["downloadLocation"], "NOASSERTION");
        assert_eq!(pkg["filesAnalyzed"], false);
        assert_eq!(pkg["licenseConcluded"], "MIT");
        assert_eq!(pkg["licenseDeclared"], "MIT");

        // Check checksum.
        let checksums = pkg["checksums"].as_array().unwrap();
        assert_eq!(checksums[0]["algorithm"], "SHA256");
        assert_eq!(checksums[0]["checksumValue"], "abcdef1234567890");

        // Check external refs (PURL).
        let refs = pkg["externalRefs"].as_array().unwrap();
        assert_eq!(refs[0]["referenceType"], "purl");
        assert_eq!(refs[0]["referenceLocator"], "pkg:generic/curl@8.4.0");
    }

    #[test]
    fn spdx_package_with_cpe_has_security_ref() {
        let mut comp = sample_component("openssl", Some("3.1.0"));
        comp.cpe = Some("cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*".to_string());
        let doc = make_doc(vec![comp]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let refs = v["packages"][0]["externalRefs"].as_array().unwrap();
        assert!(refs.len() >= 2, "should have purl and cpe refs");
        assert!(refs.iter().any(|r| r["referenceType"] == "cpe23Type"));
    }

    #[test]
    fn spdx_relationship_describes_packages() {
        let doc = make_doc(vec![
            sample_component("curl", Some("8.4.0")),
            sample_component("zlib", Some("1.3.1")),
        ]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let rels = v["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 2);
        for rel in rels {
            assert_eq!(rel["spdxElementId"], "SPDXRef-DOCUMENT");
            assert_eq!(rel["relationshipType"], "DESCRIBES");
        }
        assert_eq!(rels[0]["relatedSpdxElement"], "SPDXRef-Package-0");
        assert_eq!(rels[1]["relatedSpdxElement"], "SPDXRef-Package-1");
    }

    #[test]
    fn spdx_package_without_version_uses_noassertion() {
        let doc = make_doc(vec![sample_component("zlib", None)]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(v["packages"][0]["versionInfo"], "NOASSERTION");
    }

    #[test]
    fn spdx_annotation_includes_confidence() {
        let doc = make_doc(vec![sample_component("curl", Some("8.4.0"))]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let comment = v["packages"][0]["annotations"][0]["comment"]
            .as_str()
            .unwrap();
        assert!(comment.contains("confidence"));
    }

    // ---- CycloneDX format tests ----

    #[test]
    fn cyclonedx_output_is_valid_json() {
        let doc = make_doc(vec![sample_component("openssl", Some("3.1.0"))]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let parsed: Value = serde_json::from_str(&output).expect("should be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn cyclonedx_has_required_top_level_fields() {
        let doc = make_doc(vec![sample_component("openssl", Some("3.1.0"))]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.6");
        assert!(v["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        assert_eq!(v["version"], 1);
        assert!(v["metadata"].is_object());
        assert!(v["components"].is_array());
    }

    #[test]
    fn cyclonedx_metadata_is_correct() {
        let doc = make_doc(vec![]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let meta = &v["metadata"];
        assert_eq!(meta["timestamp"], "2026-01-01T00:00:00Z");
        assert_eq!(meta["component"]["type"], "firmware");
        assert_eq!(meta["component"]["name"], "test-firmware");
        assert_eq!(meta["component"]["version"], "1.0.0");

        let tools = &meta["tools"]["components"];
        assert!(tools.is_array());
        let tool = &tools[0];
        assert_eq!(tool["name"], "fw-sbom");
        assert_eq!(tool["publisher"], "isecwire GmbH");
    }

    #[test]
    fn cyclonedx_component_fields() {
        let doc = make_doc(vec![sample_component("curl", Some("8.4.0"))]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let comp = &v["components"][0];
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "curl");
        assert_eq!(comp["version"], "8.4.0");
        assert_eq!(comp["purl"], "pkg:generic/curl@8.4.0");
        assert_eq!(comp["bom-ref"], "pkg:generic/curl@8.4.0");

        let hashes = comp["hashes"].as_array().unwrap();
        assert_eq!(hashes[0]["alg"], "SHA-256");
        assert_eq!(hashes[0]["content"], "abcdef1234567890");

        let licenses = comp["licenses"].as_array().unwrap();
        assert_eq!(licenses[0]["license"]["id"], "MIT");

        let occurrences = &comp["evidence"]["occurrences"];
        assert!(occurrences.is_array());
        assert_eq!(occurrences[0]["location"], "usr/lib/curl");
    }

    #[test]
    fn cyclonedx_component_has_properties() {
        let doc = make_doc(vec![sample_component("curl", Some("8.4.0"))]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let props = v["components"][0]["properties"].as_array().unwrap();
        assert!(props.iter().any(|p| p["name"] == "fw-sbom:confidence"));
        assert!(props
            .iter()
            .any(|p| p["name"] == "fw-sbom:detection-method"));
    }

    #[test]
    fn cyclonedx_component_without_version_omits_field() {
        let doc = make_doc(vec![sample_component("zlib", None)]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert!(v["components"][0].get("version").is_none());
    }

    #[test]
    fn cyclonedx_serial_number_contains_document_id() {
        let doc = make_doc(vec![]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(v["serialNumber"], "urn:uuid:test-uuid-1234");
    }

    // ---- Empty component list tests ----

    #[test]
    fn spdx_empty_components_produces_valid_output() {
        let doc = make_doc(vec![]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(v["packages"].as_array().unwrap().len(), 0);
        assert_eq!(v["relationships"].as_array().unwrap().len(), 0);
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
    }

    #[test]
    fn cyclonedx_empty_components_produces_valid_output() {
        let doc = make_doc(vec![]);
        let output = generate(&doc, SbomFormat::CycloneDx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(v["components"].as_array().unwrap().len(), 0);
        assert_eq!(v["bomFormat"], "CycloneDX");
    }

    // ---- Multiple components ----

    #[test]
    fn spdx_multiple_packages_indexed_correctly() {
        let doc = make_doc(vec![
            sample_component("aaa", Some("1.0")),
            sample_component("bbb", Some("2.0")),
            sample_component("ccc", Some("3.0")),
        ]);
        let output = generate(&doc, SbomFormat::Spdx).unwrap();
        let v: Value = serde_json::from_str(&output).unwrap();

        let packages = v["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0]["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(packages[1]["SPDXID"], "SPDXRef-Package-1");
        assert_eq!(packages[2]["SPDXID"], "SPDXRef-Package-2");
    }
}

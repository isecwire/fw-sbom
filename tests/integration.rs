//! Integration tests for fw-sbom.
//!
//! These tests create temporary firmware directory structures with fake files
//! and invoke the binary to verify end-to-end behavior.

use std::fs;
use std::io::Write;
use std::process::Command;

use tempfile::TempDir;

/// Path to the compiled binary (built by `cargo test`).
fn binary_path() -> std::path::PathBuf {
    // `cargo test` puts the binary in target/debug/
    let mut path = std::env::current_exe()
        .expect("failed to get current exe path");
    // Walk up from the test binary to the target/debug directory.
    path.pop(); // remove the test binary name
    path.pop(); // remove `deps/`
    path.push("fw-sbom");
    path
}

/// Create a fake firmware directory with some recognizable content.
fn create_fake_firmware() -> TempDir {
    let dir = TempDir::new().expect("failed to create temp dir");

    // A file containing a BusyBox signature.
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let mut f = fs::File::create(bin_dir.join("busybox")).unwrap();
    f.write_all(b"\x7fELF\x00\x00\x00\x00").unwrap(); // fake ELF header (will fail parse but that's ok)
    f.write_all(b"\x00\x00BusyBox v1.36.1 (2024-06-10 15:00:00 UTC)\x00").unwrap();
    f.write_all(b"\x00\x00OpenSSL 3.1.4 21 Nov 2023\x00").unwrap();

    // A file containing an opkg status metadata.
    let opkg_dir = dir.path().join("var/lib/opkg");
    fs::create_dir_all(&opkg_dir).unwrap();
    fs::write(
        opkg_dir.join("status"),
        "Package: dropbear\nVersion: 2022.83-1\nLicense: MIT\n\n\
         Package: dnsmasq\nVersion: 2.89-1\nLicense: GPL-2.0-only\n\n",
    )
    .unwrap();

    // A plain text file with no signatures.
    fs::write(dir.path().join("README"), "This is a test firmware image.\n").unwrap();

    dir
}

#[test]
fn binary_produces_spdx_output() {
    let firmware = create_fake_firmware();
    let output = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "spdx",
            "--name", "test-fw",
            "--fw-version", "2.0.0",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(
        output.status.success(),
        "fw-sbom exited with error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    // Verify SPDX structure.
    assert_eq!(v["spdxVersion"], "SPDX-2.3");
    assert_eq!(v["name"], "test-fw");

    // Should have discovered at least some components.
    let packages = v["packages"].as_array().unwrap();
    assert!(
        !packages.is_empty(),
        "should discover at least one component"
    );

    // Check that busybox was found.
    let names: Vec<&str> = packages.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"busybox"),
        "should detect busybox, found: {:?}",
        names
    );
}

#[test]
fn binary_produces_cyclonedx_output() {
    let firmware = create_fake_firmware();
    let output = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "cyclonedx",
            "--name", "test-fw",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(
        output.status.success(),
        "fw-sbom exited with error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("output should be valid JSON");

    assert_eq!(v["bomFormat"], "CycloneDX");
    assert_eq!(v["specVersion"], "1.6");
    assert_eq!(v["metadata"]["component"]["name"], "test-fw");

    let components = v["components"].as_array().unwrap();
    assert!(!components.is_empty(), "should discover components");

    // CycloneDX components should have properties with confidence.
    if let Some(first) = components.first() {
        let props = first["properties"].as_array();
        assert!(props.is_some(), "components should have properties");
    }
}

#[test]
fn binary_writes_output_to_file() {
    let firmware = create_fake_firmware();
    let output_dir = TempDir::new().unwrap();
    let output_file = output_dir.path().join("sbom.json");

    let result = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "spdx",
            "--output", output_file.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(
        result.status.success(),
        "fw-sbom exited with error: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    assert!(output_file.exists(), "output file should be created");
    let content = fs::read_to_string(&output_file).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).expect("file should contain valid JSON");
    assert_eq!(v["spdxVersion"], "SPDX-2.3");
}

#[test]
fn binary_fails_on_nonexistent_input() {
    let result = Command::new(binary_path())
        .args(["/nonexistent/path/does/not/exist"])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(
        !result.status.success(),
        "should fail for nonexistent input"
    );
}

#[test]
fn binary_detects_opkg_packages() {
    let firmware = create_fake_firmware();
    let output = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "spdx",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let packages = v["packages"].as_array().unwrap();
    let names: Vec<&str> = packages.iter().map(|p| p["name"].as_str().unwrap()).collect();

    assert!(
        names.contains(&"dropbear"),
        "should detect dropbear from opkg metadata, found: {:?}",
        names
    );
    assert!(
        names.contains(&"dnsmasq"),
        "should detect dnsmasq from opkg metadata, found: {:?}",
        names
    );
}

#[test]
fn empty_directory_produces_valid_sbom_with_no_components() {
    let dir = TempDir::new().unwrap();
    let output = Command::new(binary_path())
        .args([
            dir.path().to_str().unwrap(),
            "--format", "spdx",
            "--name", "empty-fw",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["spdxVersion"], "SPDX-2.3");
    assert_eq!(v["packages"].as_array().unwrap().len(), 0);
}

#[test]
fn binary_enrich_adds_cpe() {
    let firmware = create_fake_firmware();
    let output = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "spdx",
            "--enrich",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(
        output.status.success(),
        "fw-sbom --enrich exited with error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let packages = v["packages"].as_array().unwrap();
    // At least one package should have a CPE external ref.
    let has_cpe = packages.iter().any(|pkg| {
        pkg.get("externalRefs")
            .and_then(|refs| refs.as_array())
            .map(|refs| refs.iter().any(|r| r["referenceType"] == "cpe23Type"))
            .unwrap_or(false)
    });
    assert!(has_cpe, "enriched SBOM should have at least one CPE reference");
}

#[test]
fn binary_diff_mode() {
    let firmware = create_fake_firmware();

    // Generate two SBOMs.
    let output_dir = TempDir::new().unwrap();
    let sbom1_path = output_dir.path().join("sbom1.json");
    let sbom2_path = output_dir.path().join("sbom2.json");

    let result1 = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "spdx",
            "--output", sbom1_path.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");
    assert!(result1.status.success());

    let result2 = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--format", "spdx",
            "--output", sbom2_path.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");
    assert!(result2.status.success());

    // Run diff.
    let diff_result = Command::new(binary_path())
        .args([
            sbom1_path.to_str().unwrap(),
            "--diff", sbom2_path.to_str().unwrap(),
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom --diff");

    assert!(
        diff_result.status.success(),
        "fw-sbom --diff exited with error: {}",
        String::from_utf8_lossy(&diff_result.stderr)
    );

    let stdout = String::from_utf8(diff_result.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .expect("diff output should be valid JSON");
    // Same SBOMs should have zero changes.
    assert_eq!(v["added"].as_array().unwrap().len(), 0);
    assert_eq!(v["removed"].as_array().unwrap().len(), 0);
    assert_eq!(v["version_changed"].as_array().unwrap().len(), 0);
}

#[test]
fn binary_exclude_pattern() {
    let dir = TempDir::new().unwrap();

    // Create files in two directories.
    let keep_dir = dir.path().join("keep");
    fs::create_dir_all(&keep_dir).unwrap();
    fs::File::create(keep_dir.join("bb.bin"))
        .unwrap()
        .write_all(b"\x00BusyBox v1.36.1\x00")
        .unwrap();

    let skip_dir = dir.path().join("skipthis");
    fs::create_dir_all(&skip_dir).unwrap();
    fs::File::create(skip_dir.join("ssl.bin"))
        .unwrap()
        .write_all(b"\x00OpenSSL 3.1.4\x00")
        .unwrap();

    let output = Command::new(binary_path())
        .args([
            dir.path().to_str().unwrap(),
            "--format", "spdx",
            "--exclude", "skipthis",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let packages = v["packages"].as_array().unwrap();
    let names: Vec<&str> = packages.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"busybox"), "should find busybox");
    assert!(!names.contains(&"openssl"), "should exclude openssl in skipthis dir");
}

#[test]
fn binary_min_confidence_filter() {
    let dir = TempDir::new().unwrap();
    fs::File::create(dir.path().join("bb.bin"))
        .unwrap()
        .write_all(b"\x00BusyBox v1.36.1\x00")
        .unwrap();

    // With very high confidence threshold, string-signature detections should be filtered.
    let output = Command::new(binary_path())
        .args([
            dir.path().to_str().unwrap(),
            "--format", "spdx",
            "--min-confidence", "0.99",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let packages = v["packages"].as_array().unwrap();
    assert!(
        packages.is_empty(),
        "high confidence threshold should filter string-signature results"
    );
}

#[test]
fn binary_graph_mode() {
    let firmware = create_fake_firmware();

    let output = Command::new(binary_path())
        .args([
            firmware.path().to_str().unwrap(),
            "--graph",
            "--quiet",
        ])
        .output()
        .expect("failed to execute fw-sbom --graph");

    assert!(
        output.status.success(),
        "fw-sbom --graph exited with error: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Graph output should be DOT format (may be empty if no real ELFs).
    assert!(
        stdout.contains("digraph") || stdout.is_empty() || stdout.contains("{}"),
        "graph output should be DOT format or empty"
    );
}

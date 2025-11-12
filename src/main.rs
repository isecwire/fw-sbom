mod analyzer;
mod diff;
mod display;
mod elf_deep;
mod enrichment;
mod graph;
mod license;
mod merge;
mod models;
mod sbom;
mod vex;

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use uuid::Uuid;

use crate::analyzer::FirmwareAnalyzer;
use crate::models::{SbomDocument, SbomFormat};

/// fw-sbom -- Firmware Software Bill of Materials generator.
///
/// Scans extracted firmware directories for software components and produces
/// SBOM documents in SPDX 2.3 or CycloneDX 1.6 JSON format.
/// Designed to support EU Cyber Resilience Act (CRA) compliance.
#[derive(Parser, Debug)]
#[command(name = "fw-sbom", version, about)]
struct Cli {
    /// Path to extracted firmware directory or file to analyze.
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Output SBOM format.
    #[arg(short, long, default_value = "spdx", value_parser = parse_format)]
    format: SbomFormat,

    /// Output file path. Prints to stdout if omitted.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Firmware / product name for the SBOM document.
    #[arg(short, long, default_value = "firmware")]
    name: String,

    /// Firmware / product version for the SBOM document.
    #[arg(long = "fw-version", default_value = "0.0.0")]
    fw_version: String,

    /// Compare with another SBOM file (diff mode).
    #[arg(long = "diff")]
    diff_file: Option<PathBuf>,

    /// Enrich components with CPE identifiers and vulnerability hints.
    #[arg(long)]
    enrich: bool,

    /// Output dependency graph in DOT format.
    #[arg(long)]
    graph: bool,

    /// Exclude paths matching these patterns (can be repeated).
    #[arg(long = "exclude", value_name = "PATTERN")]
    exclude: Vec<String>,

    /// Minimum confidence score (0.0 to 1.0) to include a component.
    #[arg(long = "min-confidence", default_value = "0.0")]
    min_confidence: f64,

    /// Merge multiple SBOM files into one (provide paths as arguments).
    #[arg(long = "merge", num_args = 1..)]
    merge_files: Option<Vec<PathBuf>>,

    /// Generate a VEX document alongside the SBOM.
    #[arg(long)]
    vex: bool,

    /// Validate generated SBOM against its JSON schema.
    #[arg(long)]
    validate: bool,

    /// Suppress colored output and progress display.
    #[arg(long)]
    quiet: bool,
}

fn parse_format(s: &str) -> Result<SbomFormat, String> {
    s.parse()
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // -- Merge mode: combine multiple SBOMs and exit. --
    if let Some(ref merge_paths) = cli.merge_files {
        let path_refs: Vec<&std::path::Path> =
            merge_paths.iter().map(|p| p.as_path()).collect();
        let merged_output = merge::merge_sbom_files(
            &path_refs,
            cli.format,
            &cli.name,
            &cli.fw_version,
        )
        .context("SBOM merge failed")?;

        match cli.output {
            Some(ref path) => {
                fs::write(path, &merged_output)
                    .with_context(|| format!("writing merged SBOM to {}", path.display()))?;
                if !cli.quiet {
                    eprintln!(
                        "  {} Merged SBOM written to {}",
                        console::style("OK").green().bold(),
                        path.display()
                    );
                }
            }
            None => {
                println!("{}", merged_output);
            }
        }
        return Ok(());
    }

    // -- Diff mode: compare two SBOMs and exit. --
    if let Some(ref diff_path) = cli.diff_file {
        if !cli.input.exists() {
            bail!("old SBOM file does not exist: {}", cli.input.display());
        }
        if !diff_path.exists() {
            bail!("new SBOM file does not exist: {}", diff_path.display());
        }

        let sbom_diff = diff::diff_sbom_files(&cli.input, diff_path)
            .context("SBOM diff failed")?;

        if !cli.quiet {
            display::print_diff(&sbom_diff);
        }

        // Also output JSON diff to stdout.
        let json = serde_json::to_string_pretty(&sbom_diff)?;
        println!("{}", json);
        return Ok(());
    }

    // Validate input path.
    if !cli.input.exists() {
        bail!("input path does not exist: {}", cli.input.display());
    }

    // Print header.
    if !cli.quiet {
        display::print_header(&cli.name, &cli.fw_version, &cli.input.to_string_lossy());
    }

    // Create spinner.
    let spinner = if !cli.quiet {
        Some(display::create_spinner("Scanning firmware..."))
    } else {
        None
    };

    // Run analysis.
    let analyzer = FirmwareAnalyzer::new(&cli.input)
        .with_excludes(cli.exclude)
        .with_min_confidence(cli.min_confidence);

    let result = analyzer
        .analyze_full()
        .context("firmware analysis failed")?;

    let mut components = result.components;

    // Finish spinner.
    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    // Enrich with CPE/CVE data if requested.
    if cli.enrich {
        enrichment::enrich_components(&mut components);
    }

    // Print summary table (or machine-readable summary for --quiet).
    if !cli.quiet {
        let stats = display::compute_stats(
            &components,
            result.elf_metadata.len(),
            result.files_scanned,
        );
        display::print_summary_table(&components, &stats);

        // Print ELF security info if available.
        if !result.elf_metadata.is_empty() {
            display::print_elf_security_table(&result.elf_metadata);
        }

        // Print kernel config if found.
        if let Some(ref kconfig) = result.kernel_config {
            display::print_kernel_config(kconfig);
        }
    } else {
        // Machine-readable summary to stderr when --quiet.
        let cve_count = components
            .iter()
            .filter_map(|c| c.known_cves.as_ref())
            .map(|cves| cves.len())
            .sum::<usize>();
        eprintln!(
            "{{\"components\":{},\"files_scanned\":{},\"cve_hints\":{}}}",
            components.len(),
            result.files_scanned,
            cve_count,
        );
    }

    // Output dependency graph if requested.
    if cli.graph {
        let dot = graph::generate_dot_graph(
            &result.dependency_edges,
            &cli.name,
        );
        // Write graph to stderr summary, DOT to stdout.
        if !cli.quiet {
            let summary = graph::summarize_graph(&result.dependency_edges);
            eprint!("{}", summary);
        }
        println!("{}", dot);
        return Ok(());
    }

    // Build the SBOM document.
    let doc_id = Uuid::new_v4().to_string();
    let doc = SbomDocument {
        name: cli.name.clone(),
        version: cli.fw_version.clone(),
        created: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        tool: format!("fw-sbom {}", env!("CARGO_PKG_VERSION")),
        document_id: doc_id.clone(),
        components: components.clone(),
        distro_info: result.distro_info,
        dependency_edges: if result.dependency_edges.is_empty() {
            None
        } else {
            Some(result.dependency_edges)
        },
    };

    // Render to the chosen format.
    let output = sbom::generate(&doc, cli.format)
        .context("SBOM generation failed")?;

    // Validate SBOM if requested.
    if cli.validate {
        validate_sbom_json(&output, cli.format)?;
    }

    // Write output.
    match cli.output {
        Some(ref path) => {
            fs::write(path, &output)
                .with_context(|| format!("writing output to {}", path.display()))?;
            if !cli.quiet {
                eprintln!(
                    "  {} SBOM written to {}",
                    console::style("OK").green().bold(),
                    path.display()
                );
            }

            // Generate VEX document alongside the SBOM if requested.
            if cli.vex {
                let vex_path = vex::vex_output_path(path);
                let vex_doc =
                    vex::generate_vex_document(&components, &doc_id, &cli.name);
                let vex_output = serde_json::to_string_pretty(&vex_doc)?;
                fs::write(&vex_path, &vex_output)
                    .with_context(|| format!("writing VEX to {}", vex_path.display()))?;
                if !cli.quiet {
                    eprintln!(
                        "  {} VEX written to {}",
                        console::style("OK").green().bold(),
                        vex_path.display()
                    );
                }
            }
        }
        None => {
            println!("{}", output);

            // If VEX is requested without an output file, print VEX to stderr.
            if cli.vex {
                let vex_doc =
                    vex::generate_vex_document(&components, &doc_id, &cli.name);
                let vex_output = serde_json::to_string_pretty(&vex_doc)?;
                eprintln!("--- VEX Document ---");
                eprintln!("{}", vex_output);
            }
        }
    }

    Ok(())
}

/// Basic JSON schema validation for generated SBOMs.
/// Checks structural correctness of required fields.
fn validate_sbom_json(json_str: &str, format: SbomFormat) -> Result<()> {
    let doc: serde_json::Value =
        serde_json::from_str(json_str).context("SBOM is not valid JSON")?;

    match format {
        SbomFormat::Spdx => {
            let required = ["spdxVersion", "dataLicense", "SPDXID", "name", "creationInfo", "packages"];
            for field in &required {
                if doc.get(field).is_none() {
                    bail!("SPDX validation failed: missing required field '{}'", field);
                }
            }
            if doc["spdxVersion"].as_str() != Some("SPDX-2.3") {
                bail!("SPDX validation warning: expected spdxVersion SPDX-2.3");
            }
            eprintln!("  {} SPDX schema validation passed", console::style("OK").green().bold());
        }
        SbomFormat::CycloneDx => {
            let required = ["bomFormat", "specVersion", "serialNumber", "metadata", "components"];
            for field in &required {
                if doc.get(field).is_none() {
                    bail!("CycloneDX validation failed: missing required field '{}'", field);
                }
            }
            let spec = doc["specVersion"].as_str().unwrap_or("");
            if spec != "1.5" && spec != "1.6" {
                bail!("CycloneDX validation warning: expected specVersion 1.5 or 1.6");
            }
            eprintln!("  {} CycloneDX schema validation passed", console::style("OK").green().bold());
        }
    }

    Ok(())
}

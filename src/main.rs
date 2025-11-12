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


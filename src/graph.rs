//! Dependency graph builder.
//!
//! Generates a DOT-format graph showing which ELF binaries depend on
//! which shared libraries, with package attribution when known.

use std::collections::{HashMap, HashSet};

use crate::models::DependencyEdge;

/// Generate a DOT-format dependency graph from dependency edges.
pub fn generate_dot_graph(edges: &[DependencyEdge], title: &str) -> String {
    let mut dot = String::new();

    dot.push_str(&format!("digraph \"{}\" {{\n", escape_dot(title)));
    dot.push_str("    rankdir=LR;\n");
    dot.push_str("    node [shape=box, style=filled, fontname=\"Helvetica\"];\n");
    dot.push_str("    edge [color=\"#666666\"];\n");
    dot.push('\n');

    // Collect all unique binaries and libraries.
    let mut binaries: HashSet<&str> = HashSet::new();
    let mut libraries: HashSet<&str> = HashSet::new();

    for edge in edges {
        binaries.insert(&edge.binary_path);
        libraries.insert(&edge.library);
    }

    // Style binary nodes.
    dot.push_str("    // Binaries\n");
    dot.push_str("    subgraph cluster_binaries {\n");
    dot.push_str("        label=\"ELF Binaries\";\n");
    dot.push_str("        style=dashed;\n");
    dot.push_str("        color=\"#cccccc\";\n");
    for bin in &binaries {
        dot.push_str(&format!(
            "        \"{}\" [fillcolor=\"#e3f2fd\", label=\"{}\"];\n",
            escape_dot(bin),
            short_label(bin),
        ));
    }
    dot.push_str("    }\n\n");

    // Style library nodes.
    dot.push_str("    // Libraries\n");
    dot.push_str("    subgraph cluster_libraries {\n");
    dot.push_str("        label=\"Shared Libraries\";\n");
    dot.push_str("        style=dashed;\n");
    dot.push_str("        color=\"#cccccc\";\n");
    for lib in &libraries {
        dot.push_str(&format!(
            "        \"{}\" [fillcolor=\"#fff3e0\", label=\"{}\"];\n",
            escape_dot(lib),
            lib,
        ));
    }
    dot.push_str("    }\n\n");

    // Edges.
    dot.push_str("    // Dependencies\n");
    for edge in edges {
        dot.push_str(&format!(
            "    \"{}\" -> \"{}\";\n",
            escape_dot(&edge.binary_path),
            escape_dot(&edge.library),
        ));
    }

    dot.push_str("}\n");
    dot
}

/// Generate a summary of the dependency graph as text.
pub fn summarize_graph(edges: &[DependencyEdge]) -> String {
    let mut out = String::new();

    // Group by binary.
    let mut by_binary: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in edges {
        by_binary
            .entry(&edge.binary_path)
            .or_default()
            .push(&edge.library);
    }

    // Group by library (reverse: who uses this lib).
    let mut by_library: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in edges {
        by_library
            .entry(&edge.library)
            .or_default()
            .push(&edge.binary_path);
    }

    out.push_str(&format!(
        "Dependency graph: {} binaries, {} unique libraries, {} edges\n",
        by_binary.len(),
        by_library.len(),
        edges.len(),
    ));
    out.push_str(&"-".repeat(60));
    out.push('\n');

    // Most-linked libraries.
    let mut lib_counts: Vec<(&&str, usize)> = by_library
        .iter()
        .map(|(lib, users)| (lib, users.len()))
        .collect();
    lib_counts.sort_by(|a, b| b.1.cmp(&a.1));

    if !lib_counts.is_empty() {
        out.push_str("\nMost-linked libraries:\n");
        for (lib, count) in lib_counts.iter().take(10) {
            out.push_str(&format!("  {:40} ({} binaries)\n", lib, count));
        }
    }

    // Binaries with most dependencies.
    let mut bin_counts: Vec<(&&str, usize)> = by_binary
        .iter()
        .map(|(bin, libs)| (bin, libs.len()))
        .collect();
    bin_counts.sort_by(|a, b| b.1.cmp(&a.1));

    if !bin_counts.is_empty() {
        out.push_str("\nBinaries with most dependencies:\n");
        for (bin, count) in bin_counts.iter().take(10) {
            out.push_str(&format!("  {:40} ({} libraries)\n", short_label(bin), count));
        }
    }

    out
}

/// Escape a string for safe use in DOT format.
fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Produce a short label from a path (just the filename).
fn short_label(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}


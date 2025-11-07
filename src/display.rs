//! Colored terminal output, tables, and progress display.
//!
//! Provides summary tables, progress spinners, and colored output
//! for a professional CLI experience.

use std::collections::HashMap;
use std::io::Write;

use comfy_table::{Cell, CellAlignment, Color, ContentArrangement, Table};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};

use crate::models::{AnalysisStats, Component, ElfMetadata, KernelSecurityConfig, SbomDiff};

/// Create and return a progress spinner for the analysis phase.
pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&[">>>", ">> >", "> >>", " >>>", "> >>", ">> >", ">>>", ""]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(120));
    pb
}

/// Print the analysis header.
pub fn print_header(name: &str, version: &str, input: &str) {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "{}",
        style("  fw-sbom  Firmware SBOM Generator").cyan().bold()
    );
    let _ = writeln!(
        err,
        "  {}  v{}",
        style("Version").dim(),
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(err, "  {}  {}", style("Product").dim(), name);
    let _ = writeln!(err, "  {}  {}", style("FW Ver ").dim(), version);
    let _ = writeln!(err, "  {}  {}", style("Input  ").dim(), input);
    let _ = writeln!(err, "{}", style("  ---").dim());
}

/// Print a summary table of discovered components.
pub fn print_summary_table(components: &[Component], stats: &AnalysisStats) {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();

    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {} {}",
        style("Analysis complete.").green().bold(),
        style(format!(
            "{} files scanned, {} ELF binaries, {} components found",
            stats.files_scanned, stats.elf_binaries, stats.components_found
        ))
        .dim()
    );

    // Components table.
    if !components.is_empty() {
        let _ = writeln!(err);
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec![
            Cell::new("Component")
                .set_alignment(CellAlignment::Left)
                .fg(Color::Cyan),
            Cell::new("Version")
                .set_alignment(CellAlignment::Left)
                .fg(Color::Cyan),
            Cell::new("License")
                .set_alignment(CellAlignment::Left)
                .fg(Color::Cyan),
            Cell::new("Detection")
                .set_alignment(CellAlignment::Left)
                .fg(Color::Cyan),
            Cell::new("Confidence")
                .set_alignment(CellAlignment::Right)
                .fg(Color::Cyan),
        ]);

        for c in components {
            let conf_pct = format!("{:.0}%", c.confidence * 100.0);
            let conf_color = if c.confidence >= 0.8 {
                Color::Green
            } else if c.confidence >= 0.6 {
                Color::Yellow
            } else {
                Color::Red
            };

            table.add_row(vec![
                Cell::new(&c.name),
                Cell::new(c.version.as_deref().unwrap_or("-")),
                Cell::new(c.license.as_deref().unwrap_or("-")),
                Cell::new(format!("{}", c.detection_method)),
                Cell::new(&conf_pct)
                    .set_alignment(CellAlignment::Right)
                    .fg(conf_color),
            ]);
        }

        let _ = writeln!(err, "{}", table);
    }

    // Detection method breakdown.
    if !stats.by_method.is_empty() {
        let _ = writeln!(err);
        let _ = writeln!(
            err,
            "  {}",
            style("Detection method breakdown:").bold()
        );
        let mut methods: Vec<_> = stats.by_method.iter().collect();
        methods.sort_by(|a, b| b.1.cmp(a.1));
        for (method, count) in methods {
            let _ = writeln!(err, "    {:25} {}", method, count);
        }
    }

    // License breakdown.
    if !stats.by_license.is_empty() {
        let _ = writeln!(err);
        let _ = writeln!(
            err,
            "  {}",
            style("License breakdown:").bold()
        );
        let mut licenses: Vec<_> = stats.by_license.iter().collect();
        licenses.sort_by(|a, b| b.1.cmp(a.1));
        for (license, count) in licenses {
            let _ = writeln!(err, "    {:25} {}", license, count);
        }
    }

    let _ = writeln!(err);
}

/// Print ELF security hardening summary.
pub fn print_elf_security_table(elf_metadata: &[ElfMetadata]) {
    if elf_metadata.is_empty() {
        return;
    }

    let stderr = std::io::stderr();
    let mut err = stderr.lock();

    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {}",
        style("ELF binary security hardening:").bold()
    );

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Binary").fg(Color::Cyan),
        Cell::new("PIE").fg(Color::Cyan),
        Cell::new("RELRO").fg(Color::Cyan),
        Cell::new("Stack Canary").fg(Color::Cyan),
        Cell::new("NX").fg(Color::Cyan),
        Cell::new("Compiler").fg(Color::Cyan),
    ]);

    for meta in elf_metadata.iter().take(20) {
        let short_path = meta
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&meta.path);

        table.add_row(vec![
            Cell::new(short_path),
            bool_cell(meta.is_pie),
            bool_cell(meta.has_relro),
            bool_cell(meta.has_stack_canary),
            bool_cell(meta.has_nx),
            Cell::new(
                meta.compiler
                    .as_deref()
                    .map(|c| {
                        if c.len() > 30 {
                            format!("{}...", &c[..27])
                        } else {
                            c.to_string()
                        }
                    })
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]);
    }

    let _ = writeln!(err, "{}", table);

    if elf_metadata.len() > 20 {
        let _ = writeln!(
            err,
            "  {} more ELF binaries not shown.",
            elf_metadata.len() - 20
        );
    }
}

/// Print kernel security config summary.
pub fn print_kernel_config(config: &KernelSecurityConfig) {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();

    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {}",
        style("Kernel security configuration:").bold()
    );

    let items = [
        ("Stack Protector", config.stack_protector),
        ("ASLR", config.aslr),
        ("SELinux", config.selinux),
        ("AppArmor", config.apparmor),
        ("Seccomp", config.seccomp),
        ("Modules Disabled", config.modules_disabled),
        ("Hardened Usercopy", config.hardened_usercopy),
        ("FORTIFY_SOURCE", config.fortify_source),
    ];

    for (name, value) in &items {
        let display = match value {
            Some(true) => style("enabled").green().to_string(),
            Some(false) => style("disabled").red().to_string(),
            None => style("unknown").dim().to_string(),
        };
        let _ = writeln!(err, "    {:25} {}", name, display);
    }
    let _ = writeln!(err);
}

/// Print SBOM diff results with colors.
pub fn print_diff(diff: &SbomDiff) {
    let stderr = std::io::stderr();
    let mut err = stderr.lock();

    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {}",
        style("SBOM Comparison Results").bold().cyan()
    );
    let _ = writeln!(
        err,
        "  {} added, {} removed, {} changed, {} unchanged",
        style(diff.added.len()).green(),
        style(diff.removed.len()).red(),
        style(diff.version_changed.len()).yellow(),
        diff.unchanged_count,
    );
    let _ = writeln!(err, "{}", style("  ---").dim());

    if !diff.added.is_empty() {
        let _ = writeln!(err);
        let _ = writeln!(err, "  {}", style("Added:").green().bold());
        for entry in &diff.added {
            let _ = writeln!(
                err,
                "    {} {} {}",
                style("+").green(),
                entry.name,
                style(entry.version.as_deref().unwrap_or("")).dim(),
            );
        }
    }

    if !diff.removed.is_empty() {
        let _ = writeln!(err);
        let _ = writeln!(err, "  {}", style("Removed:").red().bold());
        for entry in &diff.removed {
            let _ = writeln!(
                err,
                "    {} {} {}",
                style("-").red(),
                entry.name,
                style(entry.version.as_deref().unwrap_or("")).dim(),
            );
        }
    }

    if !diff.version_changed.is_empty() {
        let _ = writeln!(err);
        let _ = writeln!(
            err,
            "  {}",
            style("Version changes:").yellow().bold()
        );
        for change in &diff.version_changed {
            let _ = writeln!(
                err,
                "    {} {} : {} -> {}",
                style("~").yellow(),
                change.name,
                style(change.old_version.as_deref().unwrap_or("(none)")).red(),
                style(change.new_version.as_deref().unwrap_or("(none)")).green(),
            );
        }
    }

    let _ = writeln!(err);
}

/// Build analysis statistics from components.
pub fn compute_stats(components: &[Component], elf_count: usize, files_scanned: usize) -> AnalysisStats {
    let mut by_method: HashMap<String, usize> = HashMap::new();
    let mut by_license: HashMap<String, usize> = HashMap::new();

    for c in components {
        *by_method
            .entry(format!("{}", c.detection_method))
            .or_insert(0) += 1;
        if let Some(ref lic) = c.license {
            *by_license.entry(lic.clone()).or_insert(0) += 1;
        }
    }

    AnalysisStats {
        files_scanned,
        elf_binaries: elf_count,
        components_found: components.len(),
        by_method,
        by_license,
    }
}

fn bool_cell(val: bool) -> Cell {
    if val {
        Cell::new("Yes").fg(Color::Green)
    } else {
        Cell::new("No").fg(Color::Red)
    }
}


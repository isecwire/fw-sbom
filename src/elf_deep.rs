//! Deep ELF binary analysis.
//!
//! Parses .dynamic section for SONAME, NEEDED entries, RPATH/RUNPATH, build-id;
//! extracts compiler info from .comment section; checks security hardening flags.

use std::fs;
use std::path::Path;

use anyhow::Result;
use goblin::elf::dynamic::{DT_RPATH, DT_RUNPATH, DT_SONAME};
use goblin::elf::program_header::PT_GNU_RELRO;
use goblin::elf::Elf;
use memmap2::Mmap;

use crate::models::{Component, DependencyEdge, DetectionMethod, ElfMetadata, method_confidence};

/// Perform deep ELF analysis on a file, returning metadata and any components discovered.
pub fn analyze_elf_deep(
    path: &Path,
    rel_path: &str,
    hash: &str,
) -> Result<Option<(ElfMetadata, Vec<Component>, Vec<DependencyEdge>)>> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    let mmap = unsafe {
        match Mmap::map(&file) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        }
    };

    // Quick ELF magic check.
    if mmap.len() < 4 || &mmap[..4] != b"\x7fELF" {
        return Ok(None);
    }

    let elf = match Elf::parse(&mmap) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };

    let mut components = Vec::new();
    let mut dep_edges = Vec::new();

    // Extract SONAME.
    let soname = extract_soname(&elf);

    // Extract NEEDED libraries.
    let needed: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

    // Build dependency edges.
    for lib in &needed {
        dep_edges.push(DependencyEdge {
            binary_path: rel_path.to_string(),
            library: lib.clone(),
            soname: soname.clone(),
        });
    }

    // Extract RPATH and RUNPATH.
    let rpath = extract_dynamic_str(&elf, &mmap, DT_RPATH);
    let runpath = extract_dynamic_str(&elf, &mmap, DT_RUNPATH);

    // Extract build-id from .note.gnu.build-id section.
    let build_id = extract_build_id(&elf, &mmap);

    // Extract compiler from .comment section.
    let compiler = extract_comment(&elf, &mmap);

    // Detect compiler as a component.
    if let Some(ref comp_str) = compiler {
        if let Some(comp) = parse_compiler_component(comp_str, rel_path, hash) {
            components.push(comp);
        }
    }

    // Security hardening checks.
    let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;
    let has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);

    // Check for stack canary by looking for __stack_chk_fail in symbols.
    let has_stack_canary = elf.dynsyms.iter().any(|sym| {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            name == "__stack_chk_fail" || name == "__stack_chk_guard"
        } else {
            false
        }
    });

    // NX: check that no segment is both writable and executable.
    let has_nx = !elf.program_headers.iter().any(|ph| {
        let pf_w = 0x2;
        let pf_x = 0x1;
        (ph.p_flags & pf_w != 0) && (ph.p_flags & pf_x != 0)
    });

    let metadata = ElfMetadata {
        path: rel_path.to_string(),
        soname,
        needed,
        rpath,
        runpath,
        build_id,
        compiler,
        is_pie,
        has_relro,
        has_stack_canary,
        has_nx,
    };

    Ok(Some((metadata, components, dep_edges)))
}

/// Extract SONAME from dynamic section.
fn extract_soname(elf: &Elf) -> Option<String> {
    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag as u64 == DT_SONAME as u64 {
                if let Some(name) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Extract a string value from a specific dynamic tag.
fn extract_dynamic_str(elf: &Elf, _mmap: &[u8], tag: u64) -> Option<String> {
    if let Some(ref dynamic) = elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag as u64 == tag {
                if let Some(name) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Extract build-id from .note.gnu.build-id section.
fn extract_build_id(elf: &Elf, mmap: &[u8]) -> Option<String> {
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".note.gnu.build-id" {
            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            if offset + size <= mmap.len() && size > 16 {
                // Note format: namesz(4) + descsz(4) + type(4) + name + desc
                let data = &mmap[offset..offset + size];
                if data.len() >= 16 {
                    let namesz = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                    let descsz = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
                    let desc_offset = 12 + ((namesz + 3) & !3); // align to 4
                    if desc_offset + descsz <= data.len() {
                        let desc = &data[desc_offset..desc_offset + descsz];
                        return Some(desc.iter().map(|b| format!("{:02x}", b)).collect());
                    }
                }
            }
        }
    }
    None
}

/// Extract compiler information from .comment section.
fn extract_comment(elf: &Elf, mmap: &[u8]) -> Option<String> {
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".comment" {
            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            if offset + size <= mmap.len() {
                let data = &mmap[offset..offset + size];
                // .comment contains null-terminated strings.
                for chunk in data.split(|&b| b == 0) {
                    if let Ok(s) = std::str::from_utf8(chunk) {
                        let s = s.trim();
                        if !s.is_empty() {
                            return Some(s.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Try to parse a compiler string into a component.
fn parse_compiler_component(comment: &str, rel_path: &str, hash: &str) -> Option<Component> {
    let lower = comment.to_lowercase();

    let (name, version) = if lower.contains("gcc") {
        let ver = extract_version_from_comment(comment);
        ("gcc", ver)
    } else if lower.contains("clang") || lower.contains("llvm") {
        let ver = extract_version_from_comment(comment);
        ("clang", ver)
    } else {
        return None;
    };

    let confidence = method_confidence(&DetectionMethod::ElfDeep);
    let purl = match &version {
        Some(v) => format!("pkg:generic/{}@{}", name, v),
        None => format!("pkg:generic/{}", name),
    };

    Some(Component {
        name: name.to_string(),
        version,
        sha256: hash.to_string(),
        license: Some(if name == "gcc" {
            "GPL-3.0-or-later".to_string()
        } else {
            "Apache-2.0".to_string()
        }),
        purl: Some(purl),
        file_path: rel_path.to_string(),
        detection_method: DetectionMethod::ElfDeep,
        confidence,
        cpe: None,
        known_cves: None,
    })
}

/// Extract a version number from a compiler comment string.
fn extract_version_from_comment(comment: &str) -> Option<String> {
    // Look for patterns like "GCC: (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0" or "clang version 15.0.7"
    let mut best: Option<String> = None;
    for word in comment.split_whitespace() {
        // A version-like token: starts with a digit, contains a dot.
        if word.chars().next().map_or(false, |c| c.is_ascii_digit()) && word.contains('.') {
            let trimmed = word
                .trim_end_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
            if trimmed.len() >= 3 {
                best = Some(trimmed.to_string());
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gcc_comment() {
        let comp = parse_compiler_component(
            "GCC: (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0",
            "bin/test",
            "abc",
        );
        let comp = comp.unwrap();
        assert_eq!(comp.name, "gcc");
        assert_eq!(comp.version.as_deref(), Some("12.3.0"));
        assert_eq!(comp.detection_method, DetectionMethod::ElfDeep);
    }

    #[test]
    fn parse_clang_comment() {
        let comp = parse_compiler_component(
            "clang version 15.0.7 (Fedora 15.0.7-2.fc37)",
            "bin/test",
            "abc",
        );
        let comp = comp.unwrap();
        assert_eq!(comp.name, "clang");
        // Should pick up 15.0.7
        assert!(comp.version.as_deref().unwrap().starts_with("15.0.7"));
    }

    #[test]
    fn unknown_compiler_returns_none() {
        let comp = parse_compiler_component("some random string", "bin/test", "abc");
        assert!(comp.is_none());
    }

    #[test]
    fn extract_version_from_gcc_string() {
        let ver = extract_version_from_comment("GCC: (GNU) 13.2.0");
        assert_eq!(ver, Some("13.2.0".to_string()));
    }
}

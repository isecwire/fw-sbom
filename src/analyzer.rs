use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use goblin::elf::Elf;
use memmap2::Mmap;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::elf_deep;
use crate::license;
use crate::models::{
    Component, DependencyEdge, DetectionMethod, DistroInfo, ElfMetadata,
    KernelSecurityConfig, method_confidence,
};

/// Known embedded package signatures: (search bytes, package name, license).
/// Each entry is a set of byte-string needles that, when found inside a binary,
/// indicate the presence of a particular package.
struct Signature {
    needles: &'static [&'static [u8]],
    name: &'static str,
    license: &'static str,
}

const SIGNATURES: &[Signature] = &[
    // --- Core embedded packages ---
    Signature {
        needles: &[b"BusyBox v", b"BusyBox is", b"busybox"],
        name: "busybox",
        license: "GPL-2.0-only",
    },
    Signature {
        needles: &[b"OpenSSL ", b"openssl", b"OPENSSL_"],
        name: "openssl",
        license: "Apache-2.0",
    },
    Signature {
        needles: &[b"U-Boot ", b"U-Boot 2", b"das U-Boot"],
        name: "u-boot",
        license: "GPL-2.0-or-later",
    },
    Signature {
        needles: &[b"zlib ", b"deflate ", b"inflate "],
        name: "zlib",
        license: "Zlib",
    },
    Signature {
        needles: &[b"libcurl", b"curl_easy", b"CURL_"],
        name: "curl",
        license: "MIT",
    },
    Signature {
        needles: &[b"dropbear", b"Dropbear SSH"],
        name: "dropbear",
        license: "MIT",
    },
    Signature {
        needles: &[b"lighttpd", b"Lighttpd"],
        name: "lighttpd",
        license: "BSD-3-Clause",
    },
    Signature {
        needles: &[b"dnsmasq", b"Dnsmasq"],
        name: "dnsmasq",
        license: "GPL-2.0-only",
    },
    Signature {
        needles: &[b"sqlite3", b"SQLite format"],
        name: "sqlite",
        license: "blessing",
    },
    Signature {
        needles: &[b"mbedtls", b"mbedTLS", b"MBEDTLS_"],
        name: "mbedtls",
        license: "Apache-2.0",
    },
    Signature {
        needles: &[b"wolfSSL", b"wolfssl", b"WOLFSSL"],
        name: "wolfssl",
        license: "GPL-2.0-or-later",
    },
    Signature {
        needles: &[b"lwIP ", b"lwip"],
        name: "lwip",
        license: "BSD-3-Clause",
    },
    Signature {
        needles: &[b"FreeRTOS", b"freertos"],
        name: "freertos",
        license: "MIT",
    },
    Signature {
        needles: &[b"libnl", b"NETLINK"],
        name: "libnl",
        license: "LGPL-2.1-only",
    },
    Signature {
        needles: &[b"libpcap", b"pcap_"],
        name: "libpcap",
        license: "BSD-3-Clause",
    },
    Signature {
        needles: &[b"GNU C Library", b"GLIBC_", b"glibc"],
        name: "glibc",
        license: "LGPL-2.1-or-later",
    },
    Signature {
        needles: &[b"musl libc", b"musl"],
        name: "musl",
        license: "MIT",
    },
    Signature {
        needles: &[b"uClibc", b"uclibc"],
        name: "uclibc",
        license: "LGPL-2.1-only",
    },
    Signature {
        needles: &[b"iptables", b"libiptc"],
        name: "iptables",
        license: "GPL-2.0-or-later",
    },
    Signature {
        needles: &[b"Linux version "],
        name: "linux-kernel",
        license: "GPL-2.0-only",
    },
    // --- Expanded: messaging / networking ---
    Signature {
        needles: &[b"mosquitto", b"Mosquitto", b"MOSQ_"],
        name: "mosquitto",
        license: "EPL-2.0",
    },
    Signature {
        needles: &[b"nginx/", b"nginx version", b"NGINX"],
        name: "nginx",
        license: "BSD-2-Clause",
    },
    // --- Expanded: scripting / runtimes ---
    Signature {
        needles: &[b"Lua ", b"lua_push", b"LUA_"],
        name: "lua",
        license: "MIT",
    },
    Signature {
        needles: &[b"Python ", b"Py_Initialize", b"PYTHON_"],
        name: "python",
        license: "PSF-2.0",
    },
    Signature {
        needles: &[b"node_module", b"NODE_VERSION", b"libuv_version"],
        name: "node",
        license: "MIT",
    },
    // --- Expanded: system services ---
    Signature {
        needles: &[b"dbus-daemon", b"org.freedesktop.DBus", b"DBUS_"],
        name: "dbus",
        license: "AFL-2.1",
    },
    Signature {
        needles: &[b"systemd ", b"systemd-", b"SYSTEMD_"],
        name: "systemd",
        license: "LGPL-2.1-or-later",
    },
    Signature {
        needles: &[b"NetworkManager", b"org.freedesktop.NetworkManager"],
        name: "networkmanager",
        license: "GPL-2.0-or-later",
    },
    Signature {
        needles: &[b"wpa_supplicant", b"WPA_SUPPLICANT"],
        name: "wpa_supplicant",
        license: "BSD-3-Clause",
    },
    Signature {
        needles: &[b"hostapd", b"HOSTAPD"],
        name: "hostapd",
        license: "BSD-3-Clause",
    },
    // --- Expanded: network tools ---
    Signature {
        needles: &[b"iproute2", b"ip -Version"],
        name: "iproute2",
        license: "GPL-2.0-only",
    },
    Signature {
        needles: &[b"nftables", b"nft_"],
        name: "nftables",
        license: "GPL-2.0-or-later",
    },
    Signature {
        needles: &[b"tcpdump", b"TCPDUMP_"],
        name: "tcpdump",
        license: "BSD-3-Clause",
    },
    // --- Expanded: debug tools ---
    Signature {
        needles: &[b"strace", b"STRACE_"],
        name: "strace",
        license: "LGPL-2.1-or-later",
    },
    Signature {
        needles: &[b"GNU gdb", b"GDB_"],
        name: "gdb",
        license: "GPL-3.0-or-later",
    },
    Signature {
        needles: &[b"valgrind", b"Valgrind"],
        name: "valgrind",
        license: "GPL-2.0-or-later",
    },
    // --- Expanded: libraries ---
    Signature {
        needles: &[b"libxml2", b"xmlParseDoc", b"LIBXML_"],
        name: "libxml2",
        license: "MIT",
    },
    Signature {
        needles: &[b"libpng", b"PNG_LIBPNG_VER"],
        name: "libpng",
        license: "Libpng",
    },
    Signature {
        needles: &[b"JFIF", b"libjpeg", b"JPEG_LIB_VERSION"],
        name: "libjpeg",
        license: "IJG",
    },
    Signature {
        needles: &[b"expat ", b"XML_Parser", b"EXPAT_"],
        name: "expat",
        license: "MIT",
    },
    Signature {
        needles: &[b"ncurses", b"NCURSES_"],
        name: "ncurses",
        license: "X11",
    },
    Signature {
        needles: &[b"libreadline", b"rl_readline_version"],
        name: "readline",
        license: "GPL-3.0-or-later",
    },
    // --- Expanded: shells / core ---
    Signature {
        needles: &[b"GNU bash", b"BASH_VERSION"],
        name: "bash",
        license: "GPL-3.0-or-later",
    },
    Signature {
        needles: &[b"coreutils", b"GNU coreutils"],
        name: "coreutils",
        license: "GPL-3.0-or-later",
    },
    // --- Expanded: remote access ---
    Signature {
        needles: &[b"OpenSSH", b"SSH-2.0-OpenSSH"],
        name: "openssh",
        license: "BSD-2-Clause",
    },
    // --- Expanded: service discovery ---
    Signature {
        needles: &[b"avahi-daemon", b"Avahi mDNS"],
        name: "avahi",
        license: "LGPL-2.1-or-later",
    },
    Signature {
        needles: &[b"bluetoothd", b"BlueZ"],
        name: "bluez",
        license: "GPL-2.0-or-later",
    },
    // --- Expanded: OpenWrt-specific ---
    Signature {
        needles: &[b"ubus", b"libubus"],
        name: "ubus",
        license: "LGPL-2.1-only",
    },
    Signature {
        needles: &[b"procd", b"/sbin/procd"],
        name: "procd",
        license: "GPL-2.0-only",
    },
    Signature {
        needles: &[b"netifd", b"/sbin/netifd"],
        name: "netifd",
        license: "GPL-2.0-only",
    },
    Signature {
        needles: &[b"jansson", b"json_object_get"],
        name: "jansson",
        license: "MIT",
    },
    Signature {
        needles: &[b"libubox", b"uloop_"],
        name: "libubox",
        license: "ISC",
    },
    Signature {
        needles: &[b"libuci", b"uci_"],
        name: "libuci",
        license: "GPL-2.0-only",
    },
    Signature {
        needles: &[b"uhttpd", b"uhttpd "],
        name: "uhttpd",
        license: "ISC",
    },
    Signature {
        needles: &[b"swconfig", b"switch_dev"],
        name: "swconfig",
        license: "GPL-2.0-only",
    },
];

/// AES S-box first 16 bytes (used to detect AES implementations).
const AES_SBOX_PREFIX: &[u8] = &[
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
];

/// SHA-256 initial hash values (first 4 words).
const SHA256_INIT: &[u8] = &[
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
];

/// SHA-256 round constants (first 8 bytes: K[0] = 0x428a2f98, K[1] = 0x71374491).
const SHA256_K_PREFIX: &[u8] = &[
    0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
];

/// Map well-known shared library names to package names and licenses.
fn known_library(soname: &str) -> Option<(&'static str, &'static str)> {
    // Strip version suffixes: libssl.so.3 -> libssl.so
    let base = soname.split('.').take(2).collect::<Vec<_>>().join(".");
    match base.as_str() {
        "libssl.so" | "libcrypto.so" => Some(("openssl", "Apache-2.0")),
        "libz.so" => Some(("zlib", "Zlib")),
        "libcurl.so" => Some(("curl", "MIT")),
        "libsqlite3.so" => Some(("sqlite", "blessing")),
        "libpcap.so" => Some(("libpcap", "BSD-3-Clause")),
        "libpthread.so" | "libc.so" | "libdl.so" | "libm.so" | "librt.so" => {
            Some(("glibc", "LGPL-2.1-or-later"))
        }
        "libmbedtls.so" | "libmbedcrypto.so" | "libmbedx509.so" => {
            Some(("mbedtls", "Apache-2.0"))
        }
        "libwolfssl.so" => Some(("wolfssl", "GPL-2.0-or-later")),
        "libxml2.so" => Some(("libxml2", "MIT")),
        "libpng16.so" | "libpng12.so" | "libpng.so" => Some(("libpng", "Libpng")),
        "libjpeg.so" => Some(("libjpeg", "IJG")),
        "libexpat.so" => Some(("expat", "MIT")),
        "libncurses.so" | "libncursesw.so" => Some(("ncurses", "X11")),
        "libreadline.so" => Some(("readline", "GPL-3.0-or-later")),
        "libdbus-1.so" => Some(("dbus", "AFL-2.1")),
        "libsystemd.so" => Some(("systemd", "LGPL-2.1-or-later")),
        "libnm.so" => Some(("networkmanager", "GPL-2.0-or-later")),
        "liblua.so" | "liblua5.so" => Some(("lua", "MIT")),
        "libjansson.so" => Some(("jansson", "MIT")),
        "libubox.so" => Some(("libubox", "ISC")),
        "libubus.so" => Some(("ubus", "LGPL-2.1-only")),
        "libuci.so" => Some(("libuci", "GPL-2.0-only")),
        "libmosquitto.so" => Some(("mosquitto", "EPL-2.0")),
        "libavahi-common.so" | "libavahi-client.so" => Some(("avahi", "LGPL-2.1-or-later")),
        "libbluetooth.so" => Some(("bluez", "GPL-2.0-or-later")),
        _ => None,
    }
}

/// Firmware analyzer that walks a directory tree, inspects files, and
/// discovers software components.
pub struct FirmwareAnalyzer {
    root: PathBuf,
    exclude_patterns: Vec<String>,
    min_confidence: f64,
}

/// Analysis results including all metadata gathered.
pub struct AnalysisResult {
    pub components: Vec<Component>,
    pub elf_metadata: Vec<ElfMetadata>,
    pub dependency_edges: Vec<DependencyEdge>,
    pub distro_info: Option<DistroInfo>,
    pub kernel_config: Option<KernelSecurityConfig>,
    pub files_scanned: usize,
}

impl FirmwareAnalyzer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            exclude_patterns: Vec::new(),
            min_confidence: 0.0,
        }
    }

    /// Set exclude patterns for directories/files to skip.
    pub fn with_excludes(mut self, patterns: Vec<String>) -> Self {
        self.exclude_patterns = patterns;
        self
    }

    /// Set minimum confidence threshold.
    pub fn with_min_confidence(mut self, min: f64) -> Self {
        self.min_confidence = min;
        self
    }

    /// Check if a path should be excluded.
    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.exclude_patterns.iter().any(|pat| {
            path_str.contains(pat.as_str())
        })
    }

    /// Run the full analysis pipeline and return discovered components.
    /// This is the backward-compatible method that returns just components.
    #[allow(dead_code)]
    pub fn analyze(&self) -> Result<Vec<Component>> {
        let result = self.analyze_full()?;
        Ok(result.components)
    }

    /// Run the full analysis pipeline and return all results.
    ///
    /// Phase 1 (sequential): walk the file tree, collect metadata (distro info,
    /// kernel config, package manager data), and build the list of files to scan.
    /// Phase 2 (parallel via rayon): scan collected files for ELF, string
    /// signatures, and crypto constants in parallel.
    pub fn analyze_full(&self) -> Result<AnalysisResult> {
        let mut components: Vec<Component> = Vec::new();
        let mut seen: HashMap<(String, String), bool> = HashMap::new();
        let mut distro_info: Option<DistroInfo> = None;
        let mut kernel_config: Option<KernelSecurityConfig> = None;
        let mut files_scanned: usize = 0;

        // Files that need heavy scanning (ELF + signatures + crypto).
        let mut scan_queue: Vec<PathBuf> = Vec::new();

        // Phase 1: sequential walk for metadata and lightweight checks.
        for entry in WalkDir::new(&self.root)
            .follow_links(false) // avoid incorrect hashes for symlinks
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();

            // Check exclude patterns.
            if self.is_excluded(path) {
                continue;
            }

            files_scanned += 1;

            // Try filesystem metadata (os-release, openwrt_release).
            if distro_info.is_none() {
                if let Some(info) = self.check_distro_info(path)? {
                    distro_info = Some(info);
                }
            }

            // Try kernel config.
            if kernel_config.is_none() {
                if let Some(config) = self.check_kernel_config(path)? {
                    kernel_config = Some(config);
                }
            }

            // Try opkg .control files.
            if let Some(mut ctrl_components) = self.check_opkg_control(path)? {
                for c in &mut ctrl_components {
                    let key = (c.name.clone(), c.file_path.clone());
                    if !seen.contains_key(&key) {
                        seen.insert(key, true);
                        components.push(c.clone());
                    }
                }
            }

            // Try package-manager metadata first.
            if let Some(mut pkg_components) = self.check_package_metadata(path)? {
                for c in &mut pkg_components {
                    let key = (c.name.clone(), c.file_path.clone());
                    if !seen.contains_key(&key) {
                        seen.insert(key, true);
                        components.push(c.clone());
                    }
                }
                continue;
            }

            // Try license file detection.
            if license::is_license_file(path) {
                let rel = self.relative_path(path);
                if let Some(detection) = license::detect_license_in_file(path, &rel) {
                    let _ = detection; // tracked for future use
                }
                // Skip documentation/license files from binary scanning
                // to avoid false positives (e.g. "BusyBox" in docs).
                continue;
            }

            // Skip very large files > 256 MiB and empty files.
            let metadata = match fs::metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.len() == 0 || metadata.len() > 256 * 1024 * 1024 {
                continue;
            }

            scan_queue.push(path.to_path_buf());
        }

        // Phase 2: parallel file scanning using rayon.
        let par_components = Mutex::new(Vec::<Component>::new());
        let par_elf_metadata = Mutex::new(Vec::<ElfMetadata>::new());
        let par_dep_edges = Mutex::new(Vec::<DependencyEdge>::new());

        scan_queue.par_iter().for_each(|path| {
            let hash = match self.sha256_file(path) {
                Ok(h) => h,
                Err(_) => return,
            };
            let rel_path = self.relative_path(path);

            let mut local_components = Vec::new();
            let mut local_elf_meta = Vec::new();
            let mut local_edges = Vec::new();

            // Deep ELF analysis.
            if let Ok(Some((elf_meta, elf_components, edges))) =
                elf_deep::analyze_elf_deep(path, &rel_path, &hash)
            {
                local_elf_meta.push(elf_meta);
                local_edges.extend(edges);
                local_components.extend(elf_components);
            }

            // ELF dynamic library detection.
            if let Ok(Some(elf_components)) = self.analyze_elf(path, &hash, &rel_path) {
                local_components.extend(elf_components);
            }

            // String-signature scanning.
            if let Ok(Some(sig_components)) =
                self.scan_signatures(path, &hash, &rel_path)
            {
                local_components.extend(sig_components);
            }

            // Crypto constant scanning.
            if let Ok(Some(crypto_components)) =
                self.scan_crypto_constants(path, &hash, &rel_path)
            {
                local_components.extend(crypto_components);
            }

            // Merge into shared collections.
            if !local_components.is_empty() {
                par_components.lock().unwrap().extend(local_components);
            }
            if !local_elf_meta.is_empty() {
                par_elf_metadata.lock().unwrap().extend(local_elf_meta);
            }
            if !local_edges.is_empty() {
                par_dep_edges.lock().unwrap().extend(local_edges);
            }
        });

        // Collect parallel results.
        let par_found = par_components.into_inner().unwrap();
        let elf_metadata = par_elf_metadata.into_inner().unwrap();
        let dependency_edges = par_dep_edges.into_inner().unwrap();

        // Merge parallel results with sequential results, deduplicating.
        for c in par_found {
            let key = (c.name.clone(), c.file_path.clone());
            if !seen.contains_key(&key) {
                seen.insert(key, true);
                components.push(c);
            }
        }

        // Deduplicate: keep one entry per (name, version) pair, preferring
        // the one with higher confidence.
        let mut deduped: HashMap<String, Component> = HashMap::new();
        for c in components {
            let key = format!("{}@{}", c.name, c.version.as_deref().unwrap_or("unknown"));
            deduped
                .entry(key)
                .and_modify(|existing| {
                    // Prefer entries with higher confidence or more info.
                    if c.confidence > existing.confidence
                        || (existing.version.is_none() && c.version.is_some())
                    {
                        *existing = c.clone();
                    }
                })
                .or_insert(c);
        }

        let mut result: Vec<Component> = deduped
            .into_values()
            .filter(|c| c.confidence >= self.min_confidence)
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(AnalysisResult {
            components: result,
            elf_metadata,
            dependency_edges,
            distro_info,
            kernel_config,
            files_scanned,
        })
    }

    /// Compute SHA-256 of a file.
    fn sha256_file(&self, path: &Path) -> Result<String> {
        let mut file = fs::File::open(path).context("opening file for hashing")?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file.read(&mut buf).context("reading file for hashing")?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Return a display-friendly relative path from the firmware root.
    fn relative_path(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    }

    /// Try to extract version strings near a signature match.
    fn extract_version_near(data: &[u8], pos: usize) -> Option<String> {
        // Look for a version pattern (digits.digits...) within 64 bytes after the match.
        let start = pos;
        let end = (pos + 128).min(data.len());
        let window = &data[start..end];

        // Find first digit sequence that looks like a version.
        let mut i = 0;
        while i < window.len() {
            if window[i].is_ascii_digit() {
                let ver_start = i;
                // Consume digits, dots, hyphens, underscores (version chars).
                while i < window.len()
                    && (window[i].is_ascii_alphanumeric()
                        || window[i] == b'.'
                        || window[i] == b'-'
                        || window[i] == b'_')
                {
                    i += 1;
                }
                let candidate = &window[ver_start..i];
                // Must contain at least one dot and be reasonable length.
                if candidate.contains(&b'.')
                    && candidate.len() >= 3
                    && candidate.len() <= 32
                {
                    if let Ok(s) = std::str::from_utf8(candidate) {
                        // Trim trailing punctuation.
                        let s = s.trim_end_matches(|c: char| !c.is_alphanumeric());
                        if !s.is_empty() {
                            return Some(s.to_string());
                        }
                    }
                }
            }
            i += 1;
        }
        None
    }

    /// Scan file contents for known string signatures.
    fn scan_signatures(
        &self,
        path: &Path,
        hash: &str,
        rel_path: &str,
    ) -> Result<Option<Vec<Component>>> {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        let mut results = Vec::new();
        let confidence = method_confidence(&DetectionMethod::StringSignature);

        for sig in SIGNATURES {
            let mut matched = false;
            let mut version: Option<String> = None;

            for needle in sig.needles {
                if let Some(pos) = find_bytes(&data, needle) {
                    matched = true;
                    if version.is_none() {
                        version = Self::extract_version_near(&data, pos);
                    }
                    break;
                }
            }

            if matched {
                let purl = make_purl(sig.name, version.as_deref());
                results.push(Component {
                    name: sig.name.to_string(),
                    version,
                    sha256: hash.to_string(),
                    license: Some(sig.license.to_string()),
                    purl: Some(purl),
                    file_path: rel_path.to_string(),
                    detection_method: DetectionMethod::StringSignature,
                    confidence,
                    cpe: None,
                    known_cves: None,
                });
            }
        }

        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }

    /// Scan for crypto algorithm constants (AES S-box, SHA-256 constants).
    fn scan_crypto_constants(
        &self,
        path: &Path,
        hash: &str,
        rel_path: &str,
    ) -> Result<Option<Vec<Component>>> {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };

        let mut results = Vec::new();
        let confidence = method_confidence(&DetectionMethod::CryptoConstant);

        // Check for AES S-box.
        if find_bytes(&data, AES_SBOX_PREFIX).is_some() {
            results.push(Component {
                name: "aes-implementation".to_string(),
                version: None,
                sha256: hash.to_string(),
                license: None,
                purl: Some("pkg:generic/aes-implementation".to_string()),
                file_path: rel_path.to_string(),
                detection_method: DetectionMethod::CryptoConstant,
                confidence,
                cpe: None,
                known_cves: None,
            });
        }

        // Check for SHA-256 constants.
        if find_bytes(&data, SHA256_INIT).is_some()
            || find_bytes(&data, SHA256_K_PREFIX).is_some()
        {
            results.push(Component {
                name: "sha256-implementation".to_string(),
                version: None,
                sha256: hash.to_string(),
                license: None,
                purl: Some("pkg:generic/sha256-implementation".to_string()),
                file_path: rel_path.to_string(),
                detection_method: DetectionMethod::CryptoConstant,
                confidence,
                cpe: None,
                known_cves: None,
            });
        }

        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }

    /// Parse ELF files and extract dynamically linked libraries.
    fn analyze_elf(
        &self,
        path: &Path,
        hash: &str,
        rel_path: &str,
    ) -> Result<Option<Vec<Component>>> {
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

        let mut results = Vec::new();
        let confidence = method_confidence(&DetectionMethod::ElfDynamic);

        // Extract needed shared libraries.
        for lib in &elf.libraries {
            if let Some((pkg_name, lic)) = known_library(lib) {
                let purl = make_purl(pkg_name, None);
                results.push(Component {
                    name: pkg_name.to_string(),
                    version: None,
                    sha256: hash.to_string(),
                    license: Some(lic.to_string()),
                    purl: Some(purl),
                    file_path: rel_path.to_string(),
                    detection_method: DetectionMethod::ElfDynamic,
                    confidence,
                    cpe: None,
                    known_cves: None,
                });
            }
        }

        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }

    /// Check for package manager metadata files (opkg status, dpkg status).
    fn check_package_metadata(&self, path: &Path) -> Result<Option<Vec<Component>>> {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        let parent = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|f| f.to_str())
            .unwrap_or("");

        // opkg: /usr/lib/opkg/status or /var/lib/opkg/status
        // dpkg: /var/lib/dpkg/status
        let is_opkg = parent == "opkg" && filename == "status";
        let is_dpkg = parent == "dpkg" && filename == "status";

        if !is_opkg && !is_dpkg {
            return Ok(None);
        }

        let content = fs::read_to_string(path).context("reading package metadata")?;
        let hash = self.sha256_file(path)?;
        let rel_path = self.relative_path(path);
        let mut results = Vec::new();
        let confidence = method_confidence(&DetectionMethod::PackageManager);

        // Both opkg and dpkg use a similar stanza format.
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;
        let mut current_license: Option<String> = None;

        for line in content.lines() {
            if line.is_empty() {
                // End of stanza -- emit component.
                if let Some(name) = current_name.take() {
                    let version = current_version.take();
                    let license = current_license.take().or_else(|| {
                        license::lookup_package_license(&name).map(|s| s.to_string())
                    });
                    let purl = make_purl(&name, version.as_deref());
                    results.push(Component {
                        name: name.clone(),
                        version,
                        sha256: hash.clone(),
                        license,
                        purl: Some(purl),
                        file_path: rel_path.clone(),
                        detection_method: DetectionMethod::PackageManager,
                        confidence,
                        cpe: None,
                        known_cves: None,
                    });
                }
                continue;
            }

            if let Some(val) = line.strip_prefix("Package: ") {
                current_name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Version: ") {
                current_version = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("License: ") {
                current_license = Some(val.trim().to_string());
            }
        }

        // Handle last stanza without trailing newline.
        if let Some(name) = current_name.take() {
            let version = current_version.take();
            let license = current_license.take().or_else(|| {
                license::lookup_package_license(&name).map(|s| s.to_string())
            });
            let purl = make_purl(&name, version.as_deref());
            results.push(Component {
                name,
                version,
                sha256: hash.clone(),
                license,
                purl: Some(purl),
                file_path: rel_path.clone(),
                detection_method: DetectionMethod::PackageManager,
                confidence,
                cpe: None,
                known_cves: None,
            });
        }

        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }

    /// Check for opkg .control files in /usr/lib/opkg/info/*.control.
    fn check_opkg_control(&self, path: &Path) -> Result<Option<Vec<Component>>> {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if !filename.ends_with(".control") {
            return Ok(None);
        }

        // Check parent is "info" and grandparent is "opkg".
        let parent = path.parent().and_then(|p| p.file_name()).and_then(|f| f.to_str()).unwrap_or("");
        let grandparent = path.parent().and_then(|p| p.parent()).and_then(|p| p.file_name()).and_then(|f| f.to_str()).unwrap_or("");

        if parent != "info" || grandparent != "opkg" {
            return Ok(None);
        }

        let content = fs::read_to_string(path).context("reading opkg control file")?;
        let hash = self.sha256_file(path)?;
        let rel_path = self.relative_path(path);
        let confidence = method_confidence(&DetectionMethod::PackageManager);

        let mut name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut lic: Option<String> = None;
        let mut _description: Option<String> = None;

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("Package: ") {
                name = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Version: ") {
                version = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("License: ") {
                lic = Some(val.trim().to_string());
            } else if let Some(val) = line.strip_prefix("Description: ") {
                _description = Some(val.trim().to_string());
            }
        }

        if let Some(pkg_name) = name {
            let license = lic.or_else(|| {
                license::lookup_package_license(&pkg_name).map(|s| s.to_string())
            });
            let purl = make_purl(&pkg_name, version.as_deref());
            Ok(Some(vec![Component {
                name: pkg_name,
                version,
                sha256: hash,
                license,
                purl: Some(purl),
                file_path: rel_path,
                detection_method: DetectionMethod::PackageManager,
                confidence,
                cpe: None,
                known_cves: None,
            }]))
        } else {
            Ok(None)
        }
    }

    /// Check for distribution info files (os-release, openwrt_release).
    fn check_distro_info(&self, path: &Path) -> Result<Option<DistroInfo>> {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");

        if filename != "os-release" && filename != "openwrt_release" {
            return Ok(None);
        }

        // Verify path looks right (under /etc).
        let parent = path.parent().and_then(|p| p.file_name()).and_then(|f| f.to_str()).unwrap_or("");
        if parent != "etc" {
            return Ok(None);
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        let mut info = DistroInfo {
            id: None,
            name: None,
            version: None,
            build_id: None,
        };

        for line in content.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim_matches('"').trim_matches('\'');
                match key {
                    "ID" | "DISTRIB_ID" => info.id = Some(value.to_string()),
                    "NAME" | "DISTRIB_DESCRIPTION" => info.name = Some(value.to_string()),
                    "VERSION_ID" | "DISTRIB_RELEASE" | "VERSION" => {
                        info.version = Some(value.to_string())
                    }
                    "BUILD_ID" | "DISTRIB_REVISION" => info.build_id = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        if info.id.is_some() || info.name.is_some() {
            Ok(Some(info))
        } else {
            Ok(None)
        }
    }

    /// Parse kernel config for security-relevant settings.
    fn check_kernel_config(&self, path: &Path) -> Result<Option<KernelSecurityConfig>> {
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");

        // Check for /boot/config-* or /proc/config.gz (as extracted).
        let is_kernel_config = filename.starts_with("config-")
            && path.parent().and_then(|p| p.file_name()).and_then(|f| f.to_str()) == Some("boot");
        let is_proc_config = filename == "config.gz"
            && path.parent().and_then(|p| p.file_name()).and_then(|f| f.to_str()) == Some("proc");

        // Also check for plain "config" under a kernel-related directory.
        if !is_kernel_config && !is_proc_config {
            return Ok(None);
        }

        // Read the config (skip compressed for now, focus on plaintext).
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        // Verify it looks like a kernel config.
        if !content.contains("CONFIG_") {
            return Ok(None);
        }

        let mut config = KernelSecurityConfig {
            stack_protector: None,
            aslr: None,
            selinux: None,
            apparmor: None,
            seccomp: None,
            modules_disabled: None,
            hardened_usercopy: None,
            fortify_source: None,
        };

        for line in content.lines() {
            let line = line.trim();
            match line {
                "CONFIG_STACKPROTECTOR=y" | "CONFIG_CC_STACKPROTECTOR=y" | "CONFIG_STACKPROTECTOR_STRONG=y" => {
                    config.stack_protector = Some(true);
                }
                "# CONFIG_STACKPROTECTOR is not set" | "# CONFIG_CC_STACKPROTECTOR is not set" => {
                    config.stack_protector = Some(false);
                }
                "CONFIG_RANDOMIZE_BASE=y" => {
                    config.aslr = Some(true);
                }
                "# CONFIG_RANDOMIZE_BASE is not set" => {
                    config.aslr = Some(false);
                }
                "CONFIG_SECURITY_SELINUX=y" => {
                    config.selinux = Some(true);
                }
                "# CONFIG_SECURITY_SELINUX is not set" => {
                    config.selinux = Some(false);
                }
                "CONFIG_SECURITY_APPARMOR=y" => {
                    config.apparmor = Some(true);
                }
                "# CONFIG_SECURITY_APPARMOR is not set" => {
                    config.apparmor = Some(false);
                }
                "CONFIG_SECCOMP=y" => {
                    config.seccomp = Some(true);
                }
                "# CONFIG_SECCOMP is not set" => {
                    config.seccomp = Some(false);
                }
                "CONFIG_MODULES=y" => {
                    config.modules_disabled = Some(false);
                }
                "# CONFIG_MODULES is not set" => {
                    config.modules_disabled = Some(true);
                }
                "CONFIG_HARDENED_USERCOPY=y" => {
                    config.hardened_usercopy = Some(true);
                }
                "# CONFIG_HARDENED_USERCOPY is not set" => {
                    config.hardened_usercopy = Some(false);
                }
                "CONFIG_FORTIFY_SOURCE=y" => {
                    config.fortify_source = Some(true);
                }
                "# CONFIG_FORTIFY_SOURCE is not set" => {
                    config.fortify_source = Some(false);
                }
                _ => {}
            }
        }

        Ok(Some(config))
    }
}

/// Build a Package URL for a generic firmware package.
fn make_purl(name: &str, version: Option<&str>) -> String {
    match version {
        Some(v) => format!("pkg:generic/{}@{}", name, v),
        None => format!("pkg:generic/{}", name),
    }
}

/// Naive byte-string search (returns first occurrence position).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper to create a temp directory with a file containing given bytes.
    fn temp_dir_with_file(filename: &str, contents: &[u8]) -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let file_path = dir.path().join(filename);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(contents).unwrap();
        dir
    }

    // ---- find_bytes tests ----

    #[test]
    fn find_bytes_finds_needle_at_start() {
        let haystack = b"BusyBox v1.36.1";
        let needle = b"BusyBox v";
        assert_eq!(find_bytes(haystack, needle), Some(0));
    }

    #[test]
    fn find_bytes_finds_needle_in_middle() {
        let haystack = b"\x00\x00\x00openssl\x00\x00";
        let needle = b"openssl";
        assert_eq!(find_bytes(haystack, needle), Some(3));
    }

    #[test]
    fn find_bytes_returns_none_when_absent() {
        let haystack = b"nothing here";
        let needle = b"BusyBox";
        assert_eq!(find_bytes(haystack, needle), None);
    }

    #[test]
    fn find_bytes_empty_needle_returns_none() {
        let haystack = b"some data";
        assert_eq!(find_bytes(haystack, b""), None);
    }

    #[test]
    fn find_bytes_needle_longer_than_haystack_returns_none() {
        let haystack = b"hi";
        let needle = b"much longer needle";
        assert_eq!(find_bytes(haystack, needle), None);
    }

    // ---- make_purl tests ----

    #[test]
    fn make_purl_with_version() {
        assert_eq!(make_purl("openssl", Some("3.1.0")), "pkg:generic/openssl@3.1.0");
    }

    #[test]
    fn make_purl_without_version() {
        assert_eq!(make_purl("openssl", None), "pkg:generic/openssl");
    }

    // ---- extract_version_near tests ----

    #[test]
    fn extract_version_from_busybox_string() {
        let data = b"BusyBox v1.36.1 (2024-01-15)";
        let version = FirmwareAnalyzer::extract_version_near(data, 0);
        assert_eq!(version, Some("1.36.1".to_string()));
    }

    #[test]
    fn extract_version_from_uboot_string() {
        let data = b"U-Boot 2023.10-rc3 (Sep 01 2023)";
        let version = FirmwareAnalyzer::extract_version_near(data, 0);
        assert_eq!(version, Some("2023.10-rc3".to_string()));
    }

    #[test]
    fn extract_version_from_openssl_string() {
        let data = b"OpenSSL 3.1.4 21 Nov 2023";
        let version = FirmwareAnalyzer::extract_version_near(data, 0);
        assert_eq!(version, Some("3.1.4".to_string()));
    }

    #[test]
    fn extract_version_no_version_present() {
        let data = b"just some text with no version numbers at all here";
        let version = FirmwareAnalyzer::extract_version_near(data, 0);
        assert!(version.is_none());
    }

    #[test]
    fn extract_version_ignores_single_number_without_dot() {
        let data = b"some text 42 end";
        let version = FirmwareAnalyzer::extract_version_near(data, 0);
        assert!(version.is_none());
    }

    #[test]
    fn extract_version_linux_kernel() {
        let data = b"Linux version 5.15.0-generic (gcc 12.2.0)";
        let version = FirmwareAnalyzer::extract_version_near(data, 0);
        assert_eq!(version, Some("5.15.0-generic".to_string()));
    }

    // ---- sha256_file tests ----

    #[test]
    fn sha256_of_known_content() {
        let dir = temp_dir_with_file("test.bin", b"hello world");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("test.bin")).unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256_of_empty_file() {
        let dir = temp_dir_with_file("empty.bin", b"");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("empty.bin")).unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ---- scan_signatures tests ----

    #[test]
    fn scan_detects_busybox_signature() {
        let dir = temp_dir_with_file("busybox", b"\x00\x00BusyBox v1.36.1 (2024-01-15)\x00\x00");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("busybox")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("busybox"), &hash, "busybox")
            .unwrap();

        let components = result.expect("should detect busybox");
        assert!(!components.is_empty());
        let bb = components.iter().find(|c| c.name == "busybox").unwrap();
        assert_eq!(bb.version.as_deref(), Some("1.36.1"));
        assert_eq!(bb.license.as_deref(), Some("GPL-2.0-only"));
        assert_eq!(bb.detection_method, DetectionMethod::StringSignature);
        assert!(bb.purl.as_ref().unwrap().contains("busybox@1.36.1"));
        assert!(bb.confidence > 0.0);
    }

    #[test]
    fn scan_detects_openssl_signature() {
        let dir = temp_dir_with_file("libssl.so", b"random bytes OpenSSL 3.1.4 more stuff");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("libssl.so")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("libssl.so"), &hash, "libssl.so")
            .unwrap();

        let components = result.expect("should detect openssl");
        let ossl = components.iter().find(|c| c.name == "openssl").unwrap();
        assert_eq!(ossl.version.as_deref(), Some("3.1.4"));
    }

    #[test]
    fn scan_detects_multiple_signatures_in_one_file() {
        let mut data = Vec::new();
        data.extend_from_slice(b"libcurl 8.4.0 something ");
        data.extend_from_slice(b"zlib 1.3.1 deflate ");
        let dir = temp_dir_with_file("multi.bin", &data);
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("multi.bin")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("multi.bin"), &hash, "multi.bin")
            .unwrap();

        let components = result.expect("should detect multiple components");
        let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"curl"), "should detect curl, found: {:?}", names);
        assert!(names.contains(&"zlib"), "should detect zlib, found: {:?}", names);
    }

    #[test]
    fn scan_returns_none_for_file_without_signatures() {
        let dir = temp_dir_with_file("random.bin", b"nothing recognizable at all in here xyz");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("random.bin")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("random.bin"), &hash, "random.bin")
            .unwrap();

        assert!(result.is_none());
    }

    // ---- known_library tests ----

    #[test]
    fn known_library_recognizes_libssl() {
        let result = known_library("libssl.so.3");
        assert_eq!(result, Some(("openssl", "Apache-2.0")));
    }

    #[test]
    fn known_library_recognizes_libz() {
        let result = known_library("libz.so.1");
        assert_eq!(result, Some(("zlib", "Zlib")));
    }

    #[test]
    fn known_library_recognizes_libc() {
        let result = known_library("libc.so.6");
        assert_eq!(result, Some(("glibc", "LGPL-2.1-or-later")));
    }

    #[test]
    fn known_library_returns_none_for_unknown() {
        assert!(known_library("libfoo.so.1").is_none());
    }

    #[test]
    fn known_library_recognizes_new_libs() {
        assert!(known_library("libxml2.so.2").is_some());
        assert!(known_library("libdbus-1.so.3").is_some());
        assert!(known_library("libjansson.so.4").is_some());
    }

    // ---- deduplication tests ----

    #[test]
    fn analyze_deduplicates_same_component_different_files() {
        let dir = TempDir::new().unwrap();
        let data = b"\x00BusyBox v1.36.1\x00";

        for name in &["bin/busybox", "sbin/busybox"] {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(data).unwrap();
        }

        let analyzer = FirmwareAnalyzer::new(dir.path());
        let components = analyzer.analyze().unwrap();

        let busybox_count = components
            .iter()
            .filter(|c| c.name == "busybox" && c.version.as_deref() == Some("1.36.1"))
            .count();
        assert_eq!(busybox_count, 1, "busybox should be deduplicated to one entry");
    }

    #[test]
    fn analyze_keeps_different_versions_as_separate() {
        let dir = TempDir::new().unwrap();

        let data1 = b"\x00BusyBox v1.36.1\x00";
        let data2 = b"\x00BusyBox v1.35.0\x00";

        let path1 = dir.path().join("busybox1");
        let path2 = dir.path().join("busybox2");

        fs::File::create(&path1).unwrap().write_all(data1).unwrap();
        fs::File::create(&path2).unwrap().write_all(data2).unwrap();

        let analyzer = FirmwareAnalyzer::new(dir.path());
        let components = analyzer.analyze().unwrap();

        let busybox_versions: Vec<Option<&str>> = components
            .iter()
            .filter(|c| c.name == "busybox")
            .map(|c| c.version.as_deref())
            .collect();
        assert!(busybox_versions.contains(&Some("1.36.1")));
        assert!(busybox_versions.contains(&Some("1.35.0")));
    }

    #[test]
    fn analyze_results_sorted_by_name() {
        let dir = TempDir::new().unwrap();

        let path_z = dir.path().join("libz.bin");
        fs::File::create(&path_z).unwrap().write_all(b"\x00zlib 1.3.1 deflate \x00").unwrap();

        let path_c = dir.path().join("curl.bin");
        fs::File::create(&path_c).unwrap().write_all(b"\x00libcurl 8.4.0\x00").unwrap();

        let analyzer = FirmwareAnalyzer::new(dir.path());
        let components = analyzer.analyze().unwrap();

        let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
        let mut sorted_names = names.clone();
        sorted_names.sort();
        assert_eq!(names, sorted_names, "components should be sorted by name");
    }

    // ---- package metadata tests ----

    #[test]
    fn check_opkg_status_file() {
        let dir = TempDir::new().unwrap();
        let opkg_dir = dir.path().join("var/lib/opkg");
        fs::create_dir_all(&opkg_dir).unwrap();

        let status_content = "\
Package: busybox
Version: 1.36.1-1
License: GPL-2.0-only

Package: dropbear
Version: 2022.83-1
License: MIT
";
        fs::write(opkg_dir.join("status"), status_content).unwrap();

        let analyzer = FirmwareAnalyzer::new(dir.path());
        let result = analyzer
            .check_package_metadata(&opkg_dir.join("status"))
            .unwrap();

        let components = result.expect("should parse opkg status");
        assert_eq!(components.len(), 2);

        let bb = components.iter().find(|c| c.name == "busybox").unwrap();
        assert_eq!(bb.version.as_deref(), Some("1.36.1-1"));
        assert_eq!(bb.detection_method, DetectionMethod::PackageManager);
        assert!(bb.confidence > 0.9);

        let db = components.iter().find(|c| c.name == "dropbear").unwrap();
        assert_eq!(db.version.as_deref(), Some("2022.83-1"));
    }

    #[test]
    fn check_non_metadata_file_returns_none() {
        let dir = temp_dir_with_file("random.txt", b"just text");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let result = analyzer
            .check_package_metadata(&dir.path().join("random.txt"))
            .unwrap();
        assert!(result.is_none());
    }

    // ---- distro info tests ----

    #[test]
    fn check_os_release() {
        let dir = TempDir::new().unwrap();
        let etc_dir = dir.path().join("etc");
        fs::create_dir_all(&etc_dir).unwrap();
        fs::write(
            etc_dir.join("os-release"),
            "ID=openwrt\nNAME=\"OpenWrt\"\nVERSION_ID=\"23.05.0\"\nBUILD_ID=\"r23497\"\n",
        )
        .unwrap();

        let analyzer = FirmwareAnalyzer::new(dir.path());
        let info = analyzer
            .check_distro_info(&etc_dir.join("os-release"))
            .unwrap();

        let info = info.expect("should detect distro info");
        assert_eq!(info.id.as_deref(), Some("openwrt"));
        assert_eq!(info.name.as_deref(), Some("OpenWrt"));
        assert_eq!(info.version.as_deref(), Some("23.05.0"));
    }

    // ---- kernel config tests ----

    #[test]
    fn check_kernel_config_parses() {
        let dir = TempDir::new().unwrap();
        let boot_dir = dir.path().join("boot");
        fs::create_dir_all(&boot_dir).unwrap();
        fs::write(
            boot_dir.join("config-5.15.0"),
            "# Kernel config\nCONFIG_STACKPROTECTOR=y\nCONFIG_RANDOMIZE_BASE=y\n# CONFIG_SECURITY_SELINUX is not set\nCONFIG_SECCOMP=y\nCONFIG_MODULES=y\n",
        )
        .unwrap();

        let analyzer = FirmwareAnalyzer::new(dir.path());
        let config = analyzer
            .check_kernel_config(&boot_dir.join("config-5.15.0"))
            .unwrap();

        let config = config.expect("should parse kernel config");
        assert_eq!(config.stack_protector, Some(true));
        assert_eq!(config.aslr, Some(true));
        assert_eq!(config.selinux, Some(false));
        assert_eq!(config.seccomp, Some(true));
        assert_eq!(config.modules_disabled, Some(false));
    }

    // ---- exclude patterns test ----

    #[test]
    fn exclude_patterns_skip_files() {
        let dir = TempDir::new().unwrap();

        let path1 = dir.path().join("keep.bin");
        fs::File::create(&path1).unwrap().write_all(b"\x00BusyBox v1.36.1\x00").unwrap();

        let skip_dir = dir.path().join("skip_me");
        fs::create_dir_all(&skip_dir).unwrap();
        let path2 = skip_dir.join("hidden.bin");
        fs::File::create(&path2).unwrap().write_all(b"\x00OpenSSL 3.1.4\x00").unwrap();

        let analyzer = FirmwareAnalyzer::new(dir.path())
            .with_excludes(vec!["skip_me".to_string()]);
        let components = analyzer.analyze().unwrap();

        let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"busybox"));
        assert!(!names.contains(&"openssl"), "openssl should be excluded");
    }

    // ---- min confidence test ----

    #[test]
    fn min_confidence_filters_components() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        fs::File::create(&path).unwrap().write_all(b"\x00BusyBox v1.36.1\x00").unwrap();

        // With high min confidence, string signatures should be filtered out.
        let analyzer = FirmwareAnalyzer::new(dir.path())
            .with_min_confidence(0.99);
        let components = analyzer.analyze().unwrap();
        assert!(components.is_empty(), "high confidence threshold should filter all string-signature results");
    }

    // ---- expanded signature tests ----

    #[test]
    fn scan_detects_mosquitto() {
        let dir = temp_dir_with_file("mosquitto.bin", b"\x00mosquitto 2.0.18\x00");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("mosquitto.bin")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("mosquitto.bin"), &hash, "mosquitto.bin")
            .unwrap();
        let components = result.expect("should detect mosquitto");
        assert!(components.iter().any(|c| c.name == "mosquitto"));
    }

    #[test]
    fn scan_detects_nginx() {
        let dir = temp_dir_with_file("nginx.bin", b"\x00nginx/1.25.0\x00");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("nginx.bin")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("nginx.bin"), &hash, "nginx.bin")
            .unwrap();
        let components = result.expect("should detect nginx");
        assert!(components.iter().any(|c| c.name == "nginx"));
    }

    #[test]
    fn scan_detects_systemd() {
        let dir = temp_dir_with_file("systemd.bin", b"\x00systemd 255\x00");
        let analyzer = FirmwareAnalyzer::new(dir.path());
        let hash = analyzer.sha256_file(&dir.path().join("systemd.bin")).unwrap();
        let result = analyzer
            .scan_signatures(&dir.path().join("systemd.bin"), &hash, "systemd.bin")
            .unwrap();
        let components = result.expect("should detect systemd");
        assert!(components.iter().any(|c| c.name == "systemd"));
    }

    #[test]
    fn signature_count_above_50() {
        assert!(
            SIGNATURES.len() >= 50,
            "should have at least 50 signatures, found {}",
            SIGNATURES.len()
        );
    }
}

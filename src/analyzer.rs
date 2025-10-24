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


//! License detection engine.
//!
//! Scans for LICENSE/COPYING files, SPDX identifiers in file headers,
//! and maps known package names to licenses.

use std::fs;
use std::path::Path;

use crate::models::LicenseDetection;
use crate::models::LicenseSource;

/// Well-known license file names.
const LICENSE_FILENAMES: &[&str] = &[
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENCE",
    "LICENCE.txt",
    "COPYING",
    "COPYING.txt",
    "COPYING.LIB",
    "COPYRIGHT",
    "NOTICE",
    "NOTICE.txt",
];

/// Known package-to-license mappings (extends the signature database).
const PACKAGE_LICENSE_MAP: &[(&str, &str)] = &[
    ("busybox", "GPL-2.0-only"),
    ("openssl", "Apache-2.0"),
    ("u-boot", "GPL-2.0-or-later"),
    ("zlib", "Zlib"),
    ("curl", "MIT"),
    ("dropbear", "MIT"),
    ("lighttpd", "BSD-3-Clause"),
    ("dnsmasq", "GPL-2.0-only"),
    ("sqlite", "blessing"),
    ("mbedtls", "Apache-2.0"),
    ("wolfssl", "GPL-2.0-or-later"),
    ("lwip", "BSD-3-Clause"),
    ("freertos", "MIT"),
    ("libnl", "LGPL-2.1-only"),
    ("libpcap", "BSD-3-Clause"),
    ("glibc", "LGPL-2.1-or-later"),
    ("musl", "MIT"),
    ("uclibc", "LGPL-2.1-only"),
    ("iptables", "GPL-2.0-or-later"),
    ("linux-kernel", "GPL-2.0-only"),
    ("mosquitto", "EPL-2.0"),
    ("nginx", "BSD-2-Clause"),
    ("python", "PSF-2.0"),
    ("node", "MIT"),
    ("lua", "MIT"),
    ("dbus", "AFL-2.1"),
    ("systemd", "LGPL-2.1-or-later"),
    ("networkmanager", "GPL-2.0-or-later"),
    ("wpa_supplicant", "BSD-3-Clause"),
    ("hostapd", "BSD-3-Clause"),
    ("iproute2", "GPL-2.0-only"),
    ("nftables", "GPL-2.0-or-later"),
    ("tcpdump", "BSD-3-Clause"),
    ("strace", "LGPL-2.1-or-later"),
    ("gdb", "GPL-3.0-or-later"),
    ("valgrind", "GPL-2.0-or-later"),
    ("gcc", "GPL-3.0-or-later"),
    ("clang", "Apache-2.0"),
    ("libxml2", "MIT"),
    ("libpng", "Libpng"),
    ("libjpeg", "IJG"),
    ("expat", "MIT"),
    ("ncurses", "X11"),
    ("readline", "GPL-3.0-or-later"),
    ("bash", "GPL-3.0-or-later"),
    ("coreutils", "GPL-3.0-or-later"),
    ("openssh", "BSD-2-Clause"),
    ("avahi", "LGPL-2.1-or-later"),
    ("bluez", "GPL-2.0-or-later"),
    ("ubus", "LGPL-2.1-only"),
    ("procd", "GPL-2.0-only"),
    ("netifd", "GPL-2.0-only"),
    ("jansson", "MIT"),
    ("libubox", "ISC"),
];

/// Signature patterns for detecting licenses in file content.
struct LicensePattern {
    spdx_id: &'static str,
    patterns: &'static [&'static str],
}

const LICENSE_PATTERNS: &[LicensePattern] = &[
    LicensePattern {
        spdx_id: "MIT",
        patterns: &[
            "Permission is hereby granted, free of charge",
            "MIT License",
            "The MIT License",
        ],
    },
    LicensePattern {
        spdx_id: "Apache-2.0",
        patterns: &[
            "Apache License, Version 2.0",
            "Licensed under the Apache License",
            "Apache-2.0",
        ],
    },
    LicensePattern {
        spdx_id: "GPL-2.0-only",
        patterns: &[
            "GNU General Public License, version 2",
            "GPLv2",
            "GPL-2.0-only",
        ],
    },
    LicensePattern {
        spdx_id: "GPL-2.0-or-later",
        patterns: &[
            "either version 2 of the License, or (at your option) any later version",
            "GPL-2.0-or-later",
            "GPL-2.0+",
        ],
    },
    LicensePattern {
        spdx_id: "GPL-3.0-or-later",
        patterns: &[
            "GNU General Public License, version 3",
            "GPLv3",
            "GPL-3.0-or-later",
        ],
    },
    LicensePattern {
        spdx_id: "LGPL-2.1-only",
        patterns: &[
            "GNU Lesser General Public License, version 2.1",
            "LGPL-2.1-only",
        ],
    },
    LicensePattern {
        spdx_id: "LGPL-2.1-or-later",
        patterns: &[
            "GNU Lesser General Public License",
            "LGPL-2.1-or-later",
        ],
    },
    LicensePattern {
        spdx_id: "BSD-2-Clause",
        patterns: &[
            "Redistribution and use in source and binary forms",
            "BSD-2-Clause",
            "2-clause BSD",
        ],
    },
    LicensePattern {
        spdx_id: "BSD-3-Clause",
        patterns: &[
            "BSD-3-Clause",
            "3-clause BSD",
        ],
    },
    LicensePattern {
        spdx_id: "Zlib",
        patterns: &[
            "zlib License",
            "This software is provided 'as-is'",
        ],
    },
    LicensePattern {
        spdx_id: "ISC",
        patterns: &[
            "ISC License",
            "Permission to use, copy, modify, and/or distribute",
        ],
    },
    LicensePattern {
        spdx_id: "MPL-2.0",
        patterns: &[
            "Mozilla Public License Version 2.0",
            "MPL-2.0",
        ],
    },
    LicensePattern {
        spdx_id: "EPL-2.0",
        patterns: &[
            "Eclipse Public License",
            "EPL-2.0",
        ],
    },
];

/// Check if a file path looks like a license file.
pub fn is_license_file(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");
    LICENSE_FILENAMES.iter().any(|&n| n.eq_ignore_ascii_case(filename))
}

/// Scan a file for license information.
pub fn detect_license_in_file(path: &Path, rel_path: &str) -> Option<LicenseDetection> {
    // Only read text-like files up to 256KB.
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > 256 * 1024 || metadata.len() == 0 {
        return None;
    }

    let content = fs::read_to_string(path).ok()?;

    // Check for SPDX-License-Identifier headers first.
    if let Some(spdx) = extract_spdx_header(&content) {
        return Some(LicenseDetection {
            file_path: rel_path.to_string(),
            spdx_id: spdx,
            confidence: 0.90,
            source: LicenseSource::SpdxHeader,
        });
    }

    // Check content against known license patterns.
    for pattern in LICENSE_PATTERNS {
        for needle in pattern.patterns {
            if content.contains(needle) {
                let is_dedicated = is_license_file(path);
                return Some(LicenseDetection {
                    file_path: rel_path.to_string(),
                    spdx_id: pattern.spdx_id.to_string(),
                    confidence: if is_dedicated { 0.85 } else { 0.60 },
                    source: if is_dedicated {
                        LicenseSource::DedicatedFile
                    } else {
                        LicenseSource::SpdxHeader
                    },
                });
            }
        }
    }

    None
}

/// Extract SPDX-License-Identifier from file content.
fn extract_spdx_header(content: &str) -> Option<String> {
    for line in content.lines().take(30) {
        if let Some(idx) = line.find("SPDX-License-Identifier:") {
            let rest = &line[idx + "SPDX-License-Identifier:".len()..];
            let spdx = rest.trim().trim_end_matches(|c: char| c == '*' || c == '/');
            if !spdx.is_empty() {
                return Some(spdx.trim().to_string());
            }
        }
    }
    None
}

/// Look up a package name in the known license mapping.
pub fn lookup_package_license(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    PACKAGE_LICENSE_MAP
        .iter()
        .find(|(pkg, _)| *pkg == lower)
        .map(|(_, lic)| *lic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn is_license_file_detects_common_names() {
        assert!(is_license_file(Path::new("LICENSE")));
        assert!(is_license_file(Path::new("COPYING")));
        assert!(is_license_file(Path::new("LICENSE.txt")));
        assert!(is_license_file(Path::new("/some/path/NOTICE")));
        assert!(!is_license_file(Path::new("main.c")));
    }

    #[test]
    fn extract_spdx_from_header() {
        let content = "// SPDX-License-Identifier: MIT\n// Copyright 2024\n";
        assert_eq!(extract_spdx_header(content), Some("MIT".to_string()));
    }

    #[test]
    fn extract_spdx_apache() {
        let content = "/* SPDX-License-Identifier: Apache-2.0 */\n";
        assert_eq!(extract_spdx_header(content), Some("Apache-2.0".to_string()));
    }

    #[test]
    fn extract_spdx_none_when_absent() {
        let content = "// just a regular comment\nfn main() {}\n";
        assert!(extract_spdx_header(content).is_none());
    }

    #[test]
    fn lookup_known_packages() {
        assert_eq!(lookup_package_license("openssl"), Some("Apache-2.0"));
        assert_eq!(lookup_package_license("busybox"), Some("GPL-2.0-only"));
        assert_eq!(lookup_package_license("mosquitto"), Some("EPL-2.0"));
        assert!(lookup_package_license("unknown-pkg").is_none());
    }

    #[test]
    fn detect_mit_license_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("LICENSE");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"MIT License\n\nPermission is hereby granted, free of charge...\n")
            .unwrap();

        let result = detect_license_in_file(&path, "LICENSE");
        assert!(result.is_some());
        let det = result.unwrap();
        assert_eq!(det.spdx_id, "MIT");
        assert!(det.confidence > 0.8);
    }

    #[test]
    fn detect_apache_license_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("LICENSE");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"Apache License, Version 2.0\n\nTerms and Conditions...\n")
            .unwrap();

        let result = detect_license_in_file(&path, "LICENSE");
        assert!(result.is_some());
        assert_eq!(result.unwrap().spdx_id, "Apache-2.0");
    }
}

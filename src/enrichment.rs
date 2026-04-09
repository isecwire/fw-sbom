//! CPE / vulnerability enrichment engine.
//!
//! Maps discovered components to CPE identifiers and provides
//! known vulnerability hints from a built-in database.

use crate::models::{Component, CpeEntry, CveHint};

/// Built-in CPE dictionary mapping package names to CPE prefixes.
const CPE_DATABASE: &[(&str, &str, &str)] = &[
    // (package_name, vendor, product)
    ("openssl", "openssl", "openssl"),
    ("busybox", "busybox", "busybox"),
    ("u-boot", "denx", "u-boot"),
    ("zlib", "zlib", "zlib"),
    ("curl", "haxx", "curl"),
    ("dropbear", "matt_johnston", "dropbear_ssh_server"),
    ("lighttpd", "lighttpd", "lighttpd"),
    ("dnsmasq", "thekelleys", "dnsmasq"),
    ("sqlite", "sqlite", "sqlite"),
    ("mbedtls", "arm", "mbed_tls"),
    ("wolfssl", "wolfssl", "wolfssl"),
    ("lwip", "lwip_project", "lwip"),
    ("freertos", "amazon", "freertos"),
    ("glibc", "gnu", "glibc"),
    ("musl", "musl-libc", "musl"),
    ("uclibc", "uclibc-ng_project", "uclibc-ng"),
    ("iptables", "netfilter", "iptables"),
    ("linux-kernel", "linux", "linux_kernel"),
    ("mosquitto", "eclipse", "mosquitto"),
    ("nginx", "f5", "nginx"),
    ("python", "python", "python"),
    ("node", "nodejs", "node.js"),
    ("lua", "lua", "lua"),
    ("dbus", "freedesktop", "dbus"),
    ("systemd", "systemd_project", "systemd"),
    ("networkmanager", "gnome", "networkmanager"),
    ("wpa_supplicant", "w1.fi", "wpa_supplicant"),
    ("hostapd", "w1.fi", "hostapd"),
    ("iproute2", "linux", "iproute2"),
    ("nftables", "netfilter", "nftables"),
    ("tcpdump", "tcpdump", "tcpdump"),
    ("libpcap", "tcpdump", "libpcap"),
    ("strace", "strace_project", "strace"),
    ("gdb", "gnu", "gdb"),
    ("valgrind", "valgrind", "valgrind"),
    ("openssh", "openbsd", "openssh"),
    ("libxml2", "xmlsoft", "libxml2"),
    ("libpng", "libpng", "libpng"),
    ("expat", "libexpat_project", "libexpat"),
    ("bash", "gnu", "bash"),
    ("coreutils", "gnu", "coreutils"),
    ("ncurses", "gnu", "ncurses"),
    ("readline", "gnu", "readline"),
    ("avahi", "avahi", "avahi"),
    ("bluez", "bluez", "bluez"),
    ("gcc", "gnu", "gcc"),
    ("clang", "llvm", "clang"),
    ("libjpeg", "ijg", "libjpeg"),
    ("jansson", "digip", "jansson"),
];

/// Well-known CVE hints for common embedded packages.
/// These are examples of high-severity CVEs for awareness; not a complete database.
const CVE_HINTS: &[(&str, &str, &str, &str)] = &[
    // (package, cve_id, affected_versions, severity)
    ("openssl", "CVE-2024-5535", "< 3.3.2", "HIGH"),
    ("openssl", "CVE-2024-0727", "< 3.2.1", "MEDIUM"),
    ("openssl", "CVE-2023-5678", "< 3.1.5", "MEDIUM"),
    ("busybox", "CVE-2022-48174", "< 1.36.0", "CRITICAL"),
    ("busybox", "CVE-2022-30065", "< 1.35.0", "HIGH"),
    ("curl", "CVE-2024-2398", "< 8.7.1", "MEDIUM"),
    ("curl", "CVE-2024-2004", "< 8.7.1", "LOW"),
    ("curl", "CVE-2023-46218", "< 8.5.0", "MEDIUM"),
    ("zlib", "CVE-2023-45853", "< 1.3.1", "CRITICAL"),
    ("zlib", "CVE-2022-37434", "< 1.2.12", "CRITICAL"),
    ("dnsmasq", "CVE-2023-50387", "< 2.90", "HIGH"),
    ("dnsmasq", "CVE-2023-50868", "< 2.90", "HIGH"),
    ("u-boot", "CVE-2022-30790", "< 2022.07", "HIGH"),
    ("u-boot", "CVE-2022-30552", "< 2022.07", "HIGH"),
    ("linux-kernel", "CVE-2024-1086", "< 6.8", "HIGH"),
    ("linux-kernel", "CVE-2023-6931", "< 6.7", "HIGH"),
    ("dropbear", "CVE-2023-48795", "< 2022.83-5", "MEDIUM"),
    ("mosquitto", "CVE-2023-28366", "< 2.0.16", "HIGH"),
    ("nginx", "CVE-2024-7347", "< 1.27.1", "MEDIUM"),
    ("sqlite", "CVE-2023-7104", "< 3.43.2", "HIGH"),
    ("mbedtls", "CVE-2024-23170", "< 3.5.2", "HIGH"),
    ("wolfssl", "CVE-2024-1544", "< 5.6.6", "HIGH"),
    ("systemd", "CVE-2023-26604", "< 247.3-7", "HIGH"),
    ("wpa_supplicant", "CVE-2023-52160", "< 2.10-5", "MEDIUM"),
    ("openssh", "CVE-2024-6387", "< 9.8p1", "CRITICAL"),
    ("libxml2", "CVE-2024-25062", "< 2.12.5", "HIGH"),
    ("glibc", "CVE-2023-6246", "< 2.39", "HIGH"),
    ("glibc", "CVE-2023-4911", "< 2.38-4", "HIGH"),
    ("tcpdump", "CVE-2023-1801", "< 4.99.4", "MEDIUM"),
    ("expat", "CVE-2024-45490", "< 2.6.3", "CRITICAL"),
    ("python", "CVE-2024-6923", "< 3.12.5", "MEDIUM"),
];

/// Look up the CPE identifier for a component.
pub fn lookup_cpe(name: &str, version: Option<&str>) -> Option<String> {
    let lower = name.to_lowercase();
    CPE_DATABASE
        .iter()
        .find(|(pkg, _, _)| *pkg == lower)
        .map(|(_, vendor, product)| {
            let ver = version.unwrap_or("*");
            format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", vendor, product, ver)
        })
}

/// Get CPE entry details for a package.
#[allow(dead_code)]
pub fn get_cpe_entry(name: &str) -> Option<CpeEntry> {
    let lower = name.to_lowercase();
    CPE_DATABASE
        .iter()
        .find(|(pkg, _, _)| *pkg == lower)
        .map(|(pkg, vendor, product)| {
            let cves: Vec<CveHint> = CVE_HINTS
                .iter()
                .filter(|(p, _, _, _)| *p == *pkg)
                .map(|(_, cve_id, affected, severity)| CveHint {
                    cve_id: cve_id.to_string(),
                    affected_versions: affected.to_string(),
                    severity: severity.to_string(),
                })
                .collect();

            CpeEntry {
                package_pattern: pkg.to_string(),
                vendor: vendor.to_string(),
                product: product.to_string(),
                cpe_prefix: format!("cpe:2.3:a:{}:{}:", vendor, product),
                known_cves: cves,
            }
        })
}

/// Enrich a list of components with CPE identifiers and CVE hints.
pub fn enrich_components(components: &mut [Component]) {
    for comp in components.iter_mut() {
        // Add CPE.
        if comp.cpe.is_none() {
            comp.cpe = lookup_cpe(&comp.name, comp.version.as_deref());
        }

        // Add known CVE hints.
        if comp.known_cves.is_none() {
            let cves: Vec<String> = CVE_HINTS
                .iter()
                .filter(|(pkg, _, _, _)| *pkg == comp.name.as_str())
                .map(|(_, cve_id, _, _)| cve_id.to_string())
                .collect();
            if !cves.is_empty() {
                comp.known_cves = Some(cves);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_cpe_openssl() {
        let cpe = lookup_cpe("openssl", Some("3.1.0"));
        assert_eq!(
            cpe,
            Some("cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*".to_string())
        );
    }

    #[test]
    fn lookup_cpe_without_version() {
        let cpe = lookup_cpe("curl", None);
        assert_eq!(cpe, Some("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*".to_string()));
    }

    #[test]
    fn lookup_cpe_unknown_package() {
        assert!(lookup_cpe("unknown-pkg", None).is_none());
    }

    #[test]
    fn get_cpe_entry_with_cves() {
        let entry = get_cpe_entry("openssl").unwrap();
        assert_eq!(entry.vendor, "openssl");
        assert_eq!(entry.product, "openssl");
        assert!(!entry.known_cves.is_empty());
    }

    #[test]
    fn enrich_adds_cpe_and_cves() {
        let mut components = vec![Component {
            name: "openssl".to_string(),
            version: Some("3.1.0".to_string()),
            sha256: "abc".to_string(),
            license: Some("Apache-2.0".to_string()),
            purl: None,
            file_path: String::new(),
            detection_method: crate::models::DetectionMethod::StringSignature,
            confidence: 0.5,
            cpe: None,
            known_cves: None,
        }];

        enrich_components(&mut components);

        assert!(components[0].cpe.is_some());
        assert!(components[0].cpe.as_ref().unwrap().contains("openssl"));
        assert!(components[0].known_cves.is_some());
        assert!(!components[0].known_cves.as_ref().unwrap().is_empty());
    }

    #[test]
    fn lookup_cpe_case_insensitive() {
        assert!(lookup_cpe("OpenSSL", Some("3.0")).is_some());
        assert!(lookup_cpe("CURL", None).is_some());
    }
}

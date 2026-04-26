//! Defs-free kernel-version discovery via raw physical-memory scanning.
//!
//! Scans physical memory for the Linux banner string (`"Linux version ..."`) exactly
//! as Volatility3 does, without requiring a pre-built defs file. The discovered
//! version string tells the user which vmlinux or debug-symbol package to obtain.

use log::debug;
use memchr::memmem;
use memflow::prelude::v1::*;

const BANNER_PREFIX: &[u8] = b"Linux version ";
const SCAN_CHUNK: usize = size::mb(64);
// Long enough to capture any realistic banner including compiler and date fields.
const MAX_BANNER_LEN: usize = 512;

/// Kernel version and banner discovered from a raw physical-memory scan.
#[derive(Clone, Debug)]
pub struct KernelVersionInfo {
    /// Full Linux banner (e.g. `"Linux version 5.15.0-46-generic (buildd@...) ..."`)
    pub banner: String,
    /// Short version token extracted from the banner (e.g. `"5.15.0-46-generic"`).
    pub version: String,
    /// Physical address of the `"Linux version "` prefix in memory.
    pub phys_address: Address,
}

/// Scans all of physical memory for occurrences of the Linux kernel banner and
/// returns one `KernelVersionInfo` per unique version string found.
///
/// No defs file is required. Use this to identify the running kernel before
/// downloading the matching vmlinux or distribution debug-symbol package.
///
/// The scan is linear and reads memory in 64 MiB chunks with a small overlap so
/// banners that straddle a chunk boundary are never missed.
pub fn discover_kernel_versions<T: PhysicalMemory>(mem: &mut T) -> Vec<KernelVersionInfo> {
    let total = mem.metadata().max_address.to_umem().saturating_add(1);
    // Overlap adjacent chunks by `prefix_len - 1` so a banner split across the
    // boundary is caught by the next window.
    let overlap = (BANNER_PREFIX.len() - 1) as u64;
    // The buffer is SCAN_CHUNK + MAX_BANNER_LEN so a banner that starts near the
    // end of a chunk can still be fully extracted without an extra read.
    let mut buf = vec![0u8; SCAN_CHUNK + MAX_BANNER_LEN];
    let mut base = 0u64;
    let mut seen: Vec<String> = Vec::new();
    let mut results: Vec<KernelVersionInfo> = Vec::new();

    debug!(
        "kernel discovery: scanning {:#x} bytes of physical memory for Linux banner",
        total
    );

    while base < total {
        let remaining = total.saturating_sub(base);
        let chunk = (SCAN_CHUNK as u64).min(remaining) as usize;
        // Tail bytes beyond the chunk window — used only for banner extraction,
        // not for pattern matching, so we never double-report a hit.
        let tail = (MAX_BANNER_LEN as u64)
            .min(remaining.saturating_sub(chunk as u64)) as usize;
        let window = chunk + tail;

        if window < BANNER_PREFIX.len() {
            break;
        }

        if mem
            .phys_view()
            .read_raw_into(Address::from(base), &mut buf[..window])
            .is_err()
        {
            // On read failure skip the chunk rather than abort the whole scan.
            base = base.saturating_add(chunk as u64).saturating_sub(overlap);
            continue;
        }

        // Only search within the non-overlapping chunk window so each physical
        // address is reported at most once.
        for off in memmem::find_iter(&buf[..chunk], BANNER_PREFIX) {
            let phys_addr = base + off as u64;
            let content_start = off + BANNER_PREFIX.len();
            let content_end = (content_start + MAX_BANNER_LEN).min(window);
            let content = &buf[content_start..content_end];

            let end = content
                .iter()
                .position(|&b| b == b'\0' || b == b'\n' || b == b'\r')
                .unwrap_or(content.len());
            let suffix = String::from_utf8_lossy(&content[..end]).into_owned();
            let version = suffix
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_owned();

            if version.is_empty() || seen.contains(&version) {
                continue;
            }

            debug!(
                "kernel discovery: Linux version {} at physical {:#x}",
                version, phys_addr
            );
            seen.push(version.clone());
            results.push(KernelVersionInfo {
                banner: format!("Linux version {suffix}"),
                version,
                phys_address: Address::from(phys_addr),
            });
        }

        if chunk as u64 == remaining {
            break;
        }
        base = base
            .saturating_add(chunk as u64)
            .saturating_sub(overlap);
    }

    results
}

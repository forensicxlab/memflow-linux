//! Persistent kernel-hint cache helpers.
//!
//! The cache stores validated physical kernel base hints keyed by a cheap
//! fingerprint of the inspected memory and the selected Linux defs.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, info};
use memflow::mem::PhysicalMemory;
use memflow::prelude::v1::*;

use crate::profile::LinuxProfile;

const CACHE_VERSION: u32 = 1;
const CACHE_FILE_PREFIX: &str = "kernel-hint-v1-";
const CACHE_FILE_SUFFIX: &str = ".toml";
const FINGERPRINT_SAMPLE_SIZE: usize = 4096;

#[derive(Clone, Debug)]
/// User-configurable policy for the persistent kernel-hint cache.
pub struct KernelHintCacheOptions {
    enabled: bool,
    dir: Option<PathBuf>,
}

impl Default for KernelHintCacheOptions {
    fn default() -> Self {
        Self::from_env()
    }
}

impl KernelHintCacheOptions {
    /// Builds cache options from `MEMFLOW_LINUX_KERNEL_HINT_CACHE`.
    pub fn from_env() -> Self {
        match env::var("MEMFLOW_LINUX_KERNEL_HINT_CACHE") {
            Ok(value) => match parse_cache_option(value.trim()) {
                CacheOptionValue::Disabled => Self {
                    enabled: false,
                    dir: None,
                },
                CacheOptionValue::Default => Self {
                    enabled: true,
                    dir: None,
                },
                CacheOptionValue::Dir(dir) => Self {
                    enabled: true,
                    dir: Some(dir),
                },
            },
            Err(_) => Self {
                enabled: true,
                dir: None,
            },
        }
    }

    /// Returns options that disable kernel-hint caching entirely.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            dir: None,
        }
    }

    /// Enables caching and forces a specific cache directory.
    pub fn with_dir(path: impl AsRef<Path>) -> Self {
        Self {
            enabled: true,
            dir: Some(path.as_ref().to_path_buf()),
        }
    }

    fn resolve_dir(&self) -> Option<PathBuf> {
        if !self.enabled {
            return None;
        }

        self.dir.clone().or_else(default_cache_dir)
    }
}

#[derive(Clone, Debug)]
/// Cache handle for one inspected memory image or live target fingerprint.
pub struct KernelHintCache {
    path: PathBuf,
    memory_fingerprint: u64,
}

impl KernelHintCache {
    /// Creates a cache handle for the supplied physical memory backend.
    pub fn prepare<T: PhysicalMemory + Clone>(
        mut mem: T,
        options: &KernelHintCacheOptions,
    ) -> Result<Option<Self>> {
        let Some(dir) = options.resolve_dir() else {
            return Ok(None);
        };

        let fingerprint = compute_memory_fingerprint(&mut mem);
        let path = dir.join(format!(
            "{CACHE_FILE_PREFIX}{fingerprint:016x}{CACHE_FILE_SUFFIX}"
        ));

        debug!(
            "linux bootstrap: kernel hint cache ready at {}",
            path.display()
        );

        Ok(Some(Self {
            path,
            memory_fingerprint: fingerprint,
        }))
    }

    /// Loads a previously stored kernel hint if the cache entry still matches.
    pub fn load_kernel_hint(&self) -> Result<Option<Address>> {
        let content = match fs::read_to_string(&self.path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                debug!(
                    "linux bootstrap: kernel hint cache miss at {}",
                    self.path.display()
                );
                return Ok(None);
            }
            Err(err) => {
                return Err(Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadFile)
                    .log_info(err)
                    .log_error(format!(
                        "failed to read Linux kernel hint cache {}",
                        self.path.display()
                    )));
            }
        };

        let entry = parse_cache_entry(&content)?;
        if entry.version != CACHE_VERSION {
            debug!(
                "linux bootstrap: ignoring kernel hint cache {} with unsupported version {}",
                self.path.display(),
                entry.version
            );
            return Ok(None);
        }

        if entry.memory_fingerprint != self.memory_fingerprint {
            debug!(
                "linux bootstrap: ignoring stale kernel hint cache {} (fingerprint mismatch)",
                self.path.display()
            );
            return Ok(None);
        }

        info!(
            "linux bootstrap: loaded cached kernel hint {} from {}",
            entry.kernel_hint,
            self.path.display()
        );
        Ok(Some(entry.kernel_hint))
    }

    /// Persists a validated kernel hint for later runs.
    pub fn store(&self, profile: &LinuxProfile, kernel_hint: Address) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                Error(ErrorOrigin::OsLayer, ErrorKind::UnableToWriteFile)
                    .log_info(err)
                    .log_error(format!(
                        "failed to create Linux kernel hint cache directory {}",
                        parent.display()
                    ))
            })?;
        }

        let entry = CacheEntry {
            version: CACHE_VERSION,
            memory_fingerprint: self.memory_fingerprint,
            defs_fingerprint: compute_defs_fingerprint(profile),
            kernel_hint,
            updated_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        fs::write(&self.path, format_cache_entry(&entry)).map_err(|err| {
            Error(ErrorOrigin::OsLayer, ErrorKind::UnableToWriteFile)
                .log_info(err)
                .log_error(format!(
                    "failed to write Linux kernel hint cache {}",
                    self.path.display()
                ))
        })?;

        info!(
            "linux bootstrap: wrote kernel hint cache {} -> {}",
            self.path.display(),
            kernel_hint
        );
        Ok(())
    }

    /// Returns the on-disk path used by this cache handle.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheEntry {
    version: u32,
    memory_fingerprint: u64,
    defs_fingerprint: u64,
    kernel_hint: Address,
    updated_unix_secs: u64,
}

enum CacheOptionValue {
    Disabled,
    Default,
    Dir(PathBuf),
}

fn parse_cache_option(value: &str) -> CacheOptionValue {
    if value.is_empty()
        || value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("on")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("default")
    {
        CacheOptionValue::Default
    } else if value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("disabled")
    {
        CacheOptionValue::Disabled
    } else {
        CacheOptionValue::Dir(PathBuf::from(value))
    }
}

fn format_cache_entry(entry: &CacheEntry) -> String {
    format!(
        "version = {}\nmemory_fingerprint = \"0x{:016x}\"\ndefs_fingerprint = \"0x{:016x}\"\nkernel_hint = \"0x{:x}\"\nupdated_unix_secs = {}\n",
        entry.version,
        entry.memory_fingerprint,
        entry.defs_fingerprint,
        entry.kernel_hint.to_umem(),
        entry.updated_unix_secs,
    )
}

fn parse_cache_entry(content: &str) -> Result<CacheEntry> {
    let mut version = None;
    let mut memory_fingerprint = None;
    let mut defs_fingerprint = None;
    let mut kernel_hint = None;
    let mut updated_unix_secs = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');

        match key {
            "version" => version = value.parse::<u32>().ok(),
            "memory_fingerprint" => memory_fingerprint = parse_hex_u64(value),
            "defs_fingerprint" => defs_fingerprint = parse_hex_u64(value),
            "kernel_hint" => kernel_hint = parse_hex_u64(value).map(Address::from),
            "updated_unix_secs" => updated_unix_secs = value.parse::<u64>().ok(),
            _ => {}
        }
    }

    match (
        version,
        memory_fingerprint,
        defs_fingerprint,
        kernel_hint,
        updated_unix_secs,
    ) {
        (
            Some(version),
            Some(memory_fingerprint),
            Some(defs_fingerprint),
            Some(kernel_hint),
            Some(updated_unix_secs),
        ) => Ok(CacheEntry {
            version,
            memory_fingerprint,
            defs_fingerprint,
            kernel_hint,
            updated_unix_secs,
        }),
        _ => Err(Error(ErrorOrigin::OsLayer, ErrorKind::Encoding)
            .log_error("failed to parse Linux kernel hint cache entry")),
    }
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let digits = trimmed.trim_start_matches("0x").trim_start_matches("0X");
    let radix = if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        16
    } else if digits
        .bytes()
        .any(|byte| matches!(byte, b'a'..=b'f' | b'A'..=b'F'))
    {
        16
    } else {
        10
    };

    u64::from_str_radix(digits, radix).ok()
}

fn compute_memory_fingerprint(mem: &mut impl PhysicalMemory) -> u64 {
    let metadata = mem.metadata();
    let total = metadata.max_address.to_umem().saturating_add(1);
    let sample_offsets = fingerprint_sample_offsets(total);
    let mut buf = [0_u8; FINGERPRINT_SAMPLE_SIZE];
    let mut hash = Fnv64::new();

    hash.write_u64(metadata.max_address.to_umem());
    hash.write_u64(metadata.real_size);
    hash.write_u64(metadata.ideal_batch_size as u64);
    hash.write_u8(u8::from(metadata.readonly));

    for offset in sample_offsets {
        let remaining = total.saturating_sub(offset);
        let read_len = remaining.min(FINGERPRINT_SAMPLE_SIZE as u64) as usize;
        if read_len == 0 {
            continue;
        }

        buf[..read_len].fill(0);
        hash.write_u64(offset);
        match mem
            .phys_view()
            .read_raw_into(Address::from(offset), &mut buf[..read_len])
            .data_part()
        {
            Ok(()) => {
                hash.write_u8(1);
                hash.write(&buf[..read_len]);
            }
            Err(_) => {
                hash.write_u8(0);
            }
        }
    }

    hash.finish()
}

fn compute_defs_fingerprint(profile: &LinuxProfile) -> u64 {
    let mut hash = Fnv64::new();
    hash.write(profile.source.as_os_str().as_encoded_bytes());
    hash.write(profile.banner.as_ref());
    hash.write_u64(profile.symbols.text.to_umem());
    hash.write_u64(profile.symbols.init_task.to_umem());
    hash.write_u64(profile.symbols.linux_banner.to_umem());
    hash.finish()
}

fn fingerprint_sample_offsets(total: u64) -> Vec<u64> {
    let page = size::kb(4) as u64;
    let mut offsets = vec![0];

    if total > page {
        offsets.push(page);
    }
    if total > page * 2 {
        offsets.push(
            (total / 8)
                .saturating_sub(page)
                .min(total.saturating_sub(page)),
        );
        offsets.push(
            (total / 4)
                .saturating_sub(page)
                .min(total.saturating_sub(page)),
        );
        offsets.push(
            (total / 2)
                .saturating_sub(page)
                .min(total.saturating_sub(page)),
        );
        offsets.push(
            ((total * 3) / 4)
                .saturating_sub(page)
                .min(total.saturating_sub(page)),
        );
        offsets.push(
            ((total * 7) / 8)
                .saturating_sub(page)
                .min(total.saturating_sub(page)),
        );
        offsets.push(total.saturating_sub(page));
    }

    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn default_cache_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| env::var_os("TEMP").map(PathBuf::from))
            .map(|dir| dir.join("memflow").join("linux"))
    }

    #[cfg(target_os = "macos")]
    {
        env::var_os("HOME")
            .map(PathBuf::from)
            .map(|dir| dir.join("Library").join("Caches"))
            .or_else(|| env::var_os("TMPDIR").map(PathBuf::from))
            .map(|dir| dir.join("memflow").join("linux"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .or_else(|| Some(env::temp_dir()))
            .map(|dir| dir.join("memflow").join("linux"))
    }
}

struct Fnv64(u64);

impl Fnv64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    fn new() -> Self {
        Self(Self::OFFSET_BASIS)
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    fn finish(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_entry_round_trip() {
        let entry = CacheEntry {
            version: CACHE_VERSION,
            memory_fingerprint: 0x1111_2222_3333_4444,
            defs_fingerprint: 0x5555_6666_7777_8888,
            kernel_hint: Address::from(0x1348_00000_u64),
            updated_unix_secs: 123456789,
        };

        let content = format_cache_entry(&entry);
        let parsed = parse_cache_entry(&content).expect("cache entry should parse");

        assert_eq!(parsed, entry);
    }

    #[test]
    fn cache_option_parser_handles_common_values() {
        assert!(matches!(
            parse_cache_option("off"),
            CacheOptionValue::Disabled
        ));
        assert!(matches!(
            parse_cache_option("default"),
            CacheOptionValue::Default
        ));
        match parse_cache_option("/tmp/memflow-linux-cache") {
            CacheOptionValue::Dir(path) => {
                assert_eq!(path, PathBuf::from("/tmp/memflow-linux-cache"));
            }
            _ => panic!("expected a directory override"),
        }
    }
}

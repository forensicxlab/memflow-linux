//! Runtime representation of the generated Linux defs TOML format.

use std::fs;
use std::path::Path;

use memflow::prelude::v1::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const LINUX_DEFS_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Serialized Linux defs document consumed by the runtime.
pub struct LinuxDefs {
    #[serde(default = "default_format_version")]
    pub format: u32,
    pub metadata: LinuxMetadata,
    pub symbols: LinuxDefsSymbols,
    pub enums: LinuxEnums,
    pub offsets: LinuxOffsets,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Metadata captured from the matching kernel image.
pub struct LinuxMetadata {
    pub banner: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Symbol RVAs persisted in the defs file.
pub struct LinuxDefsSymbols {
    #[serde(with = "hex_u64")]
    pub text: u64,
    #[serde(with = "hex_u64")]
    pub init_task: u64,
    #[serde(default, with = "hex_opt_u64")]
    pub init_top_pgt: Option<u64>,
    #[serde(default, with = "hex_opt_u64")]
    pub level4_kernel_pgt: Option<u64>,
    #[serde(with = "hex_u64")]
    pub linux_banner: u64,
    #[serde(default, with = "hex_opt_u64")]
    pub modules: Option<u64>,
    #[serde(default, with = "hex_opt_u64")]
    pub elf_format: Option<u64>,
    #[serde(default, with = "hex_opt_u64")]
    pub compat_elf_format: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Normalized enum values required by the runtime.
pub struct LinuxEnums {
    pub module_state: ModuleStateValues,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Values for Linux `enum module_state`.
pub struct ModuleStateValues {
    pub live: u64,
    pub coming: u64,
    pub going: u64,
    pub unformed: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Top-level collection of kernel structure offsets used by the runtime.
pub struct LinuxOffsets {
    pub task: TaskStructOffsets,
    pub mm: MmStructOffsets,
    pub vma: VmAreaStructOffsets,
    pub maple: MapleOffsets,
    pub list: ListHeadOffsets,
    pub module: ModuleOffsets,
    pub module_memory: ModuleMemoryOffsets,
    pub fs: FsStructOffsets,
    pub file: FileOffsets,
    pub path: PathOffsets,
    pub mount: MountOffsets,
    pub vfsmount: VfsMountOffsets,
    pub dentry: DentryOffsets,
    pub qstr: QstrOffsets,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct task_struct`.
pub struct TaskStructOffsets {
    pub tasks: usize,
    pub pid: usize,
    pub tgid: usize,
    pub comm: usize,
    pub comm_len: usize,
    pub state: usize,
    pub mm: usize,
    pub active_mm: usize,
    pub exit_state: usize,
    pub exit_code: usize,
    pub real_parent: usize,
    pub parent: usize,
    pub group_leader: usize,
    pub fs: usize,
    pub files: usize,
    pub signal: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct mm_struct`.
pub struct MmStructOffsets {
    pub mmap: Option<usize>,
    pub mm_mt: Option<usize>,
    pub pgd: usize,
    pub binfmt: Option<usize>,
    pub exe_file: usize,
    pub start_code: usize,
    pub end_code: usize,
    pub arg_start: usize,
    pub arg_end: usize,
    pub env_start: usize,
    pub env_end: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct vm_area_struct`.
pub struct VmAreaStructOffsets {
    pub vm_start: usize,
    pub vm_end: usize,
    pub vm_flags: usize,
    pub vm_file: usize,
    pub vm_next: Option<usize>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets needed to traverse maple-tree VMA storage on newer kernels.
pub struct MapleOffsets {
    pub tree: MapleTreeOffsets,
    pub range64: MapleRange64Offsets,
    pub arange64: MapleArange64Offsets,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct maple_tree`.
pub struct MapleTreeOffsets {
    pub ma_root: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct maple_range_64`.
pub struct MapleRange64Offsets {
    pub pivot: usize,
    pub pivot_count: usize,
    pub slot: usize,
    pub slot_count: usize,
    pub meta_end: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct maple_arange_64`.
pub struct MapleArange64Offsets {
    pub pivot: usize,
    pub pivot_count: usize,
    pub slot: usize,
    pub slot_count: usize,
    pub meta_end: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct list_head`.
pub struct ListHeadOffsets {
    pub next: usize,
    pub prev: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct module`.
pub struct ModuleOffsets {
    pub list: usize,
    pub name: usize,
    pub name_len: usize,
    pub state: usize,
    pub mem: usize,
    pub mem_count: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct module_memory`.
pub struct ModuleMemoryOffsets {
    pub base: usize,
    pub size: usize,
    pub struct_size: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct file`.
pub struct FileOffsets {
    pub f_path: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct fs_struct`.
pub struct FsStructOffsets {
    pub root: usize,
    pub pwd: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct path`.
pub struct PathOffsets {
    pub mnt: usize,
    pub dentry: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct mount`.
pub struct MountOffsets {
    pub mnt_parent: usize,
    pub mnt_mountpoint: usize,
    pub mnt: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct vfsmount`.
pub struct VfsMountOffsets {
    pub mnt_root: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct dentry`.
pub struct DentryOffsets {
    pub d_parent: usize,
    pub d_name: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Offsets extracted from `struct qstr`.
pub struct QstrOffsets {
    pub name: usize,
}

impl LinuxDefs {
    /// Loads a generated defs TOML file from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read(path).map_err(|err| {
            Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadFile)
                .log_info(err)
                .log_error(format!("failed to read Linux defs from {}", path.display()))
        })?;

        if data.starts_with(b"\x7fELF") {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported).log_error(
                format!(
                    "memflow-linux expects generated Linux defs TOML at runtime, not a vmlinux ELF: {}",
                    path.display()
                ),
            ));
        }

        let data = String::from_utf8(data).map_err(|err| {
            Error(ErrorOrigin::OsLayer, ErrorKind::Encoding)
                .log_info(err)
                .log_error(format!(
                    "Linux defs file is not valid UTF-8: {}",
                    path.display()
                ))
        })?;

        Self::from_toml_str(&data)
    }

    /// Parses a defs document from an in-memory TOML string.
    pub fn from_toml_str(data: &str) -> Result<Self> {
        let defs: Self = toml::from_str(data).map_err(|err| {
            Error(ErrorOrigin::OsLayer, ErrorKind::Encoding)
                .log_info(err)
                .log_error("failed to parse Linux defs TOML")
        })?;

        if defs.format != LINUX_DEFS_FORMAT_VERSION {
            return Err(
                Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported).log_error(format!(
                    "unsupported Linux defs format version {}, expected {}",
                    defs.format, LINUX_DEFS_FORMAT_VERSION
                )),
            );
        }

        Ok(defs)
    }

    /// Serializes the defs document into pretty TOML.
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|err| {
            Error(ErrorOrigin::OsLayer, ErrorKind::Encoding)
                .log_info(err)
                .log_error("failed to serialize Linux defs as TOML")
        })
    }
}

fn default_format_version() -> u32 {
    LINUX_DEFS_FORMAT_VERSION
}

mod hex_u64 {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{value:016x}"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_hex_u64(&value).map_err(serde::de::Error::custom)
    }
}

mod hex_opt_u64 {
    use super::*;

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&format!("0x{value:016x}")),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| parse_hex_u64(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}

fn parse_hex_u64(value: &str) -> std::result::Result<u64, String> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u64::from_str_radix(hex, 16).map_err(|err| format!("invalid hexadecimal u64 `{value}`: {err}"))
}

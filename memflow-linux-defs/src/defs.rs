//! Internal and public data model used by the offline defs generator.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use memflow::prelude::v1::*;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

use crate::vmlinux;

const LINUX_DEFS_FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Serialized Linux defs document emitted by the offline generator.
pub struct LinuxDefs {
    #[serde(default = "default_format_version")]
    pub format: u32,
    pub metadata: LinuxMetadata,
    pub symbols: LinuxSymbols,
    pub enums: LinuxEnums,
    pub offsets: LinuxOffsets,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Metadata captured from the matching kernel image.
pub struct LinuxMetadata {
    pub banner: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
/// Symbol RVAs persisted in the generated defs file.
pub struct LinuxSymbols {
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
    /// Loads a defs TOML file from disk.
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

    /// Generates a defs document directly from an unstripped `vmlinux`.
    pub fn from_vmlinux(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read(path).map_err(|err| {
            Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadFile)
                .log_info(err)
                .log_error(format!("failed to read vmlinux from {}", path.display()))
        })?;

        if !data.starts_with(b"\x7fELF") {
            return Err(
                Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported).log_error(format!(
                    "Linux defs generation requires an unstripped vmlinux ELF file, got {}",
                    path.display()
                )),
            );
        }

        let parsed = vmlinux::load_vmlinux(path, &data)?;
        Self::from_raw(parsed.raw, parsed.banner)
    }

    fn from_raw(raw: RawProfile, fallback_banner: Vec<u8>) -> Result<Self> {
        let text = raw.required_symbol_address("_text")?;
        let init_task = raw.required_symbol_address("init_task")?;
        let init_top_pgt = raw.symbol_address("init_top_pgt");
        let level4_kernel_pgt = raw.symbol_address("level4_kernel_pgt");
        let linux_banner = raw.required_symbol("linux_banner")?;
        let modules = raw.symbol_address("modules");
        let elf_format = raw.symbol_address("elf_format");
        let compat_elf_format = raw.symbol_address("compat_elf_format");
        let banner = linux_banner.constant_data.unwrap_or(fallback_banner);

        let task_comm = raw.resolve_field("task_struct", "comm")?;
        let task_state = raw
            .optional_resolve_field("task_struct", "__state")
            .or_else(|| raw.optional_resolve_field("task_struct", "state"))
            .ok_or_else(|| {
                Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(
                    "failed to resolve `__state`/`state` in `task_struct` from Linux defs source",
                )
            })?;
        let module_name = raw.resolve_field("module", "name")?;
        let module_mem = raw.optional_resolve_field("module", "mem");
        let module_memory = raw.optional_user_type("module_memory");
        let module_memory_base = raw.optional_resolve_field("module_memory", "base");
        let module_memory_size = raw.optional_resolve_field("module_memory", "size");
        let mm_mmap = raw.optional_field_offset("mm_struct", "mmap");
        let mm_mt = raw.optional_field_offset("mm_struct", "mm_mt");
        let maple = if mm_mt.is_some() {
            let maple_range_pivot = raw.resolve_field("maple_range_64", "pivot")?;
            let maple_range_slot = raw.resolve_field("maple_range_64", "slot")?;
            let maple_arange_pivot = raw.resolve_field("maple_arange_64", "pivot")?;
            let maple_arange_slot = raw.resolve_field("maple_arange_64", "slot")?;
            let maple_range_meta = raw.resolve_field("maple_range_64", "meta")?;
            let maple_arange_meta = raw.resolve_field("maple_arange_64", "meta")?;
            let maple_meta_end = raw.resolve_field("maple_metadata", "end")?;

            MapleOffsets {
                tree: MapleTreeOffsets {
                    ma_root: raw.resolve_field("maple_tree", "ma_root")?.offset,
                },
                range64: MapleRange64Offsets {
                    pivot: maple_range_pivot.offset,
                    pivot_count: maple_range_pivot.ty.array_len().ok_or_else(|| {
                        Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(
                            "maple_range_64.pivot is not an array in the Linux defs source",
                        )
                    })?,
                    slot: maple_range_slot.offset,
                    slot_count: maple_range_slot.ty.array_len().ok_or_else(|| {
                        Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(
                            "maple_range_64.slot is not an array in the Linux defs source",
                        )
                    })?,
                    meta_end: maple_range_meta.offset + maple_meta_end.offset,
                },
                arange64: MapleArange64Offsets {
                    pivot: maple_arange_pivot.offset,
                    pivot_count: maple_arange_pivot.ty.array_len().ok_or_else(|| {
                        Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(
                            "maple_arange_64.pivot is not an array in the Linux defs source",
                        )
                    })?,
                    slot: maple_arange_slot.offset,
                    slot_count: maple_arange_slot.ty.array_len().ok_or_else(|| {
                        Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(
                            "maple_arange_64.slot is not an array in the Linux defs source",
                        )
                    })?,
                    meta_end: maple_arange_meta.offset + maple_meta_end.offset,
                },
            }
        } else {
            zero_maple_offsets()
        };

        Ok(Self {
            format: LINUX_DEFS_FORMAT_VERSION,
            metadata: LinuxMetadata {
                banner: String::from_utf8_lossy(trim_trailing_nuls(&banner)).into_owned(),
            },
            symbols: LinuxSymbols {
                text,
                init_task,
                init_top_pgt,
                level4_kernel_pgt,
                linux_banner: linux_banner.address.0,
                modules,
                elf_format,
                compat_elf_format,
            },
            enums: LinuxEnums {
                module_state: ModuleStateValues {
                    live: raw.required_enum_constant("module_state", "MODULE_STATE_LIVE")? as u64,
                    coming: raw.required_enum_constant("module_state", "MODULE_STATE_COMING")?
                        as u64,
                    going: raw.required_enum_constant("module_state", "MODULE_STATE_GOING")? as u64,
                    unformed: raw.required_enum_constant("module_state", "MODULE_STATE_UNFORMED")?
                        as u64,
                },
            },
            offsets: LinuxOffsets {
                task: TaskStructOffsets {
                    tasks: raw.resolve_field("task_struct", "tasks")?.offset,
                    pid: raw.resolve_field("task_struct", "pid")?.offset,
                    tgid: raw.resolve_field("task_struct", "tgid")?.offset,
                    comm: task_comm.offset,
                    comm_len: task_comm.ty.array_len().ok_or_else(|| {
                        Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
                            .log_error("task_struct.comm is not an array in the Linux defs source")
                    })?,
                    state: task_state.offset,
                    mm: raw.resolve_field("task_struct", "mm")?.offset,
                    active_mm: raw.resolve_field("task_struct", "active_mm")?.offset,
                    exit_state: raw.resolve_field("task_struct", "exit_state")?.offset,
                    exit_code: raw.resolve_field("task_struct", "exit_code")?.offset,
                    real_parent: raw.resolve_field("task_struct", "real_parent")?.offset,
                    parent: raw.resolve_field("task_struct", "parent")?.offset,
                    group_leader: raw.resolve_field("task_struct", "group_leader")?.offset,
                    fs: raw.resolve_field("task_struct", "fs")?.offset,
                    files: raw.resolve_field("task_struct", "files")?.offset,
                    signal: raw.resolve_field("task_struct", "signal")?.offset,
                },
                mm: MmStructOffsets {
                    mmap: mm_mmap,
                    mm_mt,
                    pgd: raw.resolve_field("mm_struct", "pgd")?.offset,
                    binfmt: raw.optional_field_offset("mm_struct", "binfmt"),
                    exe_file: raw.resolve_field("mm_struct", "exe_file")?.offset,
                    start_code: raw.resolve_field("mm_struct", "start_code")?.offset,
                    end_code: raw.resolve_field("mm_struct", "end_code")?.offset,
                    arg_start: raw.resolve_field("mm_struct", "arg_start")?.offset,
                    arg_end: raw.resolve_field("mm_struct", "arg_end")?.offset,
                    env_start: raw.resolve_field("mm_struct", "env_start")?.offset,
                    env_end: raw.resolve_field("mm_struct", "env_end")?.offset,
                },
                vma: VmAreaStructOffsets {
                    vm_start: raw.resolve_field("vm_area_struct", "vm_start")?.offset,
                    vm_end: raw.resolve_field("vm_area_struct", "vm_end")?.offset,
                    vm_flags: raw.resolve_field("vm_area_struct", "vm_flags")?.offset,
                    vm_file: raw.resolve_field("vm_area_struct", "vm_file")?.offset,
                    vm_next: raw.optional_field_offset("vm_area_struct", "vm_next"),
                },
                maple,
                list: ListHeadOffsets {
                    next: raw.resolve_field("list_head", "next")?.offset,
                    prev: raw.resolve_field("list_head", "prev")?.offset,
                },
                module: ModuleOffsets {
                    list: raw.resolve_field("module", "list")?.offset,
                    name: module_name.offset,
                    name_len: module_name.ty.array_len().ok_or_else(|| {
                        Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
                            .log_error("module.name is not an array in the Linux defs source")
                    })?,
                    state: raw.resolve_field("module", "state")?.offset,
                    mem: module_mem.as_ref().map(|field| field.offset).unwrap_or(0),
                    mem_count: module_mem
                        .as_ref()
                        .and_then(|field| field.ty.array_len())
                        .unwrap_or(0),
                },
                module_memory: ModuleMemoryOffsets {
                    base: module_memory_base
                        .as_ref()
                        .map(|field| field.offset)
                        .unwrap_or(0),
                    size: module_memory_size
                        .as_ref()
                        .map(|field| field.offset)
                        .unwrap_or(0),
                    struct_size: module_memory.map(|ty| ty.size).unwrap_or(0),
                },
                fs: FsStructOffsets {
                    root: raw.resolve_field("fs_struct", "root")?.offset,
                    pwd: raw.resolve_field("fs_struct", "pwd")?.offset,
                },
                file: FileOffsets {
                    f_path: raw.resolve_field("file", "f_path")?.offset,
                },
                path: PathOffsets {
                    mnt: raw.resolve_field("path", "mnt")?.offset,
                    dentry: raw.resolve_field("path", "dentry")?.offset,
                },
                mount: MountOffsets {
                    mnt_parent: raw.resolve_field("mount", "mnt_parent")?.offset,
                    mnt_mountpoint: raw.resolve_field("mount", "mnt_mountpoint")?.offset,
                    mnt: raw.resolve_field("mount", "mnt")?.offset,
                },
                vfsmount: VfsMountOffsets {
                    mnt_root: raw.resolve_field("vfsmount", "mnt_root")?.offset,
                },
                dentry: DentryOffsets {
                    d_parent: raw.resolve_field("dentry", "d_parent")?.offset,
                    d_name: raw.resolve_field("dentry", "d_name")?.offset,
                },
                qstr: QstrOffsets {
                    name: raw.resolve_field("qstr", "name")?.offset,
                },
            },
        })
    }
}

fn default_format_version() -> u32 {
    LINUX_DEFS_FORMAT_VERSION
}

fn zero_maple_offsets() -> MapleOffsets {
    MapleOffsets {
        tree: MapleTreeOffsets { ma_root: 0 },
        range64: MapleRange64Offsets {
            pivot: 0,
            pivot_count: 0,
            slot: 0,
            slot_count: 0,
            meta_end: 0,
        },
        arange64: MapleArange64Offsets {
            pivot: 0,
            pivot_count: 0,
            slot: 0,
            slot_count: 0,
            meta_end: 0,
        },
    }
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

fn trim_trailing_nuls(data: &[u8]) -> &[u8] {
    let mut len = data.len();
    while len > 0 && data[len - 1] == 0 {
        len -= 1;
    }
    &data[..len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_supports_pre_maple_layouts_without_module_memory() {
        let base = RawTypeRef::Base {
            _name: "unsigned long".to_owned(),
        };
        let pointer_to = |name: &str| RawTypeRef::Pointer {
            subtype: Box::new(RawTypeRef::Struct {
                name: name.to_owned(),
            }),
        };

        let raw = RawProfile {
            symbols: HashMap::from([
                (
                    "_text".to_owned(),
                    Some(RawSymbol {
                        address: AddressValue::new(0xffff_ffff_8100_0000),
                        constant_data: None,
                    }),
                ),
                (
                    "init_task".to_owned(),
                    Some(RawSymbol {
                        address: AddressValue::new(0xffff_ffff_8200_0000),
                        constant_data: None,
                    }),
                ),
                (
                    "linux_banner".to_owned(),
                    Some(RawSymbol {
                        address: AddressValue::new(0xffff_ffff_8210_0000),
                        constant_data: Some(b"Linux version 5.10.0-test\0".to_vec()),
                    }),
                ),
                ("init_top_pgt".to_owned(), None),
                ("level4_kernel_pgt".to_owned(), None),
                ("modules".to_owned(), None),
                ("elf_format".to_owned(), None),
                ("compat_elf_format".to_owned(), None),
            ]),
            user_types: HashMap::from([
                (
                    "list_head".to_owned(),
                    RawUserType {
                        size: 16,
                        fields: HashMap::from([
                            (
                                "next".to_owned(),
                                RawField {
                                    offset: 0,
                                    anonymous: false,
                                    ty: pointer_to("list_head"),
                                },
                            ),
                            (
                                "prev".to_owned(),
                                RawField {
                                    offset: 8,
                                    anonymous: false,
                                    ty: pointer_to("list_head"),
                                },
                            ),
                        ]),
                    },
                ),
                (
                    "task_struct".to_owned(),
                    RawUserType {
                        size: 4096,
                        fields: HashMap::from([
                            (
                                "tasks".to_owned(),
                                field(
                                    0x10,
                                    RawTypeRef::Struct {
                                        name: "list_head".to_owned(),
                                    },
                                ),
                            ),
                            ("pid".to_owned(), field(0x20, base.clone())),
                            ("tgid".to_owned(), field(0x24, base.clone())),
                            (
                                "comm".to_owned(),
                                field(
                                    0x30,
                                    RawTypeRef::Array {
                                        count: 16,
                                        subtype: Box::new(RawTypeRef::Base {
                                            _name: "char".to_owned(),
                                        }),
                                    },
                                ),
                            ),
                            ("state".to_owned(), field(0x48, base.clone())),
                            ("mm".to_owned(), field(0x50, pointer_to("mm_struct"))),
                            ("active_mm".to_owned(), field(0x58, pointer_to("mm_struct"))),
                            ("exit_state".to_owned(), field(0x60, base.clone())),
                            ("exit_code".to_owned(), field(0x64, base.clone())),
                            (
                                "real_parent".to_owned(),
                                field(0x68, pointer_to("task_struct")),
                            ),
                            ("parent".to_owned(), field(0x70, pointer_to("task_struct"))),
                            (
                                "group_leader".to_owned(),
                                field(0x78, pointer_to("task_struct")),
                            ),
                            ("fs".to_owned(), field(0x80, pointer_to("fs_struct"))),
                            ("files".to_owned(), field(0x88, base.clone())),
                            ("signal".to_owned(), field(0x90, base.clone())),
                        ]),
                    },
                ),
                (
                    "mm_struct".to_owned(),
                    RawUserType {
                        size: 512,
                        fields: HashMap::from([
                            ("mmap".to_owned(), field(0x08, pointer_to("vm_area_struct"))),
                            ("pgd".to_owned(), field(0x10, base.clone())),
                            ("exe_file".to_owned(), field(0x18, pointer_to("file"))),
                            ("start_code".to_owned(), field(0x20, base.clone())),
                            ("end_code".to_owned(), field(0x28, base.clone())),
                            ("arg_start".to_owned(), field(0x30, base.clone())),
                            ("arg_end".to_owned(), field(0x38, base.clone())),
                            ("env_start".to_owned(), field(0x40, base.clone())),
                            ("env_end".to_owned(), field(0x48, base.clone())),
                        ]),
                    },
                ),
                (
                    "vm_area_struct".to_owned(),
                    RawUserType {
                        size: 128,
                        fields: HashMap::from([
                            ("vm_start".to_owned(), field(0x00, base.clone())),
                            ("vm_end".to_owned(), field(0x08, base.clone())),
                            ("vm_flags".to_owned(), field(0x10, base.clone())),
                            ("vm_file".to_owned(), field(0x18, pointer_to("file"))),
                            (
                                "vm_next".to_owned(),
                                field(0x20, pointer_to("vm_area_struct")),
                            ),
                        ]),
                    },
                ),
                (
                    "module".to_owned(),
                    RawUserType {
                        size: 512,
                        fields: HashMap::from([
                            (
                                "list".to_owned(),
                                field(
                                    0x00,
                                    RawTypeRef::Struct {
                                        name: "list_head".to_owned(),
                                    },
                                ),
                            ),
                            (
                                "name".to_owned(),
                                field(
                                    0x20,
                                    RawTypeRef::Array {
                                        count: 56,
                                        subtype: Box::new(RawTypeRef::Base {
                                            _name: "char".to_owned(),
                                        }),
                                    },
                                ),
                            ),
                            ("state".to_owned(), field(0x58, base.clone())),
                        ]),
                    },
                ),
                (
                    "fs_struct".to_owned(),
                    RawUserType {
                        size: 64,
                        fields: HashMap::from([
                            (
                                "root".to_owned(),
                                field(
                                    0x00,
                                    RawTypeRef::Struct {
                                        name: "path".to_owned(),
                                    },
                                ),
                            ),
                            (
                                "pwd".to_owned(),
                                field(
                                    0x10,
                                    RawTypeRef::Struct {
                                        name: "path".to_owned(),
                                    },
                                ),
                            ),
                        ]),
                    },
                ),
                (
                    "file".to_owned(),
                    RawUserType {
                        size: 64,
                        fields: HashMap::from([(
                            "f_path".to_owned(),
                            field(
                                0x08,
                                RawTypeRef::Struct {
                                    name: "path".to_owned(),
                                },
                            ),
                        )]),
                    },
                ),
                (
                    "path".to_owned(),
                    RawUserType {
                        size: 16,
                        fields: HashMap::from([
                            ("mnt".to_owned(), field(0x00, pointer_to("vfsmount"))),
                            ("dentry".to_owned(), field(0x08, pointer_to("dentry"))),
                        ]),
                    },
                ),
                (
                    "mount".to_owned(),
                    RawUserType {
                        size: 64,
                        fields: HashMap::from([
                            ("mnt_parent".to_owned(), field(0x00, pointer_to("mount"))),
                            (
                                "mnt_mountpoint".to_owned(),
                                field(0x08, pointer_to("dentry")),
                            ),
                            (
                                "mnt".to_owned(),
                                field(
                                    0x10,
                                    RawTypeRef::Struct {
                                        name: "vfsmount".to_owned(),
                                    },
                                ),
                            ),
                        ]),
                    },
                ),
                (
                    "vfsmount".to_owned(),
                    RawUserType {
                        size: 32,
                        fields: HashMap::from([(
                            "mnt_root".to_owned(),
                            field(0x00, pointer_to("dentry")),
                        )]),
                    },
                ),
                (
                    "dentry".to_owned(),
                    RawUserType {
                        size: 64,
                        fields: HashMap::from([
                            ("d_parent".to_owned(), field(0x00, pointer_to("dentry"))),
                            (
                                "d_name".to_owned(),
                                field(
                                    0x08,
                                    RawTypeRef::Struct {
                                        name: "qstr".to_owned(),
                                    },
                                ),
                            ),
                        ]),
                    },
                ),
                (
                    "qstr".to_owned(),
                    RawUserType {
                        size: 16,
                        fields: HashMap::from([(
                            "name".to_owned(),
                            field(
                                0x08,
                                RawTypeRef::Pointer {
                                    subtype: Box::new(RawTypeRef::Base {
                                        _name: "char".to_owned(),
                                    }),
                                },
                            ),
                        )]),
                    },
                ),
            ]),
            enums: HashMap::from([(
                "module_state".to_owned(),
                RawEnum {
                    constants: HashMap::from([
                        ("MODULE_STATE_LIVE".to_owned(), 0),
                        ("MODULE_STATE_COMING".to_owned(), 1),
                        ("MODULE_STATE_GOING".to_owned(), 2),
                        ("MODULE_STATE_UNFORMED".to_owned(), 3),
                    ]),
                },
            )]),
        };

        let defs = LinuxDefs::from_raw(raw, b"Linux version 5.10.0-test\0".to_vec())
            .expect("old-kernel raw profile should normalize");

        assert_eq!(defs.offsets.mm.mm_mt, None);
        assert_eq!(defs.offsets.mm.mmap, Some(0x08));
        assert_eq!(defs.offsets.task.state, 0x48);
        assert_eq!(defs.offsets.module.mem_count, 0);
        assert_eq!(defs.offsets.module_memory.struct_size, 0);
        assert_eq!(defs.offsets.maple.tree.ma_root, 0);
    }

    fn field(offset: usize, ty: RawTypeRef) -> RawField {
        RawField {
            offset,
            anonymous: false,
            ty,
        }
    }
}

pub(crate) struct RawProfile {
    pub(crate) symbols: HashMap<String, Option<RawSymbol>>,
    pub(crate) user_types: HashMap<String, RawUserType>,
    pub(crate) enums: HashMap<String, RawEnum>,
}

#[derive(Clone)]
pub(crate) struct RawSymbol {
    pub(crate) address: AddressValue,
    pub(crate) constant_data: Option<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct RawUserType {
    pub(crate) size: usize,
    pub(crate) fields: HashMap<String, RawField>,
}

#[derive(Clone)]
pub(crate) struct RawEnum {
    pub(crate) constants: HashMap<String, i64>,
}

#[derive(Clone)]
pub(crate) struct RawField {
    pub(crate) offset: usize,
    pub(crate) anonymous: bool,
    pub(crate) ty: RawTypeRef,
}

#[derive(Clone)]
pub(crate) enum RawTypeRef {
    Base {
        _name: String,
    },
    Struct {
        name: String,
    },
    Union {
        name: String,
    },
    Pointer {
        subtype: Box<RawTypeRef>,
    },
    Array {
        count: usize,
        subtype: Box<RawTypeRef>,
    },
    Enum {
        _name: String,
    },
    Bitfield {
        ty: Box<RawTypeRef>,
    },
    Function,
    Void,
    Unknown,
}

impl RawTypeRef {
    fn named_user_type(&self) -> Option<&str> {
        match self {
            Self::Struct { name } | Self::Union { name } => Some(name.as_str()),
            Self::Pointer { subtype } => subtype.named_user_type(),
            Self::Array { subtype, .. } => subtype.named_user_type(),
            Self::Bitfield { ty } => ty.named_user_type(),
            Self::Base { .. } | Self::Enum { .. } | Self::Function | Self::Void | Self::Unknown => {
                None
            }
        }
    }

    fn array_len(&self) -> Option<usize> {
        match self {
            Self::Array { count, .. } => Some(*count),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct ResolvedField {
    offset: usize,
    ty: RawTypeRef,
}

impl RawProfile {
    fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols
            .get(name)
            .and_then(|symbol| symbol.as_ref())
            .map(|symbol| symbol.address.0)
    }

    fn optional_field_offset(&self, type_name: &str, field_name: &str) -> Option<usize> {
        self.resolve_field_inner(type_name, field_name, 0, 0)
            .map(|field| field.offset)
    }

    fn required_symbol(&self, name: &str) -> Result<RawSymbol> {
        self.symbols
            .get(name)
            .and_then(|symbol| symbol.clone())
            .ok_or_else(|| {
                Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(format!(
                    "required symbol `{name}` missing from Linux defs source"
                ))
            })
    }

    fn required_symbol_address(&self, name: &str) -> Result<u64> {
        Ok(self.required_symbol(name)?.address.0)
    }

    fn required_enum_constant(&self, enum_name: &str, constant_name: &str) -> Result<i64> {
        self.enums
            .get(enum_name)
            .and_then(|raw_enum| raw_enum.constants.get(constant_name))
            .copied()
            .ok_or_else(|| {
                Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(format!(
                    "required enum constant `{constant_name}` missing from `{enum_name}`"
                ))
            })
    }

    fn optional_user_type(&self, name: &str) -> Option<&RawUserType> {
        self.user_types.get(name)
    }

    fn resolve_field(&self, type_name: &str, field_name: &str) -> Result<ResolvedField> {
        self.resolve_field_inner(type_name, field_name, 0, 0)
            .ok_or_else(|| {
                Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(format!(
                    "failed to resolve `{field_name}` in `{type_name}` from Linux defs source"
                ))
            })
    }

    fn optional_resolve_field(&self, type_name: &str, field_name: &str) -> Option<ResolvedField> {
        self.resolve_field_inner(type_name, field_name, 0, 0)
    }

    fn resolve_field_inner(
        &self,
        type_name: &str,
        field_name: &str,
        base_offset: usize,
        depth: usize,
    ) -> Option<ResolvedField> {
        if depth > 32 {
            return None;
        }

        let user_type = self.user_types.get(type_name)?;

        if let Some(field) = user_type.fields.get(field_name) {
            return Some(ResolvedField {
                offset: base_offset + field.offset,
                ty: field.ty.clone(),
            });
        }

        for field in user_type.fields.values().filter(|field| field.anonymous) {
            if let Some(nested_name) = field.ty.named_user_type() {
                if let Some(resolved) = self.resolve_field_inner(
                    nested_name,
                    field_name,
                    base_offset + field.offset,
                    depth + 1,
                ) {
                    return Some(resolved);
                }
            }
        }

        None
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AddressValue(pub(crate) u64);

impl AddressValue {
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }
}

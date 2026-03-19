//! Offline Linux definitions generator for `memflow-linux`.
//!
//! This crate parses a matching `vmlinux`, extracts the symbols and type
//! layouts required by the runtime plugin, and emits the normalized TOML
//! format consumed by `memflow-linux`.

mod defs;
mod vmlinux;

pub use defs::{
    DentryOffsets, FileOffsets, FsStructOffsets, LinuxDefs, LinuxEnums, LinuxMetadata,
    LinuxOffsets, LinuxSymbols, ListHeadOffsets, MapleArange64Offsets, MapleOffsets,
    MapleRange64Offsets, MapleTreeOffsets, MmStructOffsets, ModuleMemoryOffsets, ModuleOffsets,
    ModuleStateValues, MountOffsets, PathOffsets, QstrOffsets, TaskStructOffsets, VfsMountOffsets,
    VmAreaStructOffsets,
};

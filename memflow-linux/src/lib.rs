//! Linux OS support for the memflow memory introspection framework.
//!
//! The crate combines generated kernel definitions, kernel discovery, and
//! process/module traversal so memflow connectors can inspect Linux targets.

mod cache;
/// Runtime representation of generated Linux definitions.
pub mod defs;
/// Helpers for decoding and iterating the live kernel `kallsyms` tables.
pub mod kallsyms;
/// Linux kernel bootstrap, discovery, and `Os` implementation.
pub mod kernel;
#[cfg(feature = "plugins")]
/// Plugin entrypoints for loading `memflow-linux` through the memflow inventory.
pub mod plugins;
/// Linux process wrappers and per-process introspection helpers.
pub mod process;
/// Profile loading and rebasing helpers built on top of generated defs.
pub mod profile;
/// Pattern-signature helpers used by low-level kernel scanners.
pub mod sig;
mod util;

pub use defs::{
    DentryOffsets, FileOffsets, FsStructOffsets, LinuxDefs, LinuxDefsSymbols, LinuxEnums,
    LinuxMetadata, LinuxOffsets, ListHeadOffsets, MapleArange64Offsets, MapleOffsets,
    MapleRange64Offsets, MapleTreeOffsets, MmStructOffsets, ModuleMemoryOffsets, ModuleOffsets,
    ModuleStateValues, MountOffsets, PathOffsets, QstrOffsets, TaskStructOffsets, VfsMountOffsets,
    VmAreaStructOffsets,
};
pub use kernel::{linux_arch, LinuxKernel, LinuxKernelBuilder, LinuxKernelInfo};
pub use process::{LinuxProcess, LinuxProcessInfo};
pub use profile::{LinuxProfile, LinuxSymbols};

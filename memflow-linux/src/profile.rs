//! Profile loading and rebasing helpers for generated Linux definitions.

use std::path::{Path, PathBuf};

use crate::defs::LinuxDefs;
pub use crate::defs::{
    DentryOffsets, FileOffsets, FsStructOffsets, LinuxEnums, LinuxMetadata, LinuxOffsets,
    ListHeadOffsets, MapleArange64Offsets, MapleOffsets, MapleRange64Offsets, MapleTreeOffsets,
    MmStructOffsets, ModuleMemoryOffsets, ModuleOffsets, ModuleStateValues, MountOffsets,
    PathOffsets, QstrOffsets, TaskStructOffsets, VfsMountOffsets, VmAreaStructOffsets,
};
use memflow::prelude::v1::*;

#[derive(Clone, Debug)]
/// Loaded Linux definitions plus address-space specific rebasing helpers.
pub struct LinuxProfile {
    pub source: PathBuf,
    pub banner: Vec<u8>,
    pub symbols: LinuxSymbols,
    pub enums: LinuxEnums,
    pub offsets: LinuxOffsets,
}

#[derive(Clone, Copy, Debug)]
/// Runtime symbol addresses after TOML values have been converted to `Address`.
pub struct LinuxSymbols {
    pub text: Address,
    pub init_task: Address,
    pub init_top_pgt: Option<Address>,
    pub level4_kernel_pgt: Option<Address>,
    pub linux_banner: Address,
    pub modules: Option<Address>,
    pub elf_format: Option<Address>,
    pub compat_elf_format: Option<Address>,
}

impl LinuxProfile {
    /// Loads a generated Linux defs TOML file from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let defs = LinuxDefs::load(path)?;
        Ok(Self::from_defs(path, defs))
    }

    /// Computes the runtime KASLR slide from the observed `_text` address.
    pub fn compute_slide(&self, runtime_text: Address) -> Result<imem> {
        let runtime = runtime_text.to_umem() as i128;
        let profile = self.symbols.text.to_umem() as i128;
        let delta = runtime - profile;
        if delta < imem::MIN as i128 || delta > imem::MAX as i128 {
            Err(Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
                .log_error("computed Linux KASLR slide does not fit into imem"))
        } else {
            Ok(delta as imem)
        }
    }

    /// Rebases a profile-relative virtual address with the supplied slide.
    pub fn rebase(&self, address: Address, slide: imem) -> Address {
        let base = address.to_umem() as i128 + slide as i128;
        Address::from(base as u64)
    }

    fn from_defs(path: &Path, defs: LinuxDefs) -> Self {
        Self {
            source: path.to_path_buf(),
            banner: defs.metadata.banner.into_bytes(),
            symbols: LinuxSymbols {
                text: Address::from(defs.symbols.text),
                init_task: Address::from(defs.symbols.init_task),
                init_top_pgt: defs.symbols.init_top_pgt.map(Address::from),
                level4_kernel_pgt: defs.symbols.level4_kernel_pgt.map(Address::from),
                linux_banner: Address::from(defs.symbols.linux_banner),
                modules: defs.symbols.modules.map(Address::from),
                elf_format: defs.symbols.elf_format.map(Address::from),
                compat_elf_format: defs.symbols.compat_elf_format.map(Address::from),
            },
            enums: defs.enums,
            offsets: defs.offsets,
        }
    }
}

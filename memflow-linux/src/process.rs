//! Linux process wrappers and per-process introspection helpers.

use std::sync::Arc;

use log::{debug, info};
use memflow::architecture::x86::{x64 as arch_x64, X86VirtualTranslate};
use memflow::cglue::Fwd;
use memflow::mem::virt_translate::*;
use memflow::prelude::v1::*;

#[cfg(feature = "plugins")]
use memflow::cglue;

use crate::kernel::LinuxKernel;
use crate::profile::{LinuxProfile, MapleRange64Offsets};
use crate::util::{nul_split_strings, read_path, read_string_range, MAX_ENVIRONMENT_BYTES};

const MAPLE_NODE_MASK: u64 = 0xff;
const MAPLE_INTERNAL_NODE: u64 = 0x04;
const MAPLE_ROOT_NODE: u64 = 0x02;
const MAPLE_DENSE_SLOTS: usize = 31;
const MAX_MAPLE_DEPTH: usize = 64;
const MAX_VMA_ITER: usize = 1_048_576;
const MAX_MODULE_MERGE_GAP: u64 = size::mb(4) as u64;
const VM_READ: u64 = 0x1;
const VM_WRITE: u64 = 0x2;
const VM_EXEC: u64 = 0x4;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Converts Linux `vm_flags` into a memflow `PageType`.
fn linux_vma_page_type(flags: u64) -> PageType {
    let page_type = if flags & VM_WRITE != 0 {
        PageType::empty().write(true)
    } else if flags & VM_READ != 0 {
        PageType::empty().write(false)
    } else {
        PageType::UNKNOWN
    };

    page_type.noexec(flags & VM_EXEC == 0)
}

#[derive(Clone, Debug)]
/// Linux-specific process metadata derived from `task_struct` and `mm_struct`.
pub struct LinuxProcessInfo {
    pub base_info: ProcessInfo,
    pub task: Address,
    pub mm: Address,
    pub active_mm: Address,
    pub fs: Address,
    pub files: Address,
    pub signal: Address,
    pub exe_file: Address,
    pub start_code: Address,
    pub end_code: Address,
    pub arg_start: Address,
    pub arg_end: Address,
    pub env_start: Address,
    pub env_end: Address,
}

/// Raw VMA entry read from the kernel before it is converted to a module or memory range.
#[derive(Clone, Debug)]
struct LinuxVmaInfo {
    vma: Address,
    start: Address,
    end: Address,
    flags: u64,
    /// Pointer to the backing `struct file`, or null for anonymous VMAs.
    file: Address,
    path: ReprCString,
    name: ReprCString,
}

/// Fully resolved user-space ELF module entry.
#[derive(Clone, Debug)]
struct LinuxModuleEntry {
    address: Address,
    base: Address,
    size: umem,
    /// Backing `struct file` pointer used to match VMAs to the same module.
    file: Address,
    path: ReprCString,
    name: ReprCString,
}

/// Intermediate record used while aggregating adjacent VMAs into a single module.
///
/// Multiple VMAs backed by the same `struct file` (e.g. text, data, BSS) are
/// merged into one `LinuxModuleEntry` after all seeds are collected.
#[derive(Clone, Debug)]
struct LinuxModuleSeed {
    start: Address,
    end: Address,
    file: Address,
    path: ReprCString,
    name: ReprCString,
    /// Whether the page at `start` contains an ELF magic header (used to pick
    /// the canonical base address of the module).
    has_elf_header: bool,
}

/// Maple-tree node type encoded in the low bits of an entry pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MapleType {
    Dense = 0,
    Leaf64 = 1,
    Range64 = 2,
    Arange64 = 3,
}

#[cfg(feature = "plugins")]
cglue_impl_group!(LinuxProcess<T, V>, ProcessInstance, { VirtualTranslate });
#[cfg(feature = "plugins")]
cglue_impl_group!(LinuxProcess<T, V>, IntoProcessInstance, { VirtualTranslate });

#[derive(Clone)]
/// Linux process wrapper backed by a per-process translator and cached VMA state.
pub struct LinuxProcess<T, V> {
    pub virt_mem: VirtualDma<T, V, X86VirtualTranslate>,
    pub proc_info: LinuxProcessInfo,
    profile: Arc<LinuxProfile>,
    cached_vmas: Option<Vec<LinuxVmaInfo>>,
    cached_modules: Option<Vec<LinuxModuleEntry>>,
}

impl<T: PhysicalMemory, V: VirtualTranslate2> LinuxProcess<T, V> {
    /// Creates a process wrapper by taking ownership of a kernel instance.
    pub fn with_kernel(kernel: LinuxKernel<T, V>, proc_info: LinuxProcessInfo) -> Self {
        let mut virt_mem = kernel.virt_mem;
        virt_mem.set_proc_arch(proc_info.base_info.proc_arch.into());
        virt_mem.set_translator(arch_x64::new_translator(proc_info.base_info.dtb1));

        Self {
            virt_mem,
            proc_info,
            profile: kernel.profile,
            cached_vmas: None,
            cached_modules: None,
        }
    }

    /// Returns the owned physical memory and translation backends.
    pub fn into_inner(self) -> (T, V) {
        self.virt_mem.into_inner()
    }
}

impl<'a, T: PhysicalMemory, V: VirtualTranslate2> LinuxProcess<Fwd<&'a mut T>, Fwd<&'a mut V>> {
    /// Creates a process wrapper that borrows the kernel backing state.
    pub fn with_kernel_ref(kernel: &'a mut LinuxKernel<T, V>, proc_info: LinuxProcessInfo) -> Self {
        let profile = kernel.profile.clone();
        let (phys_mem, vat) = kernel.virt_mem.mem_vat_pair();
        let virt_mem = VirtualDma::with_vat(
            phys_mem.forward_mut(),
            proc_info.base_info.proc_arch,
            arch_x64::new_translator(proc_info.base_info.dtb1),
            vat.forward_mut(),
        );

        Self {
            virt_mem,
            proc_info,
            profile,
            cached_vmas: None,
            cached_modules: None,
        }
    }
}

impl<T: PhysicalMemory, V: VirtualTranslate2> MemoryView for LinuxProcess<T, V> {
    fn read_raw_iter(&mut self, data: ReadRawMemOps) -> Result<()> {
        self.virt_mem.read_raw_iter(data)
    }

    fn write_raw_iter(&mut self, data: WriteRawMemOps) -> Result<()> {
        self.virt_mem.write_raw_iter(data)
    }

    fn metadata(&self) -> MemoryViewMetadata {
        self.virt_mem.metadata()
    }
}

impl<T: PhysicalMemory, V: VirtualTranslate2> VirtualTranslate for LinuxProcess<T, V> {
    fn virt_to_phys_list(
        &mut self,
        addrs: &[VtopRange],
        out: VirtualTranslationCallback,
        out_fail: VirtualTranslationFailCallback,
    ) {
        self.virt_mem.virt_to_phys_list(addrs, out, out_fail)
    }
}

impl LinuxModuleEntry {
    fn to_module_info(&self, proc_info: &LinuxProcessInfo) -> ModuleInfo {
        ModuleInfo {
            address: self.address,
            parent_process: proc_info.base_info.address,
            base: self.base,
            size: self.size,
            name: self.name.clone(),
            path: self.path.clone(),
            arch: proc_info.base_info.proc_arch,
        }
    }
}

impl<T: PhysicalMemory, V: VirtualTranslate2> LinuxProcess<T, V> {
    /// Reads a process environment block either from the canonical range or from an explicit pointer.
    fn read_environment_data(&mut self, env_block: Address) -> Result<Vec<u8>> {
        if env_block.is_null() {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::EnvarNotFound));
        }

        if env_block == self.proc_info.env_start && !self.proc_info.env_end.is_null() {
            return read_string_range(
                &mut self.virt_mem,
                self.proc_info.env_start,
                self.proc_info.env_end,
                MAX_ENVIRONMENT_BYTES,
            );
        }

        let mut buf = vec![0_u8; MAX_ENVIRONMENT_BYTES];
        self.virt_mem
            .read_raw_into(env_block, &mut buf)
            .data_part()?;

        if let Some(end) = buf.windows(2).position(|window| window == [0, 0]) {
            buf.truncate(end + 1);
        } else if let Some(end) = buf.iter().position(|byte| *byte == 0) {
            buf.truncate(end);
        }

        Ok(buf)
    }

    /// Extracts the basename from a full module path (last `/` or `\` component).
    fn module_name(path: &str) -> ReprCString {
        path.rsplit(&['/', '\\'][..])
            .next()
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown")
            .into()
    }

    fn vm_flags_to_page_type(flags: u64) -> Option<PageType> {
        Some(linux_vma_page_type(flags))
    }

    /// Constructs a synthetic module entry from the raw `start_code`/`end_code` range
    /// when no ELF-backed module can be found (e.g. statically linked binaries).
    fn module_fallback(&self) -> Option<ModuleInfo> {
        if self.proc_info.start_code.is_null()
            || self.proc_info.end_code <= self.proc_info.start_code
        {
            return None;
        }

        let path = self.proc_info.base_info.path.clone();
        Some(ModuleInfo {
            address: self.proc_info.start_code.as_page_aligned(size::kb(4)),
            parent_process: self.proc_info.base_info.address,
            base: self.proc_info.start_code.as_page_aligned(size::kb(4)),
            size: self
                .proc_info
                .end_code
                .to_umem()
                .saturating_sub(self.proc_info.start_code.to_umem()),
            name: Self::module_name(path.as_ref()),
            path,
            arch: self.proc_info.base_info.proc_arch,
        })
    }

    /// Returns the primary (executable) module for this process.
    ///
    /// Tries to match by `exe_file` pointer first, then by `start_code` falling
    /// inside a module range, then takes the first module, and finally falls
    /// back to the synthetic `start_code`/`end_code` entry.
    fn primary_module_info(&mut self) -> Option<ModuleInfo> {
        let exe_file = self.proc_info.exe_file;
        let start_code = self.proc_info.start_code;

        if let Ok(modules) = self.module_cache().cloned() {
            if let Some(module) = modules
                .iter()
                .find(|module| !exe_file.is_null() && module.file == exe_file)
            {
                return Some(module.to_module_info(&self.proc_info));
            }

            if let Some(module) = modules.iter().find(|module| {
                let start = module.base.to_umem();
                let end = start.saturating_add(module.size);
                let code = start_code.to_umem();
                code >= start && code < end
            }) {
                return Some(module.to_module_info(&self.proc_info));
            }

            if let Some(module) = modules.first() {
                return Some(module.to_module_info(&self.proc_info));
            }
        }

        self.module_fallback()
    }

    /// Returns the `struct path` address for the process filesystem root, if available.
    fn root_path(&self) -> Option<Address> {
        self.proc_info
            .fs
            .non_null()
            .map(|fs| fs + self.profile.offsets.fs.root)
    }

    fn vma_cache(&mut self) -> Result<&Vec<LinuxVmaInfo>> {
        if self.cached_vmas.is_none() {
            self.cached_vmas = Some(self.collect_vmas()?);
        }

        Ok(self.cached_vmas.as_ref().expect("populated above"))
    }

    fn module_cache(&mut self) -> Result<&Vec<LinuxModuleEntry>> {
        if self.cached_modules.is_none() {
            self.cached_modules = Some(self.collect_modules()?);
        }

        Ok(self.cached_modules.as_ref().expect("populated above"))
    }

    fn collect_vmas(&mut self) -> Result<Vec<LinuxVmaInfo>> {
        let Some(mm) = self.proc_info.mm.non_null() else {
            debug!(
                "linux process {} has no mm_struct; skipping VMA enumeration",
                self.proc_info.base_info.pid
            );
            return Ok(Vec::new());
        };

        if let Some(mm_mt) = self.profile.offsets.mm.mm_mt {
            let tree = mm + mm_mt;
            match self.collect_vmas_maple(tree) {
                Ok(vmas) => {
                    if !vmas.is_empty() {
                        info!(
                            "linux process {}: collected {} VMA(s) via maple tree",
                            self.proc_info.base_info.pid,
                            vmas.len()
                        );
                        return Ok(vmas);
                    }
                }
                Err(err) => {
                    debug!(
                        "linux process {}: maple-tree VMA walk failed, falling back: {:?}",
                        self.proc_info.base_info.pid, err
                    );
                }
            }
        }

        if let (Some(mmap), Some(vm_next)) = (
            self.profile.offsets.mm.mmap,
            self.profile.offsets.vma.vm_next,
        ) {
            let vmas = self.collect_vmas_mmap(mm + mmap, vm_next)?;
            info!(
                "linux process {}: collected {} VMA(s) via mmap linked list",
                self.proc_info.base_info.pid,
                vmas.len()
            );
            return Ok(vmas);
        }

        debug!(
            "linux process {}: profile exposes neither maple tree nor mmap VMA walking",
            self.proc_info.base_info.pid
        );
        Ok(Vec::new())
    }

    fn collect_vmas_maple(&mut self, tree: Address) -> Result<Vec<LinuxVmaInfo>> {
        let root = self
            .virt_mem
            .read::<u64>(tree + self.profile.offsets.maple.tree.ma_root)?;
        let mut out = Vec::new();
        self.walk_maple_entry(root, 0, u64::MAX, 0, &mut out)?;
        out.sort_by_key(|vma| (vma.start.to_umem(), vma.end.to_umem(), vma.vma.to_umem()));
        out.dedup_by_key(|vma| vma.vma);
        Ok(out)
    }

    fn collect_vmas_mmap(
        &mut self,
        mmap_head: Address,
        vm_next_offset: usize,
    ) -> Result<Vec<LinuxVmaInfo>> {
        let mut out = Vec::new();
        let mut current = self.virt_mem.read_addr(mmap_head).unwrap_or(Address::NULL);

        for _ in 0..MAX_VMA_ITER {
            let Some(vma) = current.non_null() else {
                break;
            };

            if let Some(info) = self.read_vma_info(vma)? {
                out.push(info);
            }

            let next = self
                .virt_mem
                .read_addr(vma + vm_next_offset)
                .unwrap_or(Address::NULL);
            if next.is_null() || next == current {
                break;
            }

            current = next;
        }

        Ok(out)
    }

    /// Iterates file-backed VMAs to build the list of loaded ELF modules.
    ///
    /// Each file-backed VMA becomes a `LinuxModuleSeed`; seeds sharing the same
    /// `file` pointer are later merged by [`aggregate_module_seeds`].
    fn collect_modules(&mut self) -> Result<Vec<LinuxModuleEntry>> {
        let mut seeds = Vec::new();

        for vma in self
            .vma_cache()?
            .clone()
            .into_iter()
            .filter(|vma| !vma.file.is_null())
        {
            let size = vma.end.to_umem().saturating_sub(vma.start.to_umem());
            if size == 0 {
                continue;
            }

            seeds.push(LinuxModuleSeed {
                start: vma.start,
                end: vma.end,
                file: vma.file,
                path: vma.path.clone(),
                name: vma.name.clone(),
                has_elf_header: self.is_elf_image(vma.start),
            });
        }

        let modules = aggregate_module_seeds(seeds);

        for entry in &modules {
            debug!(
                "linux process {} module: {} base={} size={:#x}",
                self.proc_info.base_info.pid,
                entry.path.as_ref(),
                entry.base,
                entry.size
            );
        }

        info!(
            "linux process {}: collected {} ELF-backed module(s)",
            self.proc_info.base_info.pid,
            modules.len()
        );
        Ok(modules)
    }

    /// Returns `true` if the four bytes at `base` match the ELF magic header `\x7fELF`.
    fn is_elf_image(&mut self, base: Address) -> bool {
        let mut magic = [0_u8; 4];
        self.virt_mem
            .read_raw_into(base, &mut magic)
            .map(|_| magic == ELF_MAGIC)
            .unwrap_or(false)
    }

    /// Recursively walks one maple-tree entry and collects the VMAs it references.
    fn walk_maple_entry(
        &mut self,
        entry: u64,
        min: u64,
        max: u64,
        depth: usize,
        out: &mut Vec<LinuxVmaInfo>,
    ) -> Result<()> {
        if entry == 0 || depth > MAX_MAPLE_DEPTH || out.len() >= MAX_VMA_ITER {
            return Ok(());
        }

        if let Some(node_type) = Self::maple_type(entry) {
            let node = Address::from(entry & !MAPLE_NODE_MASK);
            match node_type {
                MapleType::Dense => self.walk_maple_dense(node, min, max, depth, out),
                MapleType::Leaf64 | MapleType::Range64 => {
                    self.walk_maple_range64(node, node_type, min, max, depth, out)
                }
                MapleType::Arange64 => self.walk_maple_arange64(node, min, max, depth, out),
            }
        } else {
            self.push_vma_entry(Address::from(entry), out)
        }
    }

    /// Walks a dense maple node whose pivots are implied by the parent range.
    fn walk_maple_dense(
        &mut self,
        node: Address,
        min: u64,
        max: u64,
        depth: usize,
        out: &mut Vec<LinuxVmaInfo>,
    ) -> Result<()> {
        let span = max.saturating_sub(min);
        let slots = std::cmp::min(MAPLE_DENSE_SLOTS, span.saturating_add(1) as usize);

        for index in 0..slots {
            let slot = self.read_maple_u64(node + index * size_of::<u64>())?;
            if slot == 0 {
                continue;
            }

            let slot_min = min.saturating_add(index as u64);
            self.walk_maple_entry(slot, slot_min, slot_min, depth + 1, out)?;
        }

        Ok(())
    }

    /// Walks a `maple_range_64` node.
    fn walk_maple_range64(
        &mut self,
        node: Address,
        node_type: MapleType,
        min: u64,
        max: u64,
        depth: usize,
        out: &mut Vec<LinuxVmaInfo>,
    ) -> Result<()> {
        let offsets = self.profile.offsets.maple.range64;
        let data_end = self.range64_data_end(node, max, offsets)?;
        let mut current_min = min;

        for index in 0..=data_end.min(offsets.slot_count.saturating_sub(1)) {
            let last = if index < offsets.pivot_count {
                self.read_maple_u64(node + offsets.pivot + index * size_of::<u64>())?
            } else {
                max
            };
            let slot = self.read_maple_u64(node + offsets.slot + index * size_of::<u64>())?;

            if slot != 0 {
                self.walk_maple_entry(slot, current_min, last, depth + 1, out)?;
            }

            if last >= max {
                break;
            }

            current_min = last.saturating_add(1);
        }

        if node_type == MapleType::Leaf64 {
            out.sort_by_key(|vma| (vma.start.to_umem(), vma.end.to_umem(), vma.vma.to_umem()));
        }

        Ok(())
    }

    /// Walks a `maple_arange_64` node.
    fn walk_maple_arange64(
        &mut self,
        node: Address,
        min: u64,
        max: u64,
        depth: usize,
        out: &mut Vec<LinuxVmaInfo>,
    ) -> Result<()> {
        let offsets = self.profile.offsets.maple.arange64;
        let data_end = self
            .virt_mem
            .read::<u8>(node + offsets.meta_end)
            .map(usize::from)
            .unwrap_or(0)
            .min(offsets.slot_count.saturating_sub(1));
        let mut current_min = min;

        for index in 0..=data_end {
            let last = if index < offsets.pivot_count {
                self.read_maple_u64(node + offsets.pivot + index * size_of::<u64>())?
            } else {
                max
            };
            let slot = self.read_maple_u64(node + offsets.slot + index * size_of::<u64>())?;

            if slot != 0 {
                self.walk_maple_entry(slot, current_min, last, depth + 1, out)?;
            }

            if last >= max {
                break;
            }

            current_min = last.saturating_add(1);
        }

        Ok(())
    }

    /// Determines the last valid slot index in a `maple_range_64` node.
    ///
    /// Uses `meta_end` from the node header when the last pivot is zero
    /// (meaning only part of the slot array is populated).
    fn range64_data_end(
        &mut self,
        node: Address,
        max: u64,
        offsets: MapleRange64Offsets,
    ) -> Result<usize> {
        let last_pivot = self.read_maple_u64(
            node + offsets.pivot + (offsets.pivot_count.saturating_sub(1)) * size_of::<u64>(),
        )?;

        let data_end = if last_pivot == 0 {
            self.virt_mem
                .read::<u8>(node + offsets.meta_end)
                .map(usize::from)
                .unwrap_or(0)
        } else if last_pivot == max {
            offsets.pivot_count.saturating_sub(1)
        } else {
            offsets.slot_count.saturating_sub(1)
        };

        Ok(data_end.min(offsets.slot_count.saturating_sub(1)))
    }

    /// Reads a VMA at the given address and appends it to `out`, skipping null or low entries.
    fn push_vma_entry(&mut self, vma: Address, out: &mut Vec<LinuxVmaInfo>) -> Result<()> {
        if vma.is_null() || vma.to_umem() < size::kb(4) as u64 {
            return Ok(());
        }

        if let Some(info) = self.read_vma_info(vma)? {
            out.push(info);
        }

        Ok(())
    }

    /// Reads one `vm_area_struct` and resolves the backing file path.
    /// Returns `None` for zero-sized or otherwise invalid VMAs.
    fn read_vma_info(&mut self, vma: Address) -> Result<Option<LinuxVmaInfo>> {
        let offsets = self.profile.offsets.vma;
        let start = Address::from(self.virt_mem.read::<u64>(vma + offsets.vm_start)?);
        let end = Address::from(self.virt_mem.read::<u64>(vma + offsets.vm_end)?);
        if start.is_null() || end <= start {
            return Ok(None);
        }

        let flags = self.virt_mem.read::<u64>(vma + offsets.vm_flags)?;
        let file = self
            .virt_mem
            .read_addr(vma + offsets.vm_file)
            .unwrap_or(Address::NULL);
        let root = self.root_path();
        let path = if file.is_null() {
            ReprCString::from("")
        } else {
            read_path(
                &mut self.virt_mem,
                file + self.profile.offsets.file.f_path,
                root,
                &self.profile.offsets,
            )
            .unwrap_or_default()
            .into()
        };
        let name = if path.as_ref().is_empty() {
            ReprCString::from("")
        } else {
            Self::module_name(path.as_ref())
        };

        Ok(Some(LinuxVmaInfo {
            vma,
            start,
            end,
            flags,
            file,
            path,
            name,
        }))
    }

    /// Reads a 64-bit value from the given virtual address (used for all maple tree fields).
    fn read_maple_u64(&mut self, addr: Address) -> Result<u64> {
        Ok(self.virt_mem.read::<u64>(addr)?)
    }

    /// Decodes the maple-tree node type encoded in an internal entry value.
    fn maple_type(entry: u64) -> Option<MapleType> {
        if entry & (MAPLE_INTERNAL_NODE | MAPLE_ROOT_NODE) == 0 {
            return None;
        }

        match ((entry >> 3) & 0x0f) as u8 {
            0 => Some(MapleType::Dense),
            1 => Some(MapleType::Leaf64),
            2 => Some(MapleType::Range64),
            3 => Some(MapleType::Arange64),
            _ => None,
        }
    }

    /// Converts a sorted VMA slice into memflow memory ranges, merging adjacent VMAs
    /// that share the same `PageType` and are within `gap_size` of each other.
    fn emit_vma_ranges(
        vmas: &[LinuxVmaInfo],
        gap_size: imem,
        start: Address,
        end: Address,
        mut out: MemoryRangeCallback,
    ) {
        let mut pending: Option<(Address, umem, PageType)> = None;

        for vma in vmas {
            let Some(page_type) = Self::vm_flags_to_page_type(vma.flags) else {
                continue;
            };
            if vma.end <= start || vma.start >= end {
                continue;
            }

            let range_start = if vma.start < start { start } else { vma.start };
            let range_end = if vma.end > end { end } else { vma.end };
            if range_end <= range_start {
                continue;
            }

            let range_size = range_end.to_umem().saturating_sub(range_start.to_umem());

            if let Some((pending_start, pending_size, pending_type)) = pending {
                let pending_end = pending_start.to_umem().saturating_add(pending_size);
                let can_merge = gap_size >= 0
                    && pending_type == page_type
                    && pending_end.saturating_add(gap_size as u64) >= range_start.to_umem();
                if can_merge {
                    pending = Some((
                        pending_start,
                        range_end.to_umem().saturating_sub(pending_start.to_umem()),
                        pending_type,
                    ));
                    continue;
                }

                if !out.call((pending_start, pending_size, pending_type).into()) {
                    return;
                }
            }

            pending = Some((range_start, range_size, page_type));
        }

        if let Some((pending_start, pending_size, pending_type)) = pending {
            let _ = out.call((pending_start, pending_size, pending_type).into());
        }
    }
}

impl<T: PhysicalMemory, V: VirtualTranslate2> Process for LinuxProcess<T, V> {
    fn state(&mut self) -> ProcessState {
        self.proc_info.base_info.state.clone()
    }

    fn set_dtb(&mut self, dtb1: Address, _dtb2: Address) -> Result<()> {
        self.proc_info.base_info.dtb1 = dtb1;
        self.proc_info.base_info.dtb2 = Address::invalid();
        self.virt_mem.set_translator(arch_x64::new_translator(dtb1));
        self.cached_vmas = None;
        self.cached_modules = None;
        Ok(())
    }

    fn module_address_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        mut callback: ModuleAddressCallback,
    ) -> Result<()> {
        if target_arch.is_some() && target_arch != Some(&self.proc_info.base_info.proc_arch) {
            return Ok(());
        }

        let arch = self.proc_info.base_info.proc_arch;
        let modules = self.module_cache()?.clone();
        for module in &modules {
            if !callback.call(ModuleAddressInfo {
                address: module.address,
                arch,
            }) {
                return Ok(());
            }
        }

        if modules.is_empty() {
            if let Some(module) = self.module_fallback() {
                let _ = callback.call(ModuleAddressInfo {
                    address: module.address,
                    arch: module.arch,
                });
            }
        }

        Ok(())
    }

    fn module_by_address(
        &mut self,
        address: Address,
        architecture: ArchitectureIdent,
    ) -> Result<ModuleInfo> {
        if architecture != self.proc_info.base_info.proc_arch {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound));
        }

        let modules = self.module_cache()?.clone();
        if let Some(module) = modules.iter().find(|module| module.address == address) {
            return Ok(module.to_module_info(&self.proc_info));
        }

        self.module_fallback()
            .filter(|module| module.address == address)
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
    }

    fn module_import_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ImportCallback,
    ) -> Result<()> {
        memflow::os::util::module_import_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_export_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: ExportCallback,
    ) -> Result<()> {
        memflow::os::util::module_export_list_callback(&mut self.virt_mem, info, callback)
    }

    fn module_section_list_callback(
        &mut self,
        info: &ModuleInfo,
        callback: SectionCallback,
    ) -> Result<()> {
        memflow::os::util::module_section_list_callback(&mut self.virt_mem, info, callback)
    }

    fn primary_module_address(&mut self) -> Result<Address> {
        self.primary_module_info()
            .map(|module| module.address)
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
    }

    fn info(&self) -> &ProcessInfo {
        &self.proc_info.base_info
    }

    fn mapped_mem_range(
        &mut self,
        gap_size: imem,
        start: Address,
        end: Address,
        out: MemoryRangeCallback,
    ) {
        match self.vma_cache().cloned() {
            Ok(vmas) if !vmas.is_empty() => Self::emit_vma_ranges(&vmas, gap_size, start, end, out),
            Ok(_) => {
                debug!(
                    "linux process {}: VMA walk returned no ranges, falling back to page-table walk",
                    self.proc_info.base_info.pid
                );
                self.virt_mem.virt_page_map_range(gap_size, start, end, out);
            }
            Err(err) => {
                debug!(
                    "linux process {}: VMA walk failed, falling back to page-table walk: {:?}",
                    self.proc_info.base_info.pid, err
                );
                self.virt_mem.virt_page_map_range(gap_size, start, end, out);
            }
        }
    }

    fn envar_list_callback(
        &mut self,
        target_arch: Option<&ArchitectureIdent>,
        callback: EnvVarCallback,
    ) -> Result<()> {
        if target_arch.is_some() && target_arch != Some(&self.proc_info.base_info.proc_arch) {
            return Ok(());
        }
        if self.proc_info.env_start.is_null() {
            return Ok(());
        }

        let env_block = self.environment_block_address(self.proc_info.base_info.proc_arch)?;
        self.envar_list_from_address(env_block, self.proc_info.base_info.proc_arch, callback)
    }

    fn environment_block_address(&mut self, architecture: ArchitectureIdent) -> Result<Address> {
        if architecture != self.proc_info.base_info.proc_arch || self.proc_info.env_start.is_null()
        {
            Err(Error(ErrorOrigin::OsLayer, ErrorKind::EnvarNotFound))
        } else {
            Ok(self.proc_info.env_start)
        }
    }

    fn envar_list_from_address(
        &mut self,
        env_block: Address,
        architecture: ArchitectureIdent,
        mut callback: EnvVarCallback,
    ) -> Result<()> {
        if architecture != self.proc_info.base_info.proc_arch {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::EnvarNotFound));
        }

        let data = self.read_environment_data(env_block)?;
        let mut offset = 0usize;

        for item in nul_split_strings(&data) {
            let item_len = item.len();
            if let Some((name, value)) = item.split_once('=') {
                let info = EnvVarInfo {
                    name: name.into(),
                    value: value.into(),
                    address: env_block + offset,
                    arch: architecture,
                };

                if !callback.call(info) {
                    break;
                }
            }

            offset = offset.saturating_add(item_len + 1);
        }

        Ok(())
    }
}

/// Merges adjacent or overlapping VMA seeds that share a `file` pointer into one module entry.
///
/// Seeds are sorted by `(file, start)`.  Two seeds merge if they share the same
/// file pointer and the new seed starts within `MAX_MODULE_MERGE_GAP` bytes after the
/// current module ends.  Only seeds with an ELF header create new entries; non-header
/// seeds are dropped unless they can be appended to an existing entry.
fn aggregate_module_seeds(mut seeds: Vec<LinuxModuleSeed>) -> Vec<LinuxModuleEntry> {
    seeds.sort_by_key(|seed| (seed.file.to_umem(), seed.start.to_umem(), seed.end.to_umem()));

    let mut modules = Vec::new();

    for seed in seeds {
        let size = seed.end.to_umem().saturating_sub(seed.start.to_umem());
        if size == 0 {
            continue;
        }

        let merge_idx = modules.iter().rposition(|module: &LinuxModuleEntry| {
            if module.file != seed.file {
                return false;
            }

            let module_end = module.base.to_umem().saturating_add(module.size);
            seed.start.to_umem() <= module_end.saturating_add(MAX_MODULE_MERGE_GAP)
        });

        if let Some(index) = merge_idx {
            let module = &mut modules[index];
            let module_start = module.base.to_umem().min(seed.start.to_umem());
            let module_end = module
                .base
                .to_umem()
                .saturating_add(module.size)
                .max(seed.end.to_umem());

            module.address = Address::from(module_start);
            module.base = Address::from(module_start);
            module.size = module_end.saturating_sub(module_start);

            if module.path.as_ref().is_empty() && !seed.path.as_ref().is_empty() {
                module.path = seed.path.clone();
            }
            if module.name.as_ref().is_empty() && !seed.name.as_ref().is_empty() {
                module.name = seed.name.clone();
            }

            if seed.has_elf_header {
                module.address = module.base;
            }

            continue;
        }

        if !seed.has_elf_header {
            continue;
        }

        modules.push(LinuxModuleEntry {
            address: seed.start,
            base: seed.start,
            size,
            file: seed.file,
            path: seed.path,
            name: seed.name,
        });
    }

    modules.sort_by_key(|module| module.base.to_umem());
    modules
}
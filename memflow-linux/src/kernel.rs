//! Linux kernel bootstrap, discovery, and `Os` implementation.
//!
//! This module owns the transition from raw physical memory to a validated
//! Linux kernel context backed by generated defs and page-table state.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use log::{debug, info, warn};
use memchr::memmem;
use memflow::architecture::x86::{x64 as arch_x64, X86VirtualTranslate};
use memflow::cglue::{ForwardMut, Fwd};
use memflow::mem::virt_translate::*;
use memflow::mem::{
    phys_mem::CachedPhysicalMemory, CachedVirtualTranslate, DirectTranslate, PhysicalMemory,
    VirtualTranslate2,
};
use memflow::os::root::Os;
use memflow::prelude::v1::*;
use memflow::types::DefaultCacheValidator;

use crate::cache::{KernelHintCache, KernelHintCacheOptions};
use crate::process::{LinuxProcess, LinuxProcessInfo};
use crate::profile::LinuxProfile;
use crate::util::{read_command_line, read_path};

pub mod x64;

const MAX_PROCESS_ITER: usize = 262_144;
const MAX_KERNEL_MODULE_ITER: usize = 16_384;
const KERNEL_SCAN_CHUNK_SIZE: usize = size::mb(64);
const BANNER_SCAN_PREFIX_LEN: usize = 96;
const SWAPPER_COMM: &[u8] = b"swapper/0\0";

fn default_generic_fallback() -> bool {
    match env::var("MEMFLOW_LINUX_GENERIC_FALLBACK") {
        Ok(value) => parse_boolish_flag(&value).unwrap_or(true),
        Err(_) => true,
    }
}

fn parse_boolish_flag(value: &str) -> Option<bool> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else if value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("on")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("enable")
        || value.eq_ignore_ascii_case("enabled")
    {
        Some(true)
    } else if value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("disable")
        || value.eq_ignore_ascii_case("disabled")
    {
        Some(false)
    } else {
        None
    }
}

/// Returns the architecture identifier used by the Linux runtime.
pub fn linux_arch() -> ArchitectureIdent {
    ArchitectureIdent::X86(64, false)
}

#[derive(Clone, Debug)]
/// High-level kernel information exposed after bootstrap completes.
pub struct LinuxKernelInfo {
    pub os_info: OsInfo,
    pub dtb: Address,
    pub phys_base: Address,
    pub phys_text: Address,
    pub virt_text: Address,
    pub la57_on: bool,
    pub slide: imem,
    pub version: String,
    pub banner: ReprCString,
}

#[derive(Clone, Debug)]
struct LinuxKernelModuleEntry {
    address: Address,
    base: Address,
    size: umem,
    name: ReprCString,
    path: ReprCString,
}

#[cfg(feature = "plugins")]
use memflow::cglue;
#[cfg(feature = "plugins")]
use memflow::mem::{memory_view::*, phys_mem::*};
#[cfg(feature = "plugins")]
cglue_impl_group!(LinuxKernel<T, V>, OsInstance<'a>, { PhysicalMemory, MemoryView, VirtualTranslate });

#[derive(Clone)]
/// Active Linux kernel wrapper backed by a physical connector and translator.
pub struct LinuxKernel<T, V> {
    pub virt_mem: VirtualDma<T, V, X86VirtualTranslate>,
    pub info: LinuxKernelInfo,
    pub profile: Arc<LinuxProfile>,
    scanner: x64::KernelInfo,
    init_task: Address,
    cached_modules: Option<Vec<LinuxKernelModuleEntry>>,
}

impl<T> LinuxKernelBuilder<T, T, DirectTranslate>
where
    T: PhysicalMemory,
{
    /// Creates a builder from a physical memory connector.
    pub fn new(connector: T) -> Self {
        Self {
            connector,
            profile_path: None,
            image_path_hint: None,
            kernel_hint: None,
            kernel_hint_cache: KernelHintCacheOptions::default(),
            skip_banner_check: false,
            generic_fallback: default_generic_fallback(),
            build_page_cache: Box::new(|connector, _| connector),
            build_vat_cache: Box::new(|vat, _| vat),
        }
    }
}

/// Builder for constructing a validated Linux kernel instance.
pub struct LinuxKernelBuilder<T, TK, VK> {
    connector: T,
    profile_path: Option<PathBuf>,
    image_path_hint: Option<PathBuf>,
    kernel_hint: Option<Address>,
    kernel_hint_cache: KernelHintCacheOptions,
    skip_banner_check: bool,
    generic_fallback: bool,
    build_page_cache: Box<dyn FnOnce(T, ArchitectureIdent) -> TK>,
    build_vat_cache: Box<dyn FnOnce(DirectTranslate, ArchitectureIdent) -> VK>,
}

impl<T, TK, VK> LinuxKernelBuilder<T, TK, VK>
where
    T: PhysicalMemory + Clone,
    TK: 'static + PhysicalMemory + Clone,
    VK: 'static + VirtualTranslate2 + Clone,
{
    /// Discovers the Linux kernel, validates the selected defs, and builds the runtime object.
    pub fn build(mut self) -> Result<LinuxKernel<TK, VK>> {
        let mut selected = None;
        let mut last_err = None;
        let kernel_hint_cache =
            match KernelHintCache::prepare(self.connector.clone(), &self.kernel_hint_cache) {
                Ok(cache) => cache,
                Err(err) => {
                    warn!("linux bootstrap: failed to initialize kernel hint cache: {err:?}");
                    None
                }
            };
        let cached_kernel_hint =
            kernel_hint_cache
                .as_ref()
                .and_then(|cache| match cache.load_kernel_hint() {
                    Ok(hint) => hint,
                    Err(err) => {
                        warn!("linux bootstrap: failed to read kernel hint cache: {err:?}");
                        None
                    }
                });
        let profile_paths = resolve_profile_candidates(
            self.profile_path.as_deref(),
            self.image_path_hint.as_deref(),
        )?;
        info!(
            "linux bootstrap: trying {} defs candidate(s){}{}{}",
            profile_paths.len(),
            self.kernel_hint
                .map(|hint| format!(", kernel hint {hint}"))
                .unwrap_or_default(),
            if self.skip_banner_check {
                ", banner validation skipped"
            } else {
                ""
            },
            if self.generic_fallback {
                ""
            } else {
                ", generic fallback disabled"
            },
        );
        if let Some(cache) = kernel_hint_cache.as_ref() {
            debug!(
                "linux bootstrap: kernel hint cache file {}",
                cache.path().display()
            );
        }

        for profile_path in profile_paths {
            info!("linux bootstrap: trying defs {}", profile_path.display());
            let profile = match LinuxProfile::load(&profile_path) {
                Ok(profile) => Arc::new(profile),
                Err(err) => {
                    debug!(
                        "linux bootstrap: failed to load defs {}: {:?}",
                        profile_path.display(),
                        err
                    );
                    last_err = Some(err);
                    continue;
                }
            };

            let scanner = match discover_kernel(
                self.connector.clone(),
                &profile,
                self.kernel_hint
                    .map(|hint| hint.as_page_aligned(size::mb(2))),
                cached_kernel_hint.map(|hint| hint.as_page_aligned(size::mb(2))),
                self.generic_fallback,
            ) {
                Ok(scanner) => scanner,
                Err(err) => {
                    debug!(
                        "linux bootstrap: defs {} did not match the image: {:?}",
                        profile.source.display(),
                        err
                    );
                    last_err = Some(err);
                    continue;
                }
            };

            if scanner.la57_on {
                warn!(
                    "linux bootstrap: defs {} matched a 5-level paging kernel, which is unsupported",
                    profile.source.display()
                );
                last_err = Some(
                    Error(ErrorOrigin::OsLayer, ErrorKind::NotSupported)
                        .log_error("5-level paging is not supported by this Linux plugin yet"),
                );
                continue;
            }

            let slide = match profile.compute_slide(scanner.virt_text) {
                Ok(slide) => slide,
                Err(err) => {
                    last_err = Some(err);
                    continue;
                }
            };

            if !self.skip_banner_check {
                if let Err(err) =
                    validate_profile_banner(&profile, slide, &scanner, self.connector.forward_mut())
                {
                    debug!(
                        "linux bootstrap: banner validation failed for {}: {:?}",
                        profile.source.display(),
                        err
                    );
                    last_err = Some(err);
                    continue;
                }
            }

            selected = Some((profile, scanner, slide));
            break;
        }

        let (profile, scanner, slide) = selected.ok_or_else(|| {
            last_err.unwrap_or_else(|| {
                Error(ErrorOrigin::OsLayer, ErrorKind::Configuration).log_error(
                    "Linux defs path is required or a matching Linux defs file must be discoverable",
                )
            })
        })?;

        let arch = linux_arch();
        let vat = DirectTranslate::new();
        let connector = (self.build_page_cache)(self.connector, arch);
        let vat = (self.build_vat_cache)(vat, arch);

        info!(
            "linux bootstrap: selected defs {} base={} dtb={} slide={:#x} version={}",
            profile.source.display(),
            scanner.virt_text,
            scanner.cr3,
            slide,
            scanner.version
        );

        if let Some(cache) = kernel_hint_cache.as_ref() {
            if let Err(err) = cache.store(&profile, scanner.phys_text) {
                warn!("linux bootstrap: failed to update kernel hint cache: {err:?}");
            }
        }

        Ok(LinuxKernel::new(connector, vat, profile, scanner, slide))
    }

    /// Sets the explicit defs file to load.
    pub fn profile(mut self, path: impl AsRef<Path>) -> Self {
        self.profile_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Sets a best-effort hint about the source image path for defs discovery.
    pub fn image_hint(mut self, path: impl AsRef<Path>) -> Self {
        self.image_path_hint = Some(path.as_ref().to_path_buf());
        self
    }

    /// Supplies a known physical kernel text hint to skip slow discovery.
    pub fn kernel_hint(mut self, kernel_hint: Address) -> Self {
        self.kernel_hint = Some(kernel_hint);
        self
    }

    /// Disables the persistent kernel-hint cache.
    pub fn disable_kernel_hint_cache(mut self) -> Self {
        self.kernel_hint_cache = KernelHintCacheOptions::disabled();
        self
    }

    /// Overrides the directory used for the persistent kernel-hint cache.
    pub fn kernel_hint_cache_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.kernel_hint_cache = KernelHintCacheOptions::with_dir(path);
        self
    }

    /// Skips banner validation once a candidate kernel has been found.
    pub fn skip_banner_check(mut self) -> Self {
        self.skip_banner_check = true;
        self
    }

    /// Disables the final generic x64 fallback scan.
    pub fn disable_generic_fallback(mut self) -> Self {
        self.generic_fallback = false;
        self
    }

    /// Enables the final generic x64 fallback scan.
    pub fn enable_generic_fallback(mut self) -> Self {
        self.generic_fallback = true;
        self
    }

    /// Replaces the physical page-cache construction step.
    pub fn build_page_cache<TK2: 'static + PhysicalMemory + Clone>(
        self,
        build_page_cache: impl FnOnce(T, ArchitectureIdent) -> TK2 + 'static,
    ) -> LinuxKernelBuilder<T, TK2, VK> {
        LinuxKernelBuilder {
            connector: self.connector,
            profile_path: self.profile_path,
            image_path_hint: self.image_path_hint,
            kernel_hint: self.kernel_hint,
            kernel_hint_cache: self.kernel_hint_cache,
            skip_banner_check: self.skip_banner_check,
            generic_fallback: self.generic_fallback,
            build_page_cache: Box::new(build_page_cache),
            build_vat_cache: self.build_vat_cache,
        }
    }

    /// Replaces the virtual-translation cache construction step.
    pub fn build_vat_cache<VK2: 'static + VirtualTranslate2 + Clone>(
        self,
        build_vat_cache: impl FnOnce(DirectTranslate, ArchitectureIdent) -> VK2 + 'static,
    ) -> LinuxKernelBuilder<T, TK, VK2> {
        LinuxKernelBuilder {
            connector: self.connector,
            profile_path: self.profile_path,
            image_path_hint: self.image_path_hint,
            kernel_hint: self.kernel_hint,
            kernel_hint_cache: self.kernel_hint_cache,
            skip_banner_check: self.skip_banner_check,
            generic_fallback: self.generic_fallback,
            build_page_cache: self.build_page_cache,
            build_vat_cache: Box::new(build_vat_cache),
        }
    }

    /// Installs the default memflow page and translation caches.
    pub fn build_default_caches(
        self,
    ) -> LinuxKernelBuilder<
        T,
        CachedPhysicalMemory<'static, T, DefaultCacheValidator>,
        CachedVirtualTranslate<DirectTranslate, DefaultCacheValidator>,
    > {
        LinuxKernelBuilder {
            connector: self.connector,
            profile_path: self.profile_path,
            image_path_hint: self.image_path_hint,
            kernel_hint: self.kernel_hint,
            kernel_hint_cache: self.kernel_hint_cache,
            skip_banner_check: self.skip_banner_check,
            generic_fallback: self.generic_fallback,
            build_page_cache: Box::new(|connector, arch| {
                CachedPhysicalMemory::builder(connector)
                    .arch(arch)
                    .build()
                    .unwrap()
            }),
            build_vat_cache: Box::new(|vat, arch| {
                CachedVirtualTranslate::builder(vat)
                    .arch(arch)
                    .build()
                    .unwrap()
            }),
        }
    }
}

impl<T: PhysicalMemory + Clone> LinuxKernel<T, DirectTranslate> {
    /// Returns a builder for the supplied physical memory connector.
    pub fn builder(connector: T) -> LinuxKernelBuilder<T, T, DirectTranslate> {
        LinuxKernelBuilder::new(connector)
    }
}

fn resolve_profile_candidates(
    explicit_profile: Option<&Path>,
    image_path_hint: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    if let Some(profile) = explicit_profile {
        debug!(
            "linux bootstrap: using explicit defs candidate {}",
            profile.display()
        );
        return Ok(vec![profile.to_path_buf()]);
    }

    let mut candidates = Vec::new();

    if let Ok(profile) = std::env::var("MEMFLOW_LINUX_PROFILE") {
        let profile = PathBuf::from(profile);
        if profile.is_file() {
            debug!(
                "linux bootstrap: using MEMFLOW_LINUX_PROFILE candidate {}",
                profile.display()
            );
            candidates.push(profile);
        }
    }

    if let Some(image_path) = image_path_hint {
        debug!(
            "linux bootstrap: using image hint {} to discover adjacent defs",
            image_path.display()
        );
        if looks_like_profile_path(image_path) && image_path.is_file() {
            candidates.push(image_path.to_path_buf());
        }

        if let Some(parent) = image_path.parent() {
            candidates.extend(read_profile_candidates(parent)?);
        }
    }

    dedup_paths(&mut candidates);

    if candidates.is_empty() {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::Configuration).log_error(
            "Linux defs path is required or `MEMFLOW_LINUX_PROFILE`/an adjacent Linux defs file must exist",
        ))
    } else {
        Ok(candidates)
    }
}

fn read_profile_candidates(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(dir).map_err(|err| {
        Error(ErrorOrigin::OsLayer, ErrorKind::UnableToReadDir)
            .log_info(err)
            .log_error(format!(
                "failed to enumerate Linux defs in {}",
                dir.display()
            ))
    })?;

    let mut paths = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file() && looks_like_profile_path(path) && !is_hidden_profile(path))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn looks_like_profile_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    name == "vmlinux.toml"
        || name == "linux.toml"
        || (name.starts_with("vmlinux-") && name.ends_with(".toml"))
        || (name.starts_with("linux-defs") && name.ends_with(".toml"))
}

fn is_hidden_profile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    paths.sort();
    paths.dedup();
}

impl<T: PhysicalMemory, V: VirtualTranslate2> LinuxKernel<T, V> {
    /// Creates a kernel wrapper from already discovered scanner and profile state.
    pub fn new(
        phys_mem: T,
        vat: V,
        profile: Arc<LinuxProfile>,
        scanner: x64::KernelInfo,
        slide: imem,
    ) -> Self {
        let banner = trim_trailing_nuls(&profile.banner);
        let mut virt_mem = VirtualDma::with_vat(
            phys_mem,
            linux_arch(),
            arch_x64::new_translator(scanner.cr3),
            vat,
        );
        let kernel_size = scanner
            .kallsyms
            .as_ref()
            .map(|kallsyms| approximate_kernel_size(scanner.virt_text, kallsyms, &mut virt_mem))
            .unwrap_or(0);
        let info = LinuxKernelInfo {
            os_info: OsInfo {
                base: scanner.virt_text,
                size: kernel_size,
                arch: linux_arch(),
            },
            dtb: scanner.cr3,
            phys_base: scanner.phys_base,
            phys_text: scanner.phys_text,
            virt_text: scanner.virt_text,
            la57_on: scanner.la57_on,
            slide,
            version: scanner.version.to_string(),
            banner: String::from_utf8_lossy(banner).into_owned().into(),
        };
        let init_task = profile.rebase(profile.symbols.init_task, slide);

        let size_display = if kernel_size == 0 {
            "deferred".to_string()
        } else {
            format!("{kernel_size:#x}")
        };

        info!(
            "linux kernel ready: base={} size={} dtb={} phys_base={} init_task={}",
            scanner.virt_text, size_display, scanner.cr3, scanner.phys_base, init_task
        );

        Self {
            virt_mem,
            info,
            profile,
            scanner,
            init_task,
            cached_modules: None,
        }
    }

    /// Returns the owned physical memory and translation backends.
    pub fn into_inner(self) -> (T, V) {
        self.virt_mem.into_inner()
    }

    fn process_reader<'a>(
        &'a mut self,
        dtb: Address,
    ) -> VirtualDma<Fwd<&'a mut T>, Fwd<&'a mut V>, X86VirtualTranslate> {
        let (phys_mem, vat) = self.virt_mem.mem_vat_pair();
        VirtualDma::with_vat(
            phys_mem.forward_mut(),
            linux_arch(),
            arch_x64::new_translator(dtb),
            vat.forward_mut(),
        )
    }

    fn kernel_module_info(&self) -> ModuleInfo {
        ModuleInfo {
            address: self.info.os_info.base,
            parent_process: Address::INVALID,
            base: self.info.os_info.base,
            size: self.info.os_info.size,
            name: "vmlinux".into(),
            path: self.profile.source.display().to_string().into(),
            arch: self.info.os_info.arch,
        }
    }

    fn ensure_kallsyms(&mut self) -> Result<&crate::kallsyms::KallsymsInfo> {
        if self.scanner.kallsyms.is_none() {
            info!(
                "linux bootstrap: loading kallsyms lazily for kernel {}",
                self.info.os_info.base
            );
            let kallsyms =
                x64::find_kallsyms(self.virt_mem.phys_mem(), self.info.dtb, self.info.virt_text)?;
            self.scanner.kallsyms = Some(kallsyms);
        }

        Ok(self
            .scanner
            .kallsyms
            .as_ref()
            .expect("kallsyms must be loaded"))
    }

    fn ensure_kernel_size(&mut self) -> Result<()> {
        if self.info.os_info.size == 0 {
            let kallsyms = self.ensure_kallsyms()?.clone();
            self.info.os_info.size =
                approximate_kernel_size(self.info.os_info.base, &kallsyms, &mut self.virt_mem);
        }

        Ok(())
    }

    fn process_state(&mut self, task: Address) -> ProcessState {
        let task_offsets = self.profile.offsets.task;
        let _state = self
            .virt_mem
            .read::<u32>(task + task_offsets.state)
            .unwrap_or_default();
        let exit_state = self
            .virt_mem
            .read::<i32>(task + task_offsets.exit_state)
            .unwrap_or_default();
        let exit_code = self
            .virt_mem
            .read::<i32>(task + task_offsets.exit_code)
            .unwrap_or_default();

        if exit_state != 0 {
            ProcessState::Dead(exit_code)
        } else {
            ProcessState::Alive
        }
    }

    fn process_arch(&self, binfmt: Address) -> ArchitectureIdent {
        let compat_elf = self
            .profile
            .symbols
            .compat_elf_format
            .map(|address| self.profile.rebase(address, self.info.slide));
        process_arch_from_binfmt(binfmt, compat_elf)
    }

    fn kernel_module_cache(&mut self) -> Result<&Vec<LinuxKernelModuleEntry>> {
        if self.cached_modules.is_none() {
            self.cached_modules = Some(self.collect_kernel_modules()?);
        }

        Ok(self.cached_modules.as_ref().unwrap())
    }

    fn collect_kernel_modules(&mut self) -> Result<Vec<LinuxKernelModuleEntry>> {
        let Some(modules_head) = self.profile.symbols.modules else {
            info!("linux kernel modules: profile does not expose the global modules list");
            return Ok(Vec::new());
        };

        let modules_head = self.profile.rebase(modules_head, self.info.slide);
        let list_offsets = self.profile.offsets.list;
        let module_offsets = self.profile.offsets.module;
        let mem_offsets = self.profile.offsets.module_memory;
        let state_values = self.profile.enums.module_state;

        let mut out = Vec::new();
        let mut entry = self
            .virt_mem
            .read_addr(modules_head + list_offsets.next)
            .unwrap_or(Address::NULL);

        for _ in 0..MAX_KERNEL_MODULE_ITER {
            let Some(list_entry) = entry.non_null() else {
                break;
            };
            if list_entry == modules_head {
                break;
            }

            let module = list_entry - module_offsets.list;
            let next = self
                .virt_mem
                .read_addr(list_entry + list_offsets.next)
                .unwrap_or(Address::NULL);

            let state = self
                .virt_mem
                .read::<u32>(module + module_offsets.state)
                .unwrap_or(state_values.unformed as u32) as u64;
            if state == state_values.unformed {
                entry = next;
                continue;
            }

            let name = self
                .virt_mem
                .read_utf8_lossy(module + module_offsets.name, module_offsets.name_len)
                .data_part()
                .unwrap_or_default();

            let mut min_base = Address::NULL;
            let mut max_end = 0_u64;
            for idx in 0..module_offsets.mem_count {
                let mem_entry = module + module_offsets.mem + idx * mem_offsets.struct_size;
                let base = self
                    .virt_mem
                    .read_addr(mem_entry + mem_offsets.base)
                    .unwrap_or(Address::NULL);
                let size = self
                    .virt_mem
                    .read::<u32>(mem_entry + mem_offsets.size)
                    .map(u64::from)
                    .unwrap_or_default();
                if base.is_null() || size == 0 {
                    continue;
                }

                if min_base.is_null() || base.to_umem() < min_base.to_umem() {
                    min_base = base;
                }

                let end = base.to_umem().saturating_add(size);
                if end > max_end {
                    max_end = end;
                }
            }

            if !min_base.is_null() && max_end > min_base.to_umem() {
                let name = name.trim_end_matches('\0');
                let path = if name.is_empty() {
                    ReprCString::from("/sys/module/unknown")
                } else {
                    format!("/sys/module/{name}").into()
                };

                let entry = LinuxKernelModuleEntry {
                    address: module,
                    base: min_base,
                    size: max_end.saturating_sub(min_base.to_umem()),
                    name: if name.is_empty() {
                        ReprCString::from("unknown")
                    } else {
                        name.into()
                    },
                    path,
                };
                debug!(
                    "linux kernel module: {} base={} size={:#x}",
                    entry.name.as_ref(),
                    entry.base,
                    entry.size
                );
                out.push(entry);
            }

            if next.is_null() || next == list_entry {
                break;
            }
            entry = next;
        }

        info!(
            "linux kernel modules: discovered {} loaded module(s)",
            out.len()
        );
        Ok(out)
    }

    fn task_dtb(&mut self, mm: Address, active_mm: Address) -> Result<Address> {
        let Some(mm) = mm.non_null().or(active_mm.non_null()) else {
            return Ok(self.info.dtb);
        };

        let pgd = self.virt_mem.read_addr(mm + self.profile.offsets.mm.pgd)?;
        let phys = self.virt_mem.virt_to_phys(pgd)?;
        Ok(phys.address.as_page_aligned(size::kb(4)))
    }

    fn process_info_from_task(&mut self, task: Address) -> Result<LinuxProcessInfo> {
        let task_offsets = self.profile.offsets.task;
        let mm_offsets = self.profile.offsets.mm;

        let pid = self.virt_mem.read::<u32>(task + task_offsets.pid)?;
        let tgid = self.virt_mem.read::<u32>(task + task_offsets.tgid)?;
        let name = self
            .virt_mem
            .read_utf8_lossy(task + task_offsets.comm, task_offsets.comm_len)
            .data_part()?;
        let mm = self.virt_mem.read_addr(task + task_offsets.mm)?;
        let active_mm = self.virt_mem.read_addr(task + task_offsets.active_mm)?;
        let fs = self
            .virt_mem
            .read_addr(task + task_offsets.fs)
            .unwrap_or(Address::NULL);
        let files = self
            .virt_mem
            .read_addr(task + task_offsets.files)
            .unwrap_or(Address::NULL);
        let signal = self
            .virt_mem
            .read_addr(task + task_offsets.signal)
            .unwrap_or(Address::NULL);
        let dtb = self.task_dtb(mm, active_mm)?;

        let mut exe_file = Address::NULL;
        let mut start_code = Address::NULL;
        let mut end_code = Address::NULL;
        let mut arg_start = Address::NULL;
        let mut arg_end = Address::NULL;
        let mut env_start = Address::NULL;
        let mut env_end = Address::NULL;
        let mut path = String::new();
        let mut command_line = String::new();
        let mut binfmt = Address::NULL;

        if let Some(mm_addr) = mm.non_null() {
            if let Some(binfmt_offset) = mm_offsets.binfmt {
                binfmt = self
                    .virt_mem
                    .read_addr(mm_addr + binfmt_offset)
                    .unwrap_or(Address::NULL);
            }
            exe_file = self
                .virt_mem
                .read_addr(mm_addr + mm_offsets.exe_file)
                .unwrap_or(Address::NULL);
            start_code = self
                .virt_mem
                .read::<u64>(mm_addr + mm_offsets.start_code)
                .map(Address::from)
                .unwrap_or(Address::NULL);
            end_code = self
                .virt_mem
                .read::<u64>(mm_addr + mm_offsets.end_code)
                .map(Address::from)
                .unwrap_or(Address::NULL);
            arg_start = self
                .virt_mem
                .read::<u64>(mm_addr + mm_offsets.arg_start)
                .map(Address::from)
                .unwrap_or(Address::NULL);
            arg_end = self
                .virt_mem
                .read::<u64>(mm_addr + mm_offsets.arg_end)
                .map(Address::from)
                .unwrap_or(Address::NULL);
            env_start = self
                .virt_mem
                .read::<u64>(mm_addr + mm_offsets.env_start)
                .map(Address::from)
                .unwrap_or(Address::NULL);
            env_end = self
                .virt_mem
                .read::<u64>(mm_addr + mm_offsets.env_end)
                .map(Address::from)
                .unwrap_or(Address::NULL);

            if !exe_file.is_null() {
                let root_path = fs.non_null().map(|fs| fs + self.profile.offsets.fs.root);
                path = read_path(
                    &mut self.virt_mem,
                    exe_file + self.profile.offsets.file.f_path,
                    root_path,
                    &self.profile.offsets,
                )
                .unwrap_or_default();
            }

            if !arg_start.is_null() && !arg_end.is_null() {
                let mut proc_mem = self.process_reader(dtb);
                command_line =
                    read_command_line(&mut proc_mem, arg_start, arg_end).unwrap_or_default();
            }
        }

        let path = if path.is_empty() { name.clone() } else { path };
        let pid = if tgid != 0 { tgid } else { pid };
        let sys_arch = linux_arch();
        let proc_arch = self.process_arch(binfmt);
        let state = self.process_state(task);
        debug!(
            "linux process: pid={} task={} mm={} dtb={} proc_arch={:?} state={:?} name={}",
            pid, task, mm, dtb, proc_arch, state, name
        );

        Ok(LinuxProcessInfo {
            base_info: ProcessInfo {
                address: task,
                pid,
                state,
                name: name.into(),
                path: path.into(),
                command_line: command_line.into(),
                sys_arch,
                proc_arch,
                dtb1: dtb,
                dtb2: Address::invalid(),
            },
            task,
            mm,
            active_mm,
            fs,
            files,
            signal,
            exe_file,
            start_code,
            end_code,
            arg_start,
            arg_end,
            env_start,
            env_end,
        })
    }
}

impl<T: PhysicalMemory, V: VirtualTranslate2> PhysicalMemory for LinuxKernel<T, V> {
    fn phys_read_raw_iter(&mut self, data: PhysicalReadMemOps) -> Result<()> {
        self.virt_mem.phys_mem().phys_read_raw_iter(data)
    }

    fn phys_write_raw_iter(&mut self, data: PhysicalWriteMemOps) -> Result<()> {
        self.virt_mem.phys_mem().phys_write_raw_iter(data)
    }

    fn metadata(&self) -> PhysicalMemoryMetadata {
        self.virt_mem.phys_mem_ref().metadata()
    }

    fn set_mem_map(&mut self, mem_map: &[PhysicalMemoryMapping]) {
        self.virt_mem.phys_mem().set_mem_map(mem_map)
    }
}

impl<T: PhysicalMemory, V: VirtualTranslate2> MemoryView for LinuxKernel<T, V> {
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

impl<T: PhysicalMemory, V: VirtualTranslate2> VirtualTranslate for LinuxKernel<T, V> {
    fn virt_to_phys_list(
        &mut self,
        addrs: &[VtopRange],
        out: VirtualTranslationCallback,
        out_fail: VirtualTranslationFailCallback,
    ) {
        self.virt_mem.virt_to_phys_list(addrs, out, out_fail)
    }
}

impl<T: 'static + PhysicalMemory + Clone, V: 'static + VirtualTranslate2 + Clone> Os
    for LinuxKernel<T, V>
{
    type ProcessType<'a> = LinuxProcess<Fwd<&'a mut T>, Fwd<&'a mut V>>;
    type IntoProcessType = LinuxProcess<T, V>;

    fn info(&self) -> &OsInfo {
        &self.info.os_info
    }

    fn process_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        let list_offset = self.profile.offsets.task.tasks;
        let list_head = self.init_task + list_offset;
        let mut entry = list_head;
        let mut count = 0usize;

        for _ in 0..MAX_PROCESS_ITER {
            let task = entry - list_offset;
            let pid = self
                .virt_mem
                .read::<u32>(task + self.profile.offsets.task.pid)?;
            let tgid = self
                .virt_mem
                .read::<u32>(task + self.profile.offsets.task.tgid)?;
            let next = self.virt_mem.read_addr(entry)?;

            if pid == tgid && pid != 0 && !callback.call(task) {
                count += 1;
                break;
            }
            if pid == tgid && pid != 0 {
                count += 1;
            }

            if next.is_null() || next == list_head || next == entry {
                break;
            }

            entry = next;
        }

        info!(
            "linux process enumeration: discovered {} task-group leader(s)",
            count
        );
        Ok(())
    }

    fn process_info_by_address(&mut self, address: Address) -> Result<ProcessInfo> {
        self.process_info_from_task(address)
            .map(|info| info.base_info)
    }

    fn process_by_info(&mut self, info: ProcessInfo) -> Result<Self::ProcessType<'_>> {
        let proc_info = self.process_info_from_task(info.address)?;
        Ok(LinuxProcess::with_kernel_ref(self, proc_info))
    }

    fn into_process_by_info(self, info: ProcessInfo) -> Result<Self::IntoProcessType> {
        let mut kernel = self;
        let proc_info = kernel.process_info_from_task(info.address)?;
        Ok(LinuxProcess::with_kernel(kernel, proc_info))
    }

    fn module_address_list_callback(&mut self, mut callback: AddressCallback) -> Result<()> {
        if !callback.call(self.info.os_info.base) {
            return Ok(());
        }

        let modules = self.kernel_module_cache()?.clone();
        info!(
            "linux OS module enumeration: yielding {} module(s) plus vmlinux",
            modules.len()
        );
        for module in &modules {
            if !callback.call(module.address) {
                break;
            }
        }
        Ok(())
    }

    fn module_by_address(&mut self, address: Address) -> Result<ModuleInfo> {
        if address == self.info.os_info.base {
            self.ensure_kernel_size()?;
            Ok(self.kernel_module_info())
        } else {
            self.kernel_module_cache()?
                .iter()
                .find(|module| module.address == address)
                .cloned()
                .map(|module| ModuleInfo {
                    address: module.address,
                    parent_process: Address::INVALID,
                    base: module.base,
                    size: module.size,
                    name: module.name,
                    path: module.path,
                    arch: self.info.os_info.arch,
                })
                .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
        }
    }

    fn primary_module_address(&mut self) -> Result<Address> {
        Ok(self.info.os_info.base)
    }

    fn module_import_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: ImportCallback,
    ) -> Result<()> {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }

    fn module_export_list_callback(
        &mut self,
        info: &ModuleInfo,
        mut callback: ExportCallback,
    ) -> Result<()> {
        if info.address != self.info.os_info.base {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound));
        }

        let kallsyms = self.ensure_kallsyms()?.clone();

        for (address, name) in kallsyms.syms_iter(&mut self.virt_mem) {
            let export = ExportInfo {
                name: name.into(),
                offset: address
                    .to_umem()
                    .saturating_sub(self.info.os_info.base.to_umem()),
            };
            if !callback.call(export) {
                break;
            }
        }

        Ok(())
    }

    fn module_section_list_callback(
        &mut self,
        _info: &ModuleInfo,
        _callback: SectionCallback,
    ) -> Result<()> {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotImplemented))
    }
}

fn approximate_kernel_size(
    kernel_base: Address,
    kallsyms: &crate::kallsyms::KallsymsInfo,
    mem: &mut impl MemoryView,
) -> umem {
    let mut max_address = kernel_base.to_umem();

    for (address, _) in kallsyms.syms_iter(mem) {
        let address = address.to_umem();
        if address >= kernel_base.to_umem() && address > max_address {
            max_address = address;
        }
    }

    max_address
        .saturating_sub(kernel_base.to_umem())
        .saturating_add(size::kb(4) as u64)
}

fn process_arch_from_binfmt(
    binfmt: Address,
    compat_elf_format: Option<Address>,
) -> ArchitectureIdent {
    let Some(binfmt) = binfmt.non_null() else {
        return linux_arch();
    };

    if Some(binfmt) == compat_elf_format {
        ArchitectureIdent::X86(32, false)
    } else {
        linux_arch()
    }
}

fn validate_profile_banner(
    profile: &LinuxProfile,
    slide: imem,
    scanner: &x64::KernelInfo,
    mem: impl PhysicalMemory,
) -> Result<()> {
    let expected_bytes = trim_trailing_nuls(&profile.banner);
    if expected_bytes.is_empty() {
        return Ok(());
    }

    let expected = String::from_utf8_lossy(expected_bytes);
    let banner_address = profile.rebase(profile.symbols.linux_banner, slide);
    let mut mem = VirtualDma::new(mem, linux_arch(), arch_x64::new_translator(scanner.cr3));
    let actual = mem
        .read_utf8_lossy(banner_address, expected.len() + 1)
        .data_part()?;

    if actual == expected {
        Ok(())
    } else {
        Err(
            Error(ErrorOrigin::OsLayer, ErrorKind::Configuration).log_error(format!(
                "Linux defs banner mismatch: expected `{expected}`, got `{actual}`"
            )),
        )
    }
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
    fn parse_boolish_flag_handles_common_values() {
        assert_eq!(parse_boolish_flag("on"), Some(true));
        assert_eq!(parse_boolish_flag("enabled"), Some(true));
        assert_eq!(parse_boolish_flag("off"), Some(false));
        assert_eq!(parse_boolish_flag("disabled"), Some(false));
        assert_eq!(parse_boolish_flag(""), None);
        assert_eq!(parse_boolish_flag("maybe"), None);
    }

    #[test]
    fn compat_binfmt_selects_x86_process_arch() {
        let compat = Address::from(0xffff_ffff_8100_0000_u64);
        assert_eq!(
            process_arch_from_binfmt(compat, Some(compat)),
            ArchitectureIdent::X86(32, false)
        );
        assert_eq!(
            process_arch_from_binfmt(Address::NULL, Some(compat)),
            linux_arch()
        );
        assert_eq!(
            process_arch_from_binfmt(Address::from(0xffff_ffff_8100_1000_u64), Some(compat)),
            linux_arch()
        );
    }
}

fn scan_with_kernel_hint<T: PhysicalMemory + Clone>(
    mut mem: T,
    kernel_hint: Address,
) -> Result<x64::KernelInfo> {
    let mapping = [PhysicalMemoryMapping {
        base: kernel_hint,
        size: size::mb(2) as umem,
        real_base: kernel_hint,
    }];
    mem.set_mem_map(&mapping);
    x64::find_kernel(mem)
}

/// Tries the defs-backed discovery strategies before the generic architecture fallback.
fn discover_kernel<T: PhysicalMemory + Clone>(
    mem: T,
    profile: &LinuxProfile,
    kernel_hint: Option<Address>,
    cached_kernel_hint: Option<Address>,
    generic_fallback: bool,
) -> Result<x64::KernelInfo> {
    if let Some(kernel_hint) = kernel_hint {
        if let Ok(info) = discover_kernel_with_hint(mem.clone(), profile, kernel_hint) {
            info!("linux bootstrap: resolved kernel from explicit kernel hint");
            return Ok(info);
        }
    }

    if let Some(cached_kernel_hint) = cached_kernel_hint.filter(|hint| Some(*hint) != kernel_hint) {
        if let Ok(info) = discover_kernel_with_hint(mem.clone(), profile, cached_kernel_hint) {
            info!(
                "linux bootstrap: resolved kernel from cached kernel hint {}",
                cached_kernel_hint
            );
            return Ok(info);
        }
        debug!(
            "linux bootstrap: cached kernel hint {} did not validate",
            cached_kernel_hint
        );
    }

    if let Ok(info) = discover_kernel_from_profile(mem.clone(), profile) {
        return Ok(info);
    }

    if let Some(kernel_hint) = kernel_hint {
        if let Ok(info) = scan_with_kernel_hint(mem.clone(), kernel_hint) {
            info!("linux bootstrap: resolved kernel from explicit kernel hint fallback scan");
            return Ok(info);
        }
    }

    if let Some(cached_kernel_hint) = cached_kernel_hint.filter(|hint| Some(*hint) != kernel_hint) {
        if let Ok(info) = scan_with_kernel_hint(mem.clone(), cached_kernel_hint) {
            info!(
                "linux bootstrap: resolved kernel from cached kernel hint fallback scan {}",
                cached_kernel_hint
            );
            return Ok(info);
        }
    }

    if generic_fallback {
        info!("linux bootstrap: falling back to generic x64 kernel scan");
        x64::find_kernel(mem)
    } else {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
            .log_error("defs-backed Linux discovery failed and generic x64 fallback is disabled"))
    }
}

#[derive(Clone, Copy, Debug)]
struct TaskCandidate {
    phys_task: Address,
    runtime_init_task: Address,
    slide: imem,
}

fn discover_kernel_with_hint<T: PhysicalMemory>(
    mut mem: T,
    profile: &LinuxProfile,
    phys_text: Address,
) -> Result<x64::KernelInfo> {
    let task_delta = checked_symbol_delta(profile.symbols.text, profile.symbols.init_task)?;
    let phys_task = checked_add(phys_text, task_delta)?;
    let candidate = validate_init_task_candidate(&mut mem, profile, phys_task)?;
    resolve_kernel_from_candidate(&mut mem, profile, candidate, phys_text)
}

/// Runs the defs-aware discovery sequence for one loaded profile.
fn discover_kernel_from_profile<T: PhysicalMemory + Clone>(
    mem: T,
    profile: &LinuxProfile,
) -> Result<x64::KernelInfo> {
    if let Ok(info) = discover_kernel_from_candidate_scan(mem.clone(), profile) {
        return Ok(info);
    }

    if let Ok(info) = discover_kernel_from_banner_scan(mem.clone(), profile) {
        return Ok(info);
    }

    discover_kernel_from_task_scan(mem, profile)
}

/// Probes 2 MiB-aligned physical candidates derived from `init_task`.
fn discover_kernel_from_candidate_scan<T: PhysicalMemory>(
    mut mem: T,
    profile: &LinuxProfile,
) -> Result<x64::KernelInfo> {
    let task_delta = checked_symbol_delta(profile.symbols.text, profile.symbols.init_task)?;
    let total = mem.metadata().max_address.to_umem().saturating_add(1);
    let step = size::mb(2) as u64;

    debug!(
        "linux bootstrap: probing {}-aligned kernel candidates via init_task offset",
        size::mb(2)
    );

    for phys_text in (0..total).step_by(step as usize).map(Address::from) {
        let Ok(phys_task) = checked_add(phys_text, task_delta) else {
            break;
        };

        let Ok(candidate) = validate_init_task_candidate(&mut mem, profile, phys_task) else {
            continue;
        };

        if let Ok(info) = resolve_kernel_from_candidate(&mut mem, profile, candidate, phys_text) {
            info!(
                "linux bootstrap: resolved kernel from init_task candidate {}",
                phys_task
            );
            return Ok(info);
        }
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
        .log_error("failed to discover Linux kernel from defs-backed init_task candidate scan"))
}

/// Scans physical memory for the banner prefix embedded in the selected defs.
fn discover_kernel_from_banner_scan<T: PhysicalMemory + Clone>(
    mut mem: T,
    profile: &LinuxProfile,
) -> Result<x64::KernelInfo> {
    let banner = trim_trailing_nuls(&profile.banner);
    if banner.is_empty() {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
            .log_error("Linux defs banner is empty"));
    }

    let banner_prefix = &banner[..banner.len().min(BANNER_SCAN_PREFIX_LEN)];
    let banner_delta = checked_symbol_delta(profile.symbols.text, profile.symbols.linux_banner)?;
    let metadata = mem.metadata();
    let mut buf = vec![0_u8; KERNEL_SCAN_CHUNK_SIZE + banner_prefix.len()];
    let mut base = 0_u64;
    let total = metadata.max_address.to_umem().saturating_add(1);
    let overlap = banner_prefix.len().saturating_sub(1) as u64;

    debug!(
        "linux bootstrap: scanning physical memory for linux_banner prefix ({} bytes)",
        banner_prefix.len()
    );

    while base < total {
        let remaining = total.saturating_sub(base);
        let read_len = std::cmp::min(KERNEL_SCAN_CHUNK_SIZE as u64, remaining) as usize;
        if read_len < banner_prefix.len() {
            break;
        }

        mem.phys_view()
            .read_raw_into(Address::from(base), &mut buf[..read_len])
            .data_part()?;

        for match_off in memmem::find_iter(&buf[..read_len], banner_prefix) {
            let phys_banner = Address::from(base + match_off as u64);
            let Ok(phys_text) = checked_sub(phys_banner, banner_delta) else {
                continue;
            };

            if phys_text.to_umem() % size::mb(2) as u64 != 0 {
                continue;
            }

            if let Ok(info) = discover_kernel_with_hint(mem.clone(), profile, phys_text) {
                info!(
                    "linux bootstrap: resolved kernel from linux_banner at {}",
                    phys_banner
                );
                return Ok(info);
            }
        }

        if read_len as u64 == remaining {
            break;
        }

        base = base.saturating_add(read_len as u64).saturating_sub(overlap);
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
        .log_error("failed to discover Linux kernel from defs-backed banner scan"))
}

/// Scans physical memory for the `swapper/0` task name as a last defs-aware fallback.
fn discover_kernel_from_task_scan<T: PhysicalMemory>(
    mut mem: T,
    profile: &LinuxProfile,
) -> Result<x64::KernelInfo> {
    let metadata = mem.metadata();
    let mut buf = vec![0_u8; KERNEL_SCAN_CHUNK_SIZE + SWAPPER_COMM.len()];
    let mut base = 0_u64;
    let total = metadata.max_address.to_umem().saturating_add(1);
    let overlap = SWAPPER_COMM.len().saturating_sub(1) as u64;

    debug!("linux bootstrap: falling back to swapper/0 task scan");

    while base < total {
        let remaining = total.saturating_sub(base);
        let read_len = std::cmp::min(KERNEL_SCAN_CHUNK_SIZE as u64, remaining) as usize;
        if read_len < SWAPPER_COMM.len() {
            break;
        }

        mem.phys_view()
            .read_raw_into(Address::from(base), &mut buf[..read_len])
            .data_part()?;

        for match_off in memmem::find_iter(&buf[..read_len], SWAPPER_COMM) {
            let phys_comm = Address::from(base + match_off as u64);
            if let Some(phys_task) = phys_comm
                .to_umem()
                .checked_sub(profile.offsets.task.comm as u64)
            {
                if let Ok(candidate) =
                    validate_init_task_candidate(&mut mem, profile, Address::from(phys_task))
                {
                    if let Ok(info) =
                        resolve_kernel_from_candidate(&mut mem, profile, candidate, Address::NULL)
                    {
                        return Ok(info);
                    }
                }
            }
        }

        if read_len as u64 == remaining {
            break;
        }

        base = base.saturating_add(read_len as u64).saturating_sub(overlap);
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
        .log_error("failed to discover Linux kernel from defs-backed task scan"))
}

/// Checks whether a physical candidate looks like the rebased `init_task`.
fn validate_init_task_candidate(
    mem: &mut impl PhysicalMemory,
    profile: &LinuxProfile,
    phys_task: Address,
) -> Result<TaskCandidate> {
    let task_offsets = profile.offsets.task;
    let name = read_physical_cstring(mem, phys_task + task_offsets.comm, task_offsets.comm_len)?;
    if name != "swapper/0" {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
    }

    let pid = read_physical_value::<u32>(mem, phys_task + task_offsets.pid)?;
    let tgid = read_physical_value::<u32>(mem, phys_task + task_offsets.tgid)?;
    if pid != 0 || tgid != 0 {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
    }

    let runtime_init_task = read_physical_addr(mem, phys_task + task_offsets.group_leader)?;
    if !looks_like_kernel_pointer(runtime_init_task) {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
    }

    let parent = read_physical_addr(mem, phys_task + task_offsets.parent)?;
    let real_parent = read_physical_addr(mem, phys_task + task_offsets.real_parent)?;
    if parent != runtime_init_task || real_parent != runtime_init_task {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
    }

    let slide = compute_slide_from_symbol(runtime_init_task, profile.symbols.init_task)?;
    if !is_kernel_slide_aligned(slide) {
        return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
    }

    Ok(TaskCandidate {
        phys_task,
        runtime_init_task,
        slide,
    })
}

/// Derives the full kernel translation state from a validated `init_task` candidate.
fn resolve_kernel_from_candidate(
    mem: &mut impl PhysicalMemory,
    profile: &LinuxProfile,
    candidate: TaskCandidate,
    phys_text_hint: Address,
) -> Result<x64::KernelInfo> {
    let virt_text = profile.rebase(profile.symbols.text, candidate.slide);
    let phys_text = if phys_text_hint.is_null() {
        let text_delta = checked_symbol_delta(profile.symbols.text, profile.symbols.init_task)?;
        let phys_text = checked_sub(candidate.phys_task, text_delta)?;
        if phys_text.to_umem() % size::mb(2) as u64 != 0 {
            return Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound));
        }
        phys_text
    } else {
        phys_text_hint
    };

    for cr3 in page_table_candidates(profile, phys_text)? {
        if !validate_kernel_translation(mem, profile, cr3, virt_text, phys_text, candidate) {
            continue;
        }

        return Ok(x64::KernelInfo {
            cr3,
            phys_base: phys_text,
            la57_on: false,
            virt_text,
            phys_text,
            kallsyms: None,
            version: parse_version_range(&profile.banner)
                .unwrap_or_else(|| x64::VersionRange::from(0)),
        });
    }

    Err(Error(ErrorOrigin::OsLayer, ErrorKind::NotFound)
        .log_error("failed to validate Linux page table symbols against the discovered init_task"))
}

fn page_table_candidates(profile: &LinuxProfile, phys_text: Address) -> Result<Vec<Address>> {
    let mut candidates = Vec::new();

    for symbol in [
        profile.symbols.init_top_pgt,
        profile.symbols.level4_kernel_pgt,
    ]
    .into_iter()
    .flatten()
    {
        let delta = checked_symbol_delta(profile.symbols.text, symbol)?;
        let phys = checked_add(phys_text, delta)?.as_page_aligned(size::kb(4));
        if !candidates.contains(&phys) {
            candidates.push(phys);
        }
    }

    if candidates.is_empty() {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::Offset).log_error(
            "Linux defs are missing both `init_top_pgt` and `level4_kernel_pgt` symbols",
        ))
    } else {
        Ok(candidates)
    }
}

/// Verifies that the candidate DTB translates rebased kernel symbols as expected.
fn validate_kernel_translation(
    mem: &mut impl PhysicalMemory,
    profile: &LinuxProfile,
    cr3: Address,
    virt_text: Address,
    phys_text: Address,
    candidate: TaskCandidate,
) -> bool {
    let translator = arch_x64::new_translator(cr3);
    let mut vat = DirectTranslate::new();

    let Ok(text_phys) = vat.virt_to_phys(mem, &translator, virt_text) else {
        return false;
    };
    if text_phys.address != phys_text {
        return false;
    }

    let Ok(init_task_phys) = vat.virt_to_phys(mem, &translator, candidate.runtime_init_task) else {
        return false;
    };
    if init_task_phys.address != candidate.phys_task {
        return false;
    }

    let banner_addr = profile.rebase(profile.symbols.linux_banner, candidate.slide);
    let mut virt_mem = VirtualDma::new(mem.forward(), linux_arch(), translator);
    let expected = trim_trailing_nuls(&profile.banner);
    if expected.is_empty() {
        return true;
    }

    virt_mem
        .read_raw(banner_addr, expected.len().min(256))
        .map(|actual| actual == &expected[..expected.len().min(256)])
        .unwrap_or(false)
}

fn read_physical_value<T: Pod>(mem: &mut impl PhysicalMemory, addr: Address) -> Result<T> {
    mem.phys_view().read(addr).data_part()
}

fn read_physical_addr(mem: &mut impl PhysicalMemory, addr: Address) -> Result<Address> {
    read_physical_value::<u64>(mem, addr).map(Address::from)
}

fn read_physical_cstring(
    mem: &mut impl PhysicalMemory,
    addr: Address,
    max_len: usize,
) -> Result<String> {
    let mut buf = vec![0_u8; max_len];
    mem.phys_view().read_raw_into(addr, &mut buf).data_part()?;
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

fn compute_slide_from_symbol(runtime: Address, profile: Address) -> Result<imem> {
    let runtime = runtime.to_umem() as i128;
    let profile = profile.to_umem() as i128;
    let delta = runtime - profile;
    if delta < imem::MIN as i128 || delta > imem::MAX as i128 {
        Err(Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
            .log_error("computed Linux KASLR slide does not fit into imem"))
    } else {
        Ok(delta as imem)
    }
}

fn checked_symbol_delta(base: Address, target: Address) -> Result<u64> {
    target.to_umem().checked_sub(base.to_umem()).ok_or_else(|| {
        Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
            .log_error("Linux defs symbol ordering produced a negative delta")
    })
}

fn checked_add(base: Address, delta: u64) -> Result<Address> {
    base.to_umem()
        .checked_add(delta)
        .map(Address::from)
        .ok_or_else(|| {
            Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
                .log_error("Linux physical address addition overflowed")
        })
}

fn checked_sub(base: Address, delta: u64) -> Result<Address> {
    base.to_umem()
        .checked_sub(delta)
        .map(Address::from)
        .ok_or_else(|| {
            Error(ErrorOrigin::OsLayer, ErrorKind::Offset)
                .log_error("Linux physical address subtraction underflowed")
        })
}

fn looks_like_kernel_pointer(address: Address) -> bool {
    let value = address.to_umem();
    value >= 0xffff_8000_0000_0000 && value != Address::INVALID.to_umem()
}

fn is_kernel_slide_aligned(slide: imem) -> bool {
    slide >= 0 && (slide as u64) % size::mb(2) as u64 == 0
}

fn parse_version_range(banner: &[u8]) -> Option<x64::VersionRange> {
    let banner = std::str::from_utf8(trim_trailing_nuls(banner)).ok()?;
    let version = banner.strip_prefix("Linux version ")?;
    let version = version.split_whitespace().next()?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<usize>().ok()?;
    let minor = parts.next()?.parse::<usize>().ok()?;
    let point = parts
        .next()
        .and_then(|part| {
            let digits = part
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            (!digits.is_empty()).then_some(digits)
        })?
        .parse::<usize>()
        .ok()?;

    Some(x64::VersionRange::from((major, minor, point)))
}

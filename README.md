# memflow-linux

This workspace provides Linux support for the [memflow](https://github.com/memflow/memflow) memory introspection framework.
It is designed for introspection of Linux memory through a normal memflow connector and can be used either through the memflow plugin system or as a Rust dependency.

Given the diversity of Linux kernels, memflow-linux requires the corresponding `vmlinux` deggubing symbols associated to the target.

## Workspace layout

This repository contains two crates:

- `memflow-linux`: the runtime Linux OS layer and plugin in `memflow-linux/`
- `memflow-linux-defs`: the offline defs generator in `memflow-linux-defs/`

The typical workflow is:

1. Generate a defs file from a matching `vmlinux`.
2. Point `memflow-linux` at that defs file.
3. Open the memory image through a memflow connector and use `-o linux` or `LinuxKernel::builder(...)`.

## Current scope

- x86_64 Linux targets with 4-level paging (5-level not supported yet).
- offline introspection through a memflow `PhysicalMemory` connector such as `memflow-rawmem`
- Live introspection with `memflow-pcileech`
- defs-guided kernel bootstrap from raw physical memory
- optional persistent kernel-hint caching for faster repeated boots
- optional generic x64 fallback scan when defs-guided discovery fails
- process enumeration
- per-process virtual memory access
- argv and environment extraction
- VMA walking through maple trees on modern kernels and `mm->mmap` on older kernels
- userland module enumeration from ELF-backed file mappings
- kernel module enumeration
- kernel export enumeration from live `kallsyms`

## Building

Build the full workspace:

```bash
cargo build --release --workspace
```

Build just the runtime plugin as a `cdylib`:

```bash
cargo build --release --all-features -p memflow-linux
```

Build the defs generator example:

```bash
cargo build --release -p memflow-linux-defs --example generate_defs
```

## Generating Linux defs

Generate a defs file from a matching unstripped `vmlinux`:

```bash
cargo run -p memflow-linux-defs --example generate_defs -- \
  --vmlinux /path/to/vmlinux \
  --output /path/to/vmlinux.toml
```

If `--output` is omitted, the generator writes `<vmlinux filename>.toml` next to the input file.

The runtime expects this generated TOML file at runtime, not the original `vmlinux` ELF.
The defs file stores the normalized symbol RVAs, enum values, and structure offsets the runtime needs for bootstrap and traversal.

## Running through memflow

The simplest plugin workflow for a test on a raw linux memory image is:

```bash
export MEMFLOW_PLUGIN_PATH=/path/to/memflow/plugins
export MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml

cargo run -p memflow --example process_list -- \
  -c rawmem:/path/to/memory.raw \
  -o linux
```

`MEMFLOW_LINUX_PROFILE` points at the generated defs file.
If it is not set, `memflow-linux` also looks for adjacent defs files near the image hint using one of these names:

- `vmlinux.toml`
- `linux.toml`
- `vmlinux-*.toml`
- `linux-defs*.toml`

## Runtime configuration

The runtime accepts configuration through the builder API, plugin args, and environment variables.

Plugin arguments:

- `profile=/path/to/vmlinux.toml`: use an explicit defs file
- `kernel_hint=0x...`: provide an explicit physical kernel text hint
- `kernel_hint_cache=off`: disable the persistent kernel-hint cache
- `kernel_hint_cache=/path/to/cache-dir`: override the cache directory
- `banner_check=skip`: skip banner validation once a candidate kernel was found
- `generic_fallback=on|off`: enable or disable the generic x64 fallback scan

Environment variables:

- `MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml`: default defs file path
- `MEMFLOW_LINUX_KERNEL_HINT_CACHE=off|/path/to/cache-dir`: cache policy override
- `MEMFLOW_LINUX_GENERIC_FALLBACK=on|off`: default policy for the generic x64 fallback scan

Notes:
- `kernel_hint` is the physical kernel text base and is expected to be 2 MiB aligned.
- The generic fallback is enabled by default and is useful as a recovery path, but it can be slow on cold scans.
- After one successful run, later runs against the same image should usually bootstrap faster because the cached hint is validated before the slower scan paths are attempted.

## Bundled examples

List processes:

```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml \
cargo run -p memflow-linux --example process_list -- \
  -vv -c rawmem:/path/to/memory.raw
```

Open a process and list its modules:

```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml \
cargo run -p memflow-linux --example open_process -- \
  -vv -c rawmem:/path/to/memory.raw -p firefox-esr
```

List a process environment variable:

```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml \
cargo run -p memflow-linux --example envars_list -- \
  -vv -c rawmem:/path/to/memory.raw -p firefox-esr -e HOME
```

The examples also accept:

- `--profile /path/to/vmlinux.toml`
- `--kernel-hint 0x...`

## Programmatic usage

```rust
use memflow::prelude::v1::*;
use memflow_linux::LinuxKernel;

# fn main() -> Result<()> {
let connector = /* any memflow PhysicalMemory connector */;

let mut kernel = LinuxKernel::builder(connector)
    .profile("/path/to/vmlinux.toml")
    .build_default_caches()
    .build()?;

for process in kernel.process_info_list()? {
    println!("{} {}", process.pid, process.name);
}
# Ok(())
# }
```

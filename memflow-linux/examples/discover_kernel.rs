/*!
Scans physical memory for the Linux kernel banner string (`"Linux version ..."`)
without requiring a defs file, then prints the discovered version(s) and guidance
on where to obtain the matching debug symbols.

This mirrors the banner-scan approach used by Volatility3.

# Usage:
```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
cargo run -p memflow-linux --example discover_kernel -- -vv -c rawmem:/path/to/memory.raw
```
*/
mod common;

use clap::*;
use memflow::prelude::v1::*;
use memflow_linux::discover_kernel_versions;

fn main() -> Result<()> {
    let matches = parse_args();
    common::init_logger(&matches);

    let chain = common::extract_connector_chain(&matches)?;

    let mut inventory = Inventory::scan();
    let mut connector = inventory.builder().connector_chain(chain).build()?;

    println!("Scanning physical memory for Linux kernel banner(s)...");
    let found = discover_kernel_versions(&mut connector);

    if found.is_empty() {
        eprintln!("No Linux kernel banner found in physical memory.");
        eprintln!("Make sure the memory image covers the kernel region.");
        return Ok(());
    }

    println!("\nDiscovered {} unique kernel version(s):\n", found.len());
    for info in &found {
        println!("  Version  : {}", info.version);
        println!("  Banner   : {}", info.banner);
        println!("  Phys addr: {}", info.phys_address);
        println!();
    }

    println!("--- How to obtain debug symbols ---\n");
    for info in &found {
        println!("Kernel: {}", info.version);
        print_symbol_hints(&info.version);
        println!();
    }

    Ok(())
}

fn print_symbol_hints(version: &str) {
    // Best-effort distro detection from the version string.
    let lower = version.to_lowercase();

    if lower.contains("ubuntu") || lower.contains("generic") || lower.contains("azure") || lower.contains("aws") || lower.contains("gcp") {
        println!("  Ubuntu / Debian:");
        println!("    sudo apt-get install linux-image-{version}-dbgsym");
        println!("    (or download from https://ddebs.ubuntu.com/)");
        println!("  Then generate defs:");
        println!("    cargo run -p memflow-linux-defs --example generate_defs -- /usr/lib/debug/boot/vmlinux-{version}");
    } else if lower.contains("fc") || lower.contains("el") || lower.contains("rhel") || lower.contains("centos") {
        println!("  Fedora / RHEL / CentOS:");
        println!("    sudo dnf debuginfo-install kernel-{version}");
        println!("    # vmlinux will be in /usr/lib/debug/lib/modules/{version}/vmlinux");
        println!("  Then generate defs:");
        println!("    cargo run -p memflow-linux-defs --example generate_defs -- /usr/lib/debug/lib/modules/{version}/vmlinux");
    } else if lower.contains("arch") || lower.contains("manjaro") {
        println!("  Arch Linux:");
        println!("    Install linux-headers and build vmlinux from the matching kernel source.");
        println!("    See: https://wiki.archlinux.org/title/Debugging/Getting_traces");
    } else {
        println!("  Generic steps:");
        println!("    1. Obtain the unstripped vmlinux for kernel {version}.");
        println!("       - Ubuntu/Debian: https://ddebs.ubuntu.com/");
        println!("       - Fedora/RHEL:   dnf debuginfo-install kernel-{version}");
        println!("       - Compiled:      the vmlinux at the root of the build tree");
        println!("    2. Generate a defs file:");
        println!("       cargo run -p memflow-linux-defs --example generate_defs -- /path/to/vmlinux");
        println!("    3. Pass the generated .toml to memflow-linux:");
        println!("       MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml  (or --profile flag)");
    }
}

fn parse_args() -> ArgMatches {
    Command::new("discover_kernel example")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Scan physical memory for Linux kernel version without a defs file")
        .arg(Arg::new("verbose").short('v').action(ArgAction::Count))
        .arg(
            Arg::new("connector")
                .short('c')
                .long("connector")
                .action(ArgAction::Append)
                .required(true),
        )
        .arg(
            Arg::new("os")
                .short('o')
                .long("os")
                .action(ArgAction::Append),
        )
        .get_matches()
}

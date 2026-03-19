/*!
This example shows how to use a dynamically loaded connector in conjunction
with `memflow-linux`. The connector is loaded through the memflow inventory
system and then passed directly into the Linux OS layer builder.

The example lists all processes known to the Linux kernel.

# Usage:
```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml \
cargo run -p memflow-linux --example process_list -- -vv -c rawmem:/path/to/memory.raw
```
*/
mod common;

use clap::*;
use memflow::prelude::v1::*;
use memflow_linux::LinuxKernel;

fn main() -> Result<()> {
    let matches = parse_args();
    common::init_logger(&matches);

    let chain = common::extract_connector_chain(&matches)?;
    let profile = common::extract_profile(&matches);
    let kernel_hint = common::extract_kernel_hint(&matches)?;

    let mut inventory = Inventory::scan();
    let connector = inventory.builder().connector_chain(chain).build()?;

    let mut builder = LinuxKernel::builder(connector);
    if let Some(profile) = profile {
        builder = builder.profile(profile);
    }
    if let Some(kernel_hint) = kernel_hint {
        builder = builder.kernel_hint(kernel_hint);
    }

    let mut os = builder.build_default_caches().build()?;
    let process_list = os.process_info_list()?;

    println!(
        "{:>5} {:>10} {:>10} {:<}",
        "PID", "SYS ARCH", "PROC ARCH", "NAME"
    );

    for process in process_list {
        println!(
            "{:>5} {:^10} {:^10} {} ({}) ({:?})",
            process.pid,
            process.sys_arch,
            process.proc_arch,
            process.name,
            process.command_line,
            process.state
        );
    }

    Ok(())
}

fn parse_args() -> ArgMatches {
    Command::new("process_list example")
        .version(crate_version!())
        .author(crate_authors!())
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
        .arg(
            Arg::new("profile")
                .long("profile")
                .action(ArgAction::Set)
                .required(false)
                .value_name("LINUX_DEFS"),
        )
        .arg(
            Arg::new("kernel_hint")
                .long("kernel-hint")
                .action(ArgAction::Set)
                .required(false)
                .value_name("PHYS_BASE"),
        )
        .get_matches()
}

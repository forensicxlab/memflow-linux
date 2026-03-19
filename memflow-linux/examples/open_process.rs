/*!
This example shows how to use a dynamically loaded connector in conjunction
with `memflow-linux`. The connector is loaded through the memflow inventory
system and then passed directly into the Linux OS layer builder.

The example opens a process by name, prints its process information, and then
lists the modules discovered for that process.

# Usage:
```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml \
cargo run -p memflow-linux --example open_process -- \
  -vv -c rawmem:/path/to/memory.raw -p firefox-esr
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
    let process_name = matches
        .get_one::<String>("process")
        .map(String::as_str)
        .ok_or_else(|| Error(ErrorOrigin::OsLayer, ErrorKind::RequiredArgNotFound))?;

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
    let process_info = os.process_info_by_name(process_name)?;
    println!("{process_info:?}");

    let mut process = os.into_process_by_info(process_info)?;
    let module_list = process.module_list()?;

    println!("{:>18} {:>10} {:<24} {:<}", "BASE", "SIZE", "NAME", "PATH");

    for module in module_list {
        println!(
            "{:>18} {:>10x} {:<24} {}",
            module.base, module.size, module.name, module.path
        );
    }

    Ok(())
}

fn parse_args() -> ArgMatches {
    Command::new("open_process example")
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
            Arg::new("process")
                .short('p')
                .long("process")
                .action(ArgAction::Set)
                .required(true)
                .value_name("PROCESS"),
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

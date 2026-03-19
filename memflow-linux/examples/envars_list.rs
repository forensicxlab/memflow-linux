/*!
This example shows how to use a dynamically loaded connector in conjunction
with `memflow-linux`. The connector is loaded through the memflow inventory
system and then passed directly into the Linux OS layer builder.

The example opens a process by name, prints its environment variables, and can
optionally search for one variable by name.

# Usage:
```bash
MEMFLOW_PLUGIN_PATH=/path/to/plugins \
MEMFLOW_LINUX_PROFILE=/path/to/vmlinux.toml \
cargo run -p memflow-linux --example envars_list -- \
  -vv -c rawmem:/path/to/memory.raw -p firefox-esr -e HOME
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
    let envar_name = matches
        .get_one::<String>("envar")
        .map(String::as_str)
        .unwrap_or("");

    let mut inventory = Inventory::scan();
    let connector = inventory.builder().connector_chain(chain).build()?;

    let mut builder = LinuxKernel::builder(connector);
    if let Some(profile) = profile {
        builder = builder.profile(profile);
    }
    if let Some(kernel_hint) = kernel_hint {
        builder = builder.kernel_hint(kernel_hint);
    }

    let os = builder.build_default_caches().build()?;
    let mut process = os.into_process_by_name(process_name)?;

    println!("found process: {:?}", process.info());
    println!("   VARIABLE | VALUE");

    let envar_list = process.envar_list()?;
    for variable in envar_list {
        println!("    {}={}", variable.name.as_ref(), variable.value.as_ref());
    }

    if !envar_name.is_empty() {
        match process.envar_by_name(envar_name) {
            Ok(variable) => println!("FOUND {:?}", variable),
            Err(_) => println!("ENVAR NOT FOUND"),
        }
    }

    Ok(())
}

fn parse_args() -> ArgMatches {
    Command::new("envars_list example")
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
            Arg::new("envar")
                .short('e')
                .long("envar")
                .action(ArgAction::Set)
                .required(false)
                .value_name("ENV_VAR"),
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

use std::fs;
use std::path::{Path, PathBuf};

use clap::{crate_authors, crate_version, Arg, ArgAction, Command};
use log::Level;
use memflow_linux_defs::LinuxDefs;

fn main() {
    let matches = Command::new("generate Linux defs")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::new("verbose").short('v').action(ArgAction::Count))
        .arg(
            Arg::new("vmlinux")
                .long("vmlinux")
                .required(true)
                .value_name("VMLINUX"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .required(false)
                .value_name("DEFS_TOML"),
        )
        .get_matches();

    let level = match matches.get_count("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        _ => Level::Trace,
    };

    simplelog::TermLogger::init(
        level.to_level_filter(),
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    )
    .unwrap();

    let vmlinux = PathBuf::from(matches.get_one::<String>("vmlinux").unwrap());
    let output = matches
        .get_one::<String>("output")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_output_path(&vmlinux));

    let defs = LinuxDefs::from_vmlinux(&vmlinux).unwrap();
    let toml = defs.to_toml_string().unwrap();
    fs::write(&output, toml).unwrap();

    println!("{}", output.display());
}

fn default_output_path(vmlinux: &Path) -> PathBuf {
    let file_name = vmlinux
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vmlinux");
    vmlinux.with_file_name(format!("{file_name}.toml"))
}

//! Shared CLI helpers used by the `memflow-linux` examples.

use clap::ArgMatches;
use log::Level;
use memflow::prelude::v1::*;

/// Initializes terminal logging from a repeated `-v` flag count.
pub fn init_logger(matches: &ArgMatches) {
    let log_level = match matches.get_count("verbose") {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        _ => Level::Trace,
    };

    let _ = simplelog::TermLogger::init(
        log_level.to_level_filter(),
        simplelog::Config::default(),
        simplelog::TerminalMode::Stdout,
        simplelog::ColorChoice::Auto,
    );
}

/// Builds a connector chain from the example CLI arguments.
pub fn extract_connector_chain(matches: &ArgMatches) -> Result<ConnectorChain<'_>> {
    let conn_iter = matches
        .indices_of("connector")
        .zip(matches.get_many::<String>("connector"))
        .map(|(a, b)| a.zip(b.map(String::as_str)))
        .into_iter()
        .flatten();

    let os_iter = matches
        .indices_of("os")
        .zip(matches.get_many::<String>("os"))
        .map(|(a, b)| a.zip(b.map(String::as_str)))
        .into_iter()
        .flatten();

    ConnectorChain::new(conn_iter, os_iter)
}

/// Returns the optional explicit defs path supplied on the CLI.
pub fn extract_profile(matches: &ArgMatches) -> Option<&str> {
    matches.get_one::<String>("profile").map(String::as_str)
}

/// Parses an optional hexadecimal kernel hint from the CLI.
pub fn extract_kernel_hint(matches: &ArgMatches) -> Result<Option<Address>> {
    matches
        .get_one::<String>("kernel_hint")
        .map(|value| value.trim_start_matches("0x").trim_start_matches("0X"))
        .map(|value| {
            u64::from_str_radix(value, 16)
                .map(Address::from)
                .map_err(|_| {
                    Error(ErrorOrigin::OsLayer, ErrorKind::ArgValidation)
                        .log_error("failed to parse --kernel-hint as hexadecimal")
                })
        })
        .transpose()
}

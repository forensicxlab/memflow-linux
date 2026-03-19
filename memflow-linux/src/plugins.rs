//! memflow plugin entrypoints for `memflow-linux`.

use crate::kernel::LinuxKernel;

use log::info;
use memflow::plugins::os::create_instance;
use memflow::prelude::v1::*;
use std::path::Path;

#[os(name = "linux", accept_input = true, return_wrapped = true)]
/// Instantiates the Linux OS layer from plugin arguments and a memory connector.
pub fn create_os(
    args: &OsArgs,
    mem: Option<ConnectorInstanceArcBox<'static>>,
    lib: LibArc,
) -> Result<OsInstanceArcBox<'static>> {
    let mem = mem.ok_or_else(|| {
        Error(ErrorOrigin::OsLayer, ErrorKind::Configuration)
            .log_error("the Linux OS plugin requires a memory connector")
    })?;

    let explicit_profile = args.extra_args.get("profile");
    let target = args.target.as_ref().map(|value| value.as_ref());
    let skip_banner_check = args
        .extra_args
        .get("banner_check")
        .is_some_and(|value| value.eq_ignore_ascii_case("skip"));
    let generic_fallback = args.extra_args.get("generic_fallback").and_then(|value| {
        if value.eq_ignore_ascii_case("1")
            || value.eq_ignore_ascii_case("on")
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("enable")
            || value.eq_ignore_ascii_case("enabled")
        {
            Some(true)
        } else if value.eq_ignore_ascii_case("0")
            || value.eq_ignore_ascii_case("off")
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("disable")
            || value.eq_ignore_ascii_case("disabled")
        {
            Some(false)
        } else {
            None
        }
    });

    let mut builder = LinuxKernel::builder(mem);
    if let Some(profile) = explicit_profile {
        builder = builder.profile(profile);
    } else if let Some(target) = target {
        if looks_like_profile_path(target) {
            builder = builder.profile(target);
        } else {
            builder = builder.image_hint(target);
        }
    }

    if let Some(kernel_hint) = args.extra_args.get("kernel_hint").and_then(|value| {
        let value = value.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(value, 16).ok()
    }) {
        builder = builder.kernel_hint(Address::from(kernel_hint));
    }

    if let Some(cache) = args.extra_args.get("kernel_hint_cache") {
        if cache.eq_ignore_ascii_case("0")
            || cache.eq_ignore_ascii_case("off")
            || cache.eq_ignore_ascii_case("false")
            || cache.eq_ignore_ascii_case("disabled")
        {
            builder = builder.disable_kernel_hint_cache();
        } else if !cache.is_empty()
            && !cache.eq_ignore_ascii_case("1")
            && !cache.eq_ignore_ascii_case("on")
            && !cache.eq_ignore_ascii_case("true")
            && !cache.eq_ignore_ascii_case("default")
        {
            builder = builder.kernel_hint_cache_dir(cache);
        }
    }

    if skip_banner_check {
        builder = builder.skip_banner_check();
    }

    if let Some(generic_fallback) = generic_fallback {
        builder = if generic_fallback {
            builder.enable_generic_fallback()
        } else {
            builder.disable_generic_fallback()
        };
    }

    info!(
        "linux plugin: create_os target={:?} explicit_profile={} kernel_hint={:?} kernel_hint_cache={:?} skip_banner_check={} generic_fallback={:?}",
        target,
        explicit_profile.is_some(),
        args.extra_args.get("kernel_hint"),
        args.extra_args.get("kernel_hint_cache"),
        skip_banner_check,
        generic_fallback
    );

    let kernel = builder.build_default_caches().build()?;
    Ok(create_instance(kernel, lib, args))
}

/// Returns whether an OS target looks like a generated Linux defs file.
fn looks_like_profile_path(path: &str) -> bool {
    let path = Path::new(path);
    path.extension().and_then(|ext| ext.to_str()) == Some("toml")
}

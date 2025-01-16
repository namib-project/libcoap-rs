use std::{env, env::VarError, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use enumset::EnumSet;
use version_compare::Version;

use crate::{
    build_system::{pkgconfig::PkgConfigBuildSystem, BuildSystem},
    metadata::{DtlsBackend, LibcoapFeature, MINIMUM_LIBCOAP_VERSION},
};

mod bindings;
mod build_system;
mod metadata;

fn main() -> Result<()> {
    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("no OUT_DIR was provided (are we not running as a cargo build script?)"),
    );

    let requested_features: EnumSet<LibcoapFeature> = EnumSet::<LibcoapFeature>::all()
        .iter()
        .filter(|feat| std::env::var_os(format!("CARGO_FEATURE_{}", feat.cargo_feature_var_name())).is_some())
        .collect();

    let requested_dtls_backend: Option<DtlsBackend> = match env::var("LIBCOAP_RS_DTLS_BACKEND") {
        Ok(v) => v.parse().map(Some),
        Err(VarError::NotPresent) => Ok(None),
        Err(e) => Err(anyhow!(e)),
    }
    .context("unable to parse environment variable LIBCOAP_RS_DTLS_BACKEND")?;

    let chosen_build_system = match env::var("LIBCOAP_RS_BUILD_SYSTEM") {
        Ok(v) => Ok(Some(v)),
        Err(VarError::NotPresent) => Ok(None),
        Err(e) => Err(e).context("unable to parse environment variable LIBCOAP_BUILD_SYSTEM"),
    }?;

    let bypass_compile_time_feature_checks = match env::var("LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS") {
        Ok(v) if v == "0" => Ok(false),
        Ok(v) => Ok(true),
        Err(VarError::NotPresent) => Ok(false),
        Err(e) => Err(e).context("unable to parse environment variable LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS"),
    }?;

    let mut build_system: Box<dyn BuildSystem> = match chosen_build_system.as_ref().map(String::as_str) {
        Some("pkgconfig") => PkgConfigBuildSystem::link_with_libcoap(out_dir, requested_dtls_backend)
            .context("unable to link libcoap using force-configured build system pkgconfig")
            .map(|v| Box::<dyn BuildSystem>::from(Box::new(v))),
        Some(v) => Err(anyhow!("unknown build system {v}")),
        None => {
            #[cfg(target_os = "espidf")]
            {
                link_libcoap_espidf()
            }
            #[cfg(not(target_os = "espidf"))]
            {
                #[cfg(unix)]
                {
                    link_libcoap_unix(out_dir, requested_features, requested_dtls_backend)
                }
                #[cfg(windows)]
                {
                    link_libcoap_windows()
                }
            }
        },
    }?;

    let bindings_file = build_system.generate_bindings()?;
    println!(
        "cargo:rustc-env=BINDINGS_FILE={}",
        bindings_file.canonicalize()?.display()
    );

    if build_system.version() < Version::from(MINIMUM_LIBCOAP_VERSION) {
        println!("cargo:warning=The linked version of libcoap is lower than the minimal version required for libcoap-sys ({}), this will most likely cause errors.", MINIMUM_LIBCOAP_VERSION);
    }

    match build_system.detected_features() {
        Some(detected_features) => {
            let compile_time_checkable_features: EnumSet<LibcoapFeature> = requested_features.iter().filter(|feat| feat.define_name().is_some()).collect();
            if !bypass_compile_time_feature_checks && !compile_time_checkable_features.is_subset(detected_features) {
                let missing_features = requested_features.difference(detected_features);
                bail!(
                    concat!(
                        "the libcoap-rs compile-time feature check has determined that the following enabled features\n",
                        "are not supported by the used C library: {}.\n",
                        "If you are certain that this check is mistaken (e.g., because you are cross-compiling), you\n",
                        "may bypass this check by setting the `LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS` environment\n",
                        "variable to any non-zero value.\n",
                        "Be aware, however, that this might lead to more cryptic errors if the requested features are\n",
                        "not available after all."
                    ),
                    missing_features
                        .iter()
                        .map(|v| v.as_str())
                        .collect::<Vec<&str>>()
                        .join(", ")
                );
            }
        },
        None => {
            println!("cargo:warning=The used build system for libcoap-sys does not support compile-time feature checks. Missing features may therefore only be detected during runtime.");
        },
    }

    Ok(())
}

#[cfg(target_os = "espidf")]
fn link_libcoap_espidf() -> Result<impl BuildSystem> {
    // For ESP-IDF: Use esp-idf tooling.
    todo!()
}

#[cfg(unix)]
fn link_libcoap_unix(
    out_dir: PathBuf,
    requested_features: EnumSet<LibcoapFeature>,
    requested_dtls_backend: Option<DtlsBackend>,
) -> Result<Box<dyn BuildSystem>> {
    // For unix-like systems: Use pkg-config.
    if cfg!(feature = "vendored") {
        todo!()
    } else {
        PkgConfigBuildSystem::link_with_libcoap(out_dir, requested_dtls_backend)
            .map(|v| Box::<dyn BuildSystem>::from(Box::new(v)))
    }
}

#[cfg(windows)]
fn link_libcoap_windows() -> Result<impl BuildSystem> {
    // For Windows, we currently only support manual setup (cmake would be a possible alternative).
    todo!()
}

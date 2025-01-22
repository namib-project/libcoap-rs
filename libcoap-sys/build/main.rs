use std::{env, env::VarError, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use enumset::EnumSet;
use version_compare::Version;

use crate::build_system::esp_idf::EspIdfBuildSystem;
use crate::build_system::vendored::VendoredBuildSystem;
use crate::{
    build_system::{manual::ManualBuildSystem, pkgconfig::PkgConfigBuildSystem, BuildSystem},
    metadata::{DtlsBackend, LibcoapFeature, MINIMUM_LIBCOAP_VERSION},
};

mod bindings;
mod build_system;
mod metadata;

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed=LIBCOAP_RS_DTLS_BACKEND");
    println!("cargo:rerun-if-env-changed=LIBCOAP_RS_BUILD_SYSTEM");
    println!("cargo:rerun-if-env-changed=LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS");
    // On ESP-IDF builds, this indicates whether the libcoap component has been enabled.
    println!("cargo::rustc-check-cfg=cfg(esp_idf_comp_espressif__coap_enabled)");
    // Indicates the DTLS library crate that was linked against, if a library version vendored by
    // another crate was used.
    println!("cargo:rustc-check-cfg=cfg(used_dtls_crate, values(\"mbedtls\", \"tinydtls\", \"openssl\"))");
    // Indicates the DTLS backend used, if any.
    println!("cargo:rustc-check-cfg=cfg(dtls_backend, values(\"mbedtls\", \"tinydtls\", \"openssl\", \"gnutls\", \"wolfssl\"))");
    // The detected libcoap version, if any.
    println!("cargo::rustc-check-cfg=cfg(libcoap_version, values(any()))");

    let out_dir = PathBuf::from(
        env::var_os("OUT_DIR").expect("no OUT_DIR was provided (are we not running as a cargo build script?)"),
    );

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("unable to parse CARGO_CFG_TARGET_OS env variable");

    let requested_features: EnumSet<LibcoapFeature> = EnumSet::<LibcoapFeature>::all()
        .iter()
        .filter(|feat| env::var_os(format!("CARGO_FEATURE_{}", feat.cargo_feature_var_suffix())).is_some())
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
        Ok(_v) => Ok(true),
        Err(VarError::NotPresent) => Ok(false),
        Err(e) => Err(e).context("unable to parse environment variable LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS"),
    }?;

    let mut build_system: Box<dyn BuildSystem> = match chosen_build_system.as_deref() {
        Some(requested_build_system) => link_libcoap_explicit(
            requested_build_system,
            &target_os,
            out_dir,
            requested_features,
            requested_dtls_backend,
            bypass_compile_time_feature_checks,
        ),
        None => link_libcoap_auto(
            &target_os,
            out_dir,
            requested_features,
            requested_dtls_backend,
            bypass_compile_time_feature_checks,
        ),
    }?;

    let bindings_file = build_system.generate_bindings()?;
    println!(
        "cargo:rustc-env=BINDINGS_FILE={}",
        bindings_file.canonicalize()?.display()
    );

    if let Some(version) = build_system.version() {
        if version < Version::from(MINIMUM_LIBCOAP_VERSION).unwrap() {
            println!("cargo:warning=The linked version of libcoap is lower than the minimal version required for libcoap-sys ({}), this will most likely cause errors.", MINIMUM_LIBCOAP_VERSION);
        }
        println!("cargo::metadata=libcoap_version={}", version.as_str());
        println!("cargo::rustc-cfg=libcoap_version=\"{}\"", version.as_str());
    } else {
        println!("cargo:warning=Unable to automatically detect the linked version of libcoap, please manually ensure that the used version is at least {} for libcoap-sys to work as expected.", MINIMUM_LIBCOAP_VERSION);
    }

    if let Some(dtls_backend) = build_system.detected_dtls_backend() {
        println!("cargo::metadata=dtls_backend={}", dtls_backend.as_str());
        println!("cargo::rustc-cfg=dtls_backend=\"{}\"", dtls_backend.as_str());

        if !bypass_compile_time_feature_checks {
            if let Some(req_backend) = requested_dtls_backend {
                assert_eq!(req_backend, dtls_backend,
                           concat!(
                           "the libcoap-rs compile-time check has determined that the DTLS library\n",
                           "the used version of libcoap linked against ({}) does not match the one set in LIBCOAP_RS_DTLS_BACKEND ({}).\n",
                           "If you are certain that this check is mistaken (e.g., because you are cross-compiling), you\n",
                           "may bypass this check by setting the `LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS` environment\n",
                           "variable to any non-zero value.\n",
                           "Be aware, however, that this might lead to more cryptic errors if the requested features are\n",
                           "not available after all.\n",
                           "Refer to the libcoap-sys crate-level documentation for more information: https://docs.rs/libcoap-sys."
                           ), dtls_backend.as_str(), req_backend.as_str())
            } else if bypass_compile_time_feature_checks {
                println!("cargo:warning=You have bypassed the libcoap-sys compile-time DTLS library check.")
            }
        }
    }

    match build_system.detected_features() {
        Some(detected_features) => {
            let compile_time_checkable_features: EnumSet<LibcoapFeature> = requested_features
                .iter()
                .filter(|feat| feat.define_name().is_some())
                .collect();
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
                        "not available after all.\n",
                        "Refer to the libcoap-sys crate-level documentation for more information: https://docs.rs/libcoap-sys."
                    ),
                    missing_features
                        .iter()
                        .map(|v| v.as_str())
                        .collect::<Vec<&str>>()
                        .join(", ")
                );
            } else if bypass_compile_time_feature_checks {
                println!("cargo:warning=You have bypassed the libcoap-sys compile-time feature check.")
            }
        },
        None => {
            println!("cargo:warning=The used build system for libcoap-sys does not support compile-time feature checks. Missing features may therefore only be detected during runtime.");
        },
    }

    Ok(())
}

fn link_libcoap_explicit(
    requested_build_system: &str,
    target_os: &str,
    out_dir: PathBuf,
    requested_features: EnumSet<LibcoapFeature>,
    requested_dtls_backend: Option<DtlsBackend>,
    bypass_compile_time_feature_checks: bool,
) -> Result<Box<dyn BuildSystem>> {
    match requested_build_system {
        "vendored" if target_os == "espidf" => {
            EspIdfBuildSystem::new(out_dir, requested_features, requested_dtls_backend, bypass_compile_time_feature_checks).map(|v| Box::<dyn BuildSystem>::from(Box::new(v)))
        },
        "vendored" if cfg!(not(feature = "vendored")) => Err(anyhow!("LIBCOAP_RS_BUILD_SYSTEM has been set to \"vendored\", but the corresponding crate feature \"vendored\" has not been enabled.")),
        "vendored" => VendoredBuildSystem::build_libcoap(out_dir, requested_features, requested_dtls_backend)
            .map(|v| Box::<dyn BuildSystem>::from(Box::new(v))),
        "pkgconfig" if target_os != "espidf" => {
            PkgConfigBuildSystem::link_with_libcoap(out_dir, requested_dtls_backend)
                .map(|v| Box::<dyn BuildSystem>::from(Box::new(v)))
        },
        "manual" => ManualBuildSystem::link_with_libcoap(out_dir, requested_dtls_backend).map(|v| Box::<dyn BuildSystem>::from(Box::new(v))),
        v => Err(anyhow!("build system {v} is unknown or unsupported for this target")),
    }
    .context(format!(
        "unable to link libcoap using force-configured build system {requested_build_system}"
    ))
}

fn vendored_libcoap_build(
    target_os: &str,
    out_dir: PathBuf,
    requested_features: EnumSet<LibcoapFeature>,
    requested_dtls_backend: Option<DtlsBackend>,
    bypass_compile_time_feature_checks: bool,
) -> Result<Box<dyn BuildSystem>> {
    // TODO: Later on, we'll probably want to use the CMake based build system for any host+target
    //       combination that the libcoap build documentation recommends CMake for (most notably:
    //       Windows).
    //       See: https://github.com/obgm/libcoap/blob/develop/BUILDING
    match target_os {
        "espidf" => EspIdfBuildSystem::new(
            out_dir,
            requested_features,
            requested_dtls_backend,
            bypass_compile_time_feature_checks,
        )
        .map(|v| Box::<dyn BuildSystem>::from(Box::new(v))),
        _ => VendoredBuildSystem::build_libcoap(out_dir, requested_features, requested_dtls_backend)
            .map(|v| Box::<dyn BuildSystem>::from(Box::new(v))),
    }
}

fn link_libcoap_auto(
    target_os: &str,
    out_dir: PathBuf,
    requested_features: EnumSet<LibcoapFeature>,
    requested_dtls_backend: Option<DtlsBackend>,
    bypass_compile_time_feature_checks: bool,
) -> Result<Box<dyn BuildSystem>> {
    let mut errors = Vec::<(&'static str, anyhow::Error)>::new();
    // Try vendored build first if the feature is enabled and supported by the host.
    // If the vendored build fails on a supported target, do not try anything else (we assume that
    // the user wanted to use the vendored library for a reason).
    if cfg!(feature = "vendored") || target_os == "espidf" {
        return vendored_libcoap_build(
            target_os,
            out_dir,
            requested_features,
            requested_dtls_backend,
            bypass_compile_time_feature_checks,
        );
    }
    PkgConfigBuildSystem::link_with_libcoap(out_dir.clone(), requested_dtls_backend)
        .map(|v| Box::<dyn BuildSystem>::from(Box::new(v)))
        .or_else(|e| {
            errors.push(("pkgconfig", e));
            ManualBuildSystem::link_with_libcoap(out_dir, requested_dtls_backend)
                .map(|v| Box::<dyn BuildSystem>::from(Box::new(v)))
        })
        .map_err(|e| {
            errors.push(("manual", e));
            anyhow!(
                "unable to find a version of libcoap to link with:\n{}",
                errors
                    .iter()
                    .map(|(k, v)| format!("Build system {k} failed with error: {v:?}"))
                    .collect::<Vec<String>>()
                    .join("\n")
            )
        })
}

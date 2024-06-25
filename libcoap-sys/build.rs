// SPDX-License-Identifier: BSD-2-CLAUSE
/*
 * build.rs - build script for libcoap Rust bindings.
 * This file is part of the libcoap-sys crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::{
    default::Default,
    env,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt::{Debug, Formatter};
use bindgen::callbacks::{IntKind, ParseCallbacks};

use bindgen::EnumVariation;
use pkg_config::probe_library;
use version_compare::{Cmp, Version};

#[derive(Debug, Default)]
pub struct CoapConfigMacroParser {
    version: RefCell<String>,
}

impl ParseCallbacks for CoapConfigMacroParser {
    fn int_macro(&self, _name: &str, _value: i64) -> Option<IntKind> {
        None
    }

    fn str_macro(&self, name: &str, value: &[u8]) {
        match name {
            "PACKAGE_VERSION" => {
                let version_str = String::from_utf8_lossy(value);
                println!("cargo:rustc-cfg=libcoap_version=\"{}\"", version_str.as_ref());
                let version = Version::from(version_str.as_ref()).unwrap();
                match version.compare(Version::from("4.3.4").unwrap()) {
                    Cmp::Lt | Cmp::Eq => println!("cargo:rustc-cfg=inlined_coap_send_rst"),
                    _ => {}
                }
                self.version.replace(version.to_string());
            },
            _ => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DtlsBackend {
    GnuTls,
    OpenSsl,
    MbedTls,
    TinyDtls,
}
impl ToString for DtlsBackend {
    fn to_string(&self) -> String {
        match self {
            DtlsBackend::GnuTls => "gnutls",
            DtlsBackend::OpenSsl => "openssl",
            DtlsBackend::MbedTls => "mbedtls",
            DtlsBackend::TinyDtls => "tinydtls",
        }
        .to_string()
    }
}

fn get_builder_espidf() -> bindgen::Builder {
        embuild::espidf::sysenv::output();
        let esp_idf_path = embuild::espidf::sysenv::idf_path().ok_or("missing IDF path").unwrap();
        let esp_idf_buildroot  = env::var("DEP_ESP_IDF_ROOT").unwrap();
        let esp_include_path = embuild::espidf::sysenv::cincl_args().ok_or("missing IDF cincl args").unwrap();
        let embuild_env = embuild::espidf::sysenv::env_path().ok_or("missing IDF env path").unwrap();
        let esp_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let cfg_flags = embuild::espidf::sysenv::cfg_args().ok_or("missing cfg flags from IDF").unwrap();
        
        // Determine compiler path
        unsafe {env::set_var("PATH", embuild_env)};
        let cmake_info = embuild::cmake::Query::new(
            &Path::new(&esp_idf_buildroot).join("build"),
            "cargo",
            &[embuild::cmake::file_api::ObjKind::Codemodel, embuild::cmake::file_api::ObjKind::Toolchains, embuild::cmake::file_api::ObjKind::Cache],
        ).unwrap().get_replies().unwrap();
        let compiler = cmake_info
            .get_toolchains().map_err(|_e| "Can't get toolchains")
            .and_then(|mut t| {
                t.take(embuild::cmake::file_api::codemodel::Language::C)
                    .ok_or("No C toolchain")
            })
            .and_then(|t| {
                t.compiler
                    .path
                    .ok_or("No compiler path set")
            }).unwrap();

        // Parse include arguments
        let arg_splitter = regex::Regex::new(r##"(?:[^\\]"[^"]*[^\\]")?(\s)"##).unwrap();
        let apostrophe_remover = regex::Regex::new(r##"^"(?<content>.*)"$"##).unwrap();
        let esp_clang_args = arg_splitter.split(
            esp_include_path.args.as_str()
        ).map(|x| apostrophe_remover.replace(x.trim(), "$content").to_string()).collect::<Vec<String>>();
        let bindgen_builder = embuild::bindgen::Factory {
            clang_args: esp_clang_args.clone(),
            linker: Some(compiler),
            mcu: None,
            force_cpp: false,
            sysroot: None
        }.builder().unwrap();

        let clang_target = if esp_arch.starts_with("riscv32") {"riscv32"} else {esp_arch.as_str()};
        let short_target = if esp_arch.starts_with("riscv32") {"riscv"} else {esp_arch.as_str()};
        let target_mcu = if cfg_flags.get("esp32").is_some() {"esp32"}
            else if cfg_flags.get("esp32s2").is_some() { "esp32s2" }
            else if cfg_flags.get("esp32s3").is_some() { "esp32s3" }
            else if cfg_flags.get("esp32c3").is_some() { "esp32c3" }
            else if cfg_flags.get("esp32c2").is_some() { "esp32c2" }
            else if cfg_flags.get("esp32h2").is_some() { "esp32h2" }
            else if cfg_flags.get("esp32c5").is_some() { "esp32c5" }
            else if cfg_flags.get("esp32c6").is_some() { "esp32c6" }
            else if cfg_flags.get("esp32p4").is_some() { "esp32p4" }
            else {panic!("unknown ESP target MCU, please add target to libcoap-sys build.rs file!")};
        
        bindgen_builder
            .clang_args(&esp_clang_args)
            .clang_arg("-target")
            .clang_arg(clang_target)
            .clang_arg("-DESP_PLATFORM")
            .clang_arg("-DLWIP_IPV4=1")
            .clang_arg("-DLWIP_IPV6=1")
            .clang_arg(format!("-I{}/components/lwip/lwip/src/include", esp_idf_path))
            .clang_arg(format!("-I{}/components/lwip/port/freertos/include", esp_idf_path))
            .clang_arg(format!("-I{}/components/esp_system/include", esp_idf_path))
            .clang_arg(format!("-I{}/components/freertos/esp_additions/include", esp_idf_path))
            .clang_arg(format!("-I{}/components/freertos/esp_additions/include/freertos", esp_idf_path))
            .clang_arg(format!("-I{}/components/freertos/esp_additions/arch/{}/include", esp_idf_path, short_target)) // for older espidf
            .clang_arg(format!("-I{}/components/freertos/config/{}/include", esp_idf_path, short_target)) // for newer espidf
            .clang_arg(format!("-I{}/components/{}/include", esp_idf_path, short_target))
            .clang_arg(format!("-I{}/components/freertos/FreeRTOS-Kernel-SMP/include", esp_idf_path))
            .clang_arg(format!("-I{}/components/freertos/FreeRTOS-Kernel-SMP/portable/{}/include/freertos", esp_idf_path, short_target))
            .clang_arg(format!("-I{}/components/soc/{}/include", esp_idf_path, target_mcu))
            .clang_arg(format!("-I{}/components/heap/include", esp_idf_path))
            .clang_arg(format!("-I{}/components/esp_rom/include", esp_idf_path))
            .clang_arg(format!("-I{}/managed_components/espressif__coap/libcoap/include", esp_idf_buildroot))
            .clang_arg(format!("-I{}/build/config/", esp_idf_buildroot))
            .allowlist_type("epoll_event")
}

fn get_builder() -> bindgen::Builder {
    bindgen::Builder::default()
        .blocklist_type("epoll_event")
}

fn main() {
    println!("cargo:rerun-if-changed=src/libcoap/");
    println!("cargo:rerun-if-changed=src/wrapper.h");
    // Read required environment variables.
    let orig_pkg_config = std::env::var_os("PKG_CONFIG_PATH").map(|v| String::from(v.to_str().unwrap()));
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    let mut bindgen_builder = match target_os.as_str() {
        "espidf" => get_builder_espidf(),
        _ => get_builder()
    };

    

    let mut dtls_backend = Option::None;
    if cfg!(feature = "dtls") {
        // We can only select one TLS backend at a time for libcoap, but cargo does not support mutually
        // exclusive features, and it would be really bad if a project that uses multiple dependencies
        // which depend on different TLS backends would not compile.
        // Therefore, if multiple TLS backend features are enabled, we choose one based on the following
        // priority order: gnutls > openssl > mbedtls > tinydtls, matching the order specified in
        // https://github.com/obgm/libcoap/blob/develop/configure.ac#L494
        let mut multiple_backends = false;
        if cfg!(feature = "dtls_backend_tinydtls") {
            dtls_backend = Some(DtlsBackend::TinyDtls);
        }
        if cfg!(feature = "dtls_backend_mbedtls") {
            if dtls_backend.is_some() {
                multiple_backends = true;
            }
            println!("cargo:rerun-if-env-changed=MBEDTLS_LIBRARY_PATH");
            dtls_backend = Some(DtlsBackend::MbedTls);
        }
        if cfg!(feature = "dtls_backend_openssl") {
            if dtls_backend.is_some() {
                multiple_backends = true;
            }
            dtls_backend = Some(DtlsBackend::OpenSsl);
        }
        if cfg!(feature = "dtls_backend_gnutls") {
            if dtls_backend.is_some() {
                multiple_backends = true;
            }
            dtls_backend = Some(DtlsBackend::GnuTls);
        }
        if multiple_backends {
            println!("cargo:warning=Multiple DTLS backends enabled for libcoap-sys. Only one can be enabled, choosing {:?} as the backend to use. This can cause problems.", dtls_backend.as_ref().unwrap());
        }
        if dtls_backend.is_none() {
            println!("cargo:warning=No DTLS backend selected for libcoap-sys, aborting build.");
            panic!("No DTLS backend selected for libcoap-sys, aborting build")
        }
    }

    // Build vendored library if feature was set.
    if cfg!(feature = "vendored") && target_os.as_str() != "espidf" {
        let libcoap_src_dir = Path::new(&out_dir).join("libcoap");

        // Even though libcoap supports out-of-source builds, autogen.sh (or the corresponding
        // autotools) modify files in the source tree, which causes verification problems when
        // running cargo package.
        // Therefore, we copy the libcoap source over to the output directory and build from there.
        let copy_options = fs_extra::dir::CopyOptions {
            overwrite: true,
            ..Default::default()
        };
        match std::fs::remove_dir_all(&libcoap_src_dir) {
            Ok(_) => {},
            Err(e) if e.kind() == ErrorKind::NotFound => {},
            e => e.unwrap(),
        }
        fs_extra::dir::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("libcoap"),
            Path::new(&out_dir),
            &copy_options,
        )
        .unwrap();
        let current_dir_backup = env::current_dir().unwrap();
        env::set_current_dir(&libcoap_src_dir).expect("unable to change to libcoap build dir");
        Command::new(libcoap_src_dir.join("autogen.sh")).status().unwrap();
        let mut build_config = autotools::Config::new(&libcoap_src_dir);
        build_config.out_dir(&out_dir);
        if let Some(dtls_backend) = dtls_backend {
            build_config
                .enable("dtls", None)
                .with(dtls_backend.to_string().as_str(), None);

            // If DTLS is vendored we need to tell libcoap about the vendored version
            match dtls_backend {
                DtlsBackend::TinyDtls => {
                    // We do not ship tinydtls with our source distribution. Instead, we use tinydtls-sys.
                    build_config.without("submodule-tinydtls", None);

                    // If tinydtls-sys is built with the vendored feature, the library is built alongside
                    // the Rust crate. To use the version built by the tinydtls-sys build script, we use the
                    // environment variables set by the build script.
                    if let Some(tinydtls_include) = env::var_os("DEP_TINYDTLS_INCLUDE") {
                        build_config.env(
                            "TinyDTLS_CFLAGS",
                            format!(
                                "-I{} -I{}",
                                tinydtls_include.to_str().unwrap(),
                                Path::new(tinydtls_include.to_str().unwrap())
                                    .join("tinydtls")
                                    .to_str()
                                    .unwrap()
                            ),
                        );
                    };

                    if let Some(tinydtls_libs) = env::var_os("DEP_TINYDTLS_LIBS") {
                        build_config.env("TinyDTLS_LIBS", format!("-L{}", tinydtls_libs.to_str().unwrap()));

                        build_config.env(
                            "PKG_CONFIG_PATH",
                            Path::new(tinydtls_libs.as_os_str())
                                .join("lib")
                                .join("pkgconfig")
                                .into_os_string(),
                        );
                    }
                },
                DtlsBackend::OpenSsl => {
                    // Set include path according to the path provided by openssl-sys (relevant if
                    // openssl-sys is vendored)
                    if let Some(openssl_include) = env::var_os("DEP_OPENSSL_INCLUDE") {
                        build_config.env("OpenSSL_CFLAGS", format!("-I{}", openssl_include.to_str().unwrap()));
                        build_config.env(
                            "PKG_CONFIG_PATH",
                            Path::new(openssl_include.as_os_str())
                                .parent()
                                .unwrap()
                                .join("lib")
                                .join("pkgconfig")
                                .into_os_string(),
                        );
                    }
                },
                DtlsBackend::MbedTls => {
                    // Set include path according to the path provided by mbedtls-sys (relevant if
                    // mbedtls-sys is vendored).
                    // libcoap doesn't support overriding the MbedTLS CFLAGS, but doesn't set those
                    // either, so we just set CFLAGS and hope they propagate.
                    if let Some(mbedtls_include) = env::var_os("DEP_MBEDTLS_INCLUDE") {
                        let mbedtls_library_path = Path::new(env::var_os("DEP_MBEDTLS_CONFIG_H").unwrap().as_os_str())
                            .parent()
                            .unwrap()
                            .join("build")
                            .join("library");
                        build_config.env("MbedTLS_CFLAGS", format!("-I{}", mbedtls_include.to_str().unwrap()));
                        build_config.env("MbedTLS_LIBS", format!("-lmbedtls -lmbedcrypto -lmbedx509 -L{}", mbedtls_library_path.to_str().unwrap()));
                    } else {
                        // If we're not vendoring mbedtls, allow manually setting the mbedtls
                        // library path (required if linking statically, which is always the case
                        // when vendoring libcoap).
                        if let Some(mbedtls_lib_path) = env::var_os("MBEDTLS_LIBRARY_PATH") {
                            build_config.env("MbedTLS_LIBS", format!("-lmbedtls -lmbedcrypto -lmbedx509 -L{}", mbedtls_lib_path.to_str().unwrap()));
                            if let Some(mbedtls_include_path) = env::var_os("MBEDTLS_INCLUDE_PATH") {
                                build_config.env("MbedTLS_CFLAGS", format!("-I{}", mbedtls_include_path.to_str().unwrap()));
                            }
                        } else {
                            // mbedtls will get pkg-config support in the near future, prepare for that
                            if let Ok(lib) = &pkg_config::Config::new().cargo_metadata(false).probe("mbedtls") {
                                let mut lib_flags = "-lmbedtls -lmbedcrypto -lmbedx509".to_string();
                                lib_flags.push_str(lib.link_paths.iter().map(|x| format!("-L{} ", x.display())).collect::<String>().as_str());
                                build_config.env("MbedTLS_LIBS", lib_flags);
                                build_config.env("MbedTLS_CFLAGS", lib.link_paths.iter().map(|x| format!("-I{}", x.display())).collect::<String>());
                            } else {
                                println!("cargo:warning=You have enabled libcoap vendoring with mbedtls, but haven't provided a static library path for mbedtls (MBEDTLS_LIBRARY_PATH environment variable is unset). Building might fail because of that.");
                            }
                        }
                    }
                },
                DtlsBackend::GnuTls => {
                    // Vendoring not supported                
                },
            }
        } else {
            build_config.disable("dtls", None);
        }
        build_config
            // Set Makeflags
            //.make_args(make_flags)
            // Disable shared library compilation because the vendored library will always be
            // statically linked
            .disable("shared", None)
            // Disable any documentation for vendored C library
            .disable("documentation", None)
            .disable("doxygen", None)
            .disable("manpages", None)
            // This would install the license into the documentation directory, but we don't use the
            // generated documentation anywhere.
            .disable("license-install", None)
            // Disable tests and examples as well as test coverage
            .disable("tests", None)
            .disable("examples", None)
            .disable("gcov", None)
            // TODO allow multithreaded access
            .disable("thread-safe", None);

        // Enable debug symbols if enabled in Rust
        match std::env::var_os("DEBUG").unwrap().to_str().unwrap() {
            "0" | "false" => {},
            _ => {
                build_config.with("debug", None);
            },
        }

        // Enable dependency features based on selected cargo features.
        build_config
            .enable("async", Some(if cfg!(feature = "async") { "yes" } else { "no" }))
            .enable("tcp", Some(if cfg!(feature = "tcp") { "yes" } else { "no" }))
            .enable("server-mode", Some(if cfg!(feature = "server") { "yes" } else { "no" }))
            .enable("client-mode", Some(if cfg!(feature = "client") { "yes" } else { "no" }))
            .with("epoll", Some(if cfg!(feature = "epoll") { "yes" } else { "no" }));

        // Run build
        let dst = build_config.build();

        std::fs::copy(dst.join("build").join("coap_config.h"), dst.join("include").join("coap_config.h")).unwrap();

        // Add the built library to the search path
        println!("cargo:rustc-link-search=native={}", dst.join("lib").to_str().unwrap());
        println!("cargo:include={}", dst.join("include").to_str().unwrap());
        bindgen_builder = bindgen_builder
            .clang_arg(format!("-I{}", dst.join("include").to_str().unwrap()))
            .clang_arg(format!("-L{}", dst.join("lib").to_str().unwrap()));
        unsafe {
            env::set_var(
                "PKG_CONFIG_PATH",
                format!(
                    "{}:{}",
                    dst.join("lib").join("pkgconfig").to_str().unwrap(),
                    orig_pkg_config.as_ref().map(String::clone).unwrap_or_else(String::new)
                ),
            );
        }
        env::set_current_dir(current_dir_backup).expect("unable to switch back to source dir");
    }

    if target_os.as_str() != "espidf" {
        // Tell cargo to link libcoap.
        println!(
            "cargo:rustc-link-lib={}{}",
            cfg!(feature = "static").then(|| "static=").unwrap_or("dylib="),
            format!(
                "coap-3-{}",
                &dtls_backend
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "notls".to_string())
            )
            .as_str()
        );

        // For the DTLS libraries, we need to tell cargo which external libraries to link.
        // Note that these linker instructions have to be added *after* the linker instruction
        // for libcoap itself, as some linkers require dependencies to be in reverse order.
        if let Some(dtls_backend) = dtls_backend {
            match dtls_backend {
                DtlsBackend::TinyDtls => {
                    // Handled by tinydtls-sys
                },
                DtlsBackend::OpenSsl => {
                    // Handled by openssl-sys
                },
                DtlsBackend::MbedTls => {
                    // If mbedtls is vendored, mbedtls-sys-auto already takes care of linking.
                    if env::var_os("DEP_MBEDTLS_INCLUDE").is_none() {
                        // We aren't using mbedtls-sys-auto if we aren't vendoring (as it doesn't support
                        // mbedtls >= 3.0.0), so we need to tell cargo to link to mbedtls ourselves.

                        if let Some(mbedtls_lib_path) = env::var_os("MBEDTLS_LIBRARY_PATH") {
                            println!("cargo:rustc-link-search=native={}", mbedtls_lib_path.to_str().unwrap())
                        }
                        // Try to find mbedtls using pkg-config, will emit cargo link statements if successful
                        if env::var_os("MBEDTLS_LIBRARY_PATH").is_some() || pkg_config::Config::new().statik(cfg!(feature = "static")).probe("mbedtls").is_err() {
                            // couldn't find using pkg-config or MBEDTLS_LIBRARY_PATH was set, just try
                            // linking with given library search path
                            println!("cargo:rustc-link-lib={}mbedtls",
                                     cfg!(feature = "static").then(|| "static=").unwrap_or("dylib=")
                            );
                            println!("cargo:rustc-link-lib={}mbedx509",
                                     cfg!(feature = "static").then(|| "static=").unwrap_or("dylib=")
                            );
                            println!("cargo:rustc-link-lib={}mbedcrypto",
                                     cfg!(feature = "static").then(|| "static=").unwrap_or("dylib=")
                            );
                        }
                    }
                },
                DtlsBackend::GnuTls => {
                    // gnutls-sys is unmaintained, so we need to link to gnutls ourselves.

                    // try pkg-config
                    if probe_library("gnutls").is_err() {
                        // if that doesn't work, try using the standard library search path.
                        println!("cargo:rustc-link-lib=gnutls")
                    }
                },
            }
        }
    }

    let cfg_info = Box::new(CoapConfigMacroParser::default());

    bindgen_builder = bindgen_builder
        .header("src/wrapper.h")
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        .rustfmt_bindings(false)
        // Causes invalid syntax for some reason, so we have to disable it.
        .generate_comments(false)
        .dynamic_link_require_all(true)
        .allowlist_function("(oscore|coap)_.*")
        .allowlist_type("(oscore|coap)_.*")
        .allowlist_var("(oscore|coap)_.*")
        .allowlist_function("(OSCORE|COAP)_.*")
        .allowlist_type("(OSCORE|COAP)_.*")
        .allowlist_var("(OSCORE|COAP)_.*")
        .allowlist_file(r".*\/coap_config.h")
        // We use the definitions made by the libc crate instead
        .blocklist_type("sockaddr(_in|_in6)?")
        .blocklist_type("in6?_(addr|port)(_t)?")
        .blocklist_type("in6_addr__bindgen_ty_1")
        .blocklist_type("(__)?socklen_t")
        .blocklist_type("fd_set")
        .blocklist_type("sa_family_t")
        .blocklist_type("(__)?time_t")
        .blocklist_type("__fd_mask")
        // Are generated because they are typedef-ed inside of the C headers, blocklisting them
        // will instead replace them with the appropriate rust types.
        // See https://github.com/rust-lang/rust-bindgen/issues/1215 for an open issue concerning
        // this problem.
        .blocklist_type("__(u)?int(8|16|32|64|128)_t")
        .size_t_is_usize(true)
        .parse_callbacks(cfg_info);
    if !cfg!(feature = "vendored") {
        // Triggers a rebuild on every cargo build invocation if used for the vendored version, as
        // the included headers seem to come from our built version.
        // Should be fine though, as we already printed `cargo:rerun-if-changed=src/libcoap/` at the
        // start of the file.
        bindgen_builder = bindgen_builder.parse_callbacks(Box::new(bindgen::CargoCallbacks));
    }
    let bindings = bindgen_builder.generate().unwrap();

    let out_path = PathBuf::from(out_dir);
    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();

    unsafe {
        match orig_pkg_config.as_ref() {
            Some(value) => env::set_var("PKG_CONFIG_PATH", value),
            None => env::remove_var("PKG_CONFIG_PATH"),
        }
    }
}

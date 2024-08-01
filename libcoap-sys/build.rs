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
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt::{Debug, Display};
use std::rc::Rc;

use bindgen::callbacks::{IntKind, ParseCallbacks};
use bindgen::EnumVariation;
use pkg_config::probe_library;
use version_compare::{Cmp, Version};

/// Features whose availability can be checked during compile time based on defines.
const COMPILE_TIME_FEATURE_CHECKS: [&str; 16] = [
    "af-unix",
    "async",
    "client",
    "small-stack",
    "tcp",
    "epoll",
    "ipv4",
    "ipv6",
    "oscore",
    "q-block",
    "server",
    "thread-recursive-lock-detection",
    "thread-safe",
    "dtls",
    "observe-persist",
    "websockets",
];

/// Data structure describing meta-information about the used version of libcoap.
#[derive(Debug)]
struct LibcoapMetadata {
    package_version: String,
    version: i64,
    feature_defines_available: bool,
    feature_defines: BTreeSet<String>,
    dtls_backend: Option<DtlsBackend>,
}

impl Default for LibcoapMetadata {
    fn default() -> Self {
        Self {
            package_version: Default::default(),
            version: 0,
            feature_defines_available: false,
            // COAP_DISABLE_TCP is set if TCP is _not_ supported, assume it is supported otherwise.
            feature_defines: BTreeSet::from(["tcp".to_string()]),
            dtls_backend: None,
        }
    }
}

/// Implementation of bindgen's [ParseCallbacks] that allow reading some metainformation about the
/// used libcoap version from its defines (package version, supported features, ...)
#[derive(Debug, Default)]
struct CoapDefineParser {
    defines: Rc<RefCell<LibcoapMetadata>>,
}

impl ParseCallbacks for CoapDefineParser {
    fn int_macro(&self, name: &str, value: i64) -> Option<IntKind> {
        match name {
            "LIBCOAP_VERSION" => {
                self.defines.borrow_mut().version = value;
            },
            "COAP_AF_UNIX_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("af-unix".to_string());
            },
            "COAP_ASYNC_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("async".to_string());
            },
            "COAP_CLIENT_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("client".to_string());
            },
            "COAP_CONSTRAINED_STACK" => {
                self.defines
                    .borrow_mut()
                    .feature_defines
                    .insert("small-stack".to_string());
            },
            "COAP_DISABLE_TCP" => {
                if value == 1 {
                    self.defines.borrow_mut().feature_defines.remove("tcp");
                }
            },
            "COAP_EPOLL_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("epoll".to_string());
            },
            "COAP_IPV4_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("ipv4".to_string());
            },
            "COAP_IPV6_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("ipv6".to_string());
            },
            "COAP_OSCORE_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("oscore".to_string());
            },
            "COAP_Q_BLOCK_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("q-block".to_string());
            },
            "COAP_SERVER_SUPPORT" => {
                self.defines.borrow_mut().feature_defines.insert("server".to_string());
            },
            "COAP_THREAD_RECURSIVE_CHECK" => {
                self.defines
                    .borrow_mut()
                    .feature_defines
                    .insert("thread-recursive-lock-detection".to_string());
            },
            "COAP_THREAD_SAFE" => {
                self.defines
                    .borrow_mut()
                    .feature_defines
                    .insert("thread-safe".to_string());
            },
            "COAP_WITH_LIBGNUTLS" => {
                self.defines.borrow_mut().dtls_backend = Some(DtlsBackend::GnuTls);
                self.defines.borrow_mut().feature_defines.insert("dtls".to_string());
            },
            "COAP_WITH_LIBMBEDTLS" => {
                self.defines.borrow_mut().dtls_backend = Some(DtlsBackend::MbedTls);
                self.defines.borrow_mut().feature_defines.insert("dtls".to_string());
            },
            "COAP_WITH_LIBOPENSSL" => {
                self.defines.borrow_mut().dtls_backend = Some(DtlsBackend::OpenSsl);
                self.defines.borrow_mut().feature_defines.insert("dtls".to_string());
            },
            "COAP_WITH_LIBTINYDTLS" => {
                self.defines.borrow_mut().dtls_backend = Some(DtlsBackend::TinyDtls);
                self.defines.borrow_mut().feature_defines.insert("dtls".to_string());
            },
            // TODO as soon as we have wolfSSL support in libcoap-sys
            /*"COAP_WITH_LIBWOLFSSL" => {
                self.defines.borrow_mut().dtls_backend = Some(DtlsBackend::WolfSsl);
                self.defines
                    .borrow_mut()
                    .feature_defines
                    .insert("dtls".to_string());
            },*/
            "COAP_WITH_OBSERVE_PERSIST" => {
                self.defines
                    .borrow_mut()
                    .feature_defines
                    .insert("observe-persist".to_string());
            },
            "COAP_WS_SUPPORT" => {
                self.defines
                    .borrow_mut()
                    .feature_defines
                    .insert("websockets".to_string());
            },
            _ => {},
        }
        None
    }

    fn str_macro(&self, name: &str, value: &[u8]) {
        // Will allow this here, as we might want to add additional cfg flags later on.
        #[allow(clippy::single_match)]
        match name {
            "LIBCOAP_PACKAGE_VERSION" => {
                let version_str = String::from_utf8_lossy(value);
                println!("cargo:rustc-cfg=libcoap_version=\"{}\"", version_str.as_ref());
                println!("cargo:libcoap_version={}", version_str.as_ref());
                let version = Version::from(version_str.as_ref()).expect("invalid libcoap version");
                match version.compare(Version::from("4.3.4").unwrap()) {
                    Cmp::Lt | Cmp::Eq => println!("cargo:rustc-cfg=inlined_coap_send_rst"),
                    _ => {},
                }
                self.defines.borrow_mut().package_version = version.to_string();
            },
            _ => {},
        }
    }

    fn include_file(&self, filename: &str) {
        let header_path = Path::new(filename);
        if header_path.file_name().eq(&Some(OsStr::new("coap_defines.h"))) {
            self.defines.borrow_mut().feature_defines_available = true;
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
impl Display for DtlsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            DtlsBackend::GnuTls => "gnutls",
            DtlsBackend::OpenSsl => "openssl",
            DtlsBackend::MbedTls => "mbedtls",
            DtlsBackend::TinyDtls => "tinydtls",
        }
        .to_string();
        write!(f, "{}", str)
    }
}

fn get_target_mcu() -> &'static str {
    let cfg_flags = embuild::espidf::sysenv::cfg_args().expect("missing cfg flags from IDF");
    let mcus = [
        "esp32", "esp32s2", "esp32s3", "esp32c3", "esp32c2", "esp32h2", "esp32c5", "esp32c6", "esp32p4",
    ];
    for mcu in mcus {
        if cfg_flags.get(mcu).is_some() {
            return mcu;
        }
    }
    panic!("unknown ESP target MCU, please add target to libcoap-sys build.rs file!")
}

fn get_builder_espidf() -> bindgen::Builder {
    embuild::espidf::sysenv::output();
    let esp_idf_path = embuild::espidf::sysenv::idf_path().expect("missing IDF path");
    let esp_idf_buildroot = env::var("DEP_ESP_IDF_ROOT").expect("DEP_ESP_IDF_ROOT is not set");
    let esp_include_path = embuild::espidf::sysenv::cincl_args().expect("missing IDF cincl args");
    let embuild_env = embuild::espidf::sysenv::env_path().expect("missing IDF env path");
    let esp_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH is not set");

    // Determine compiler path
    // SAFETY: Always safe to call in a single-threaded environment (see docs of env::set_var).
    unsafe { env::set_var("PATH", embuild_env) };
    let cmake_info = embuild::cmake::Query::new(
        &Path::new(&esp_idf_buildroot).join("build"),
        "cargo",
        &[
            embuild::cmake::file_api::ObjKind::Codemodel,
            embuild::cmake::file_api::ObjKind::Toolchains,
            embuild::cmake::file_api::ObjKind::Cache,
        ],
    )
    .expect("unable to query cmake API for compiler path")
    .get_replies()
    .expect("unable to get cmake query replies for compiler path");
    let compiler = cmake_info
        .get_toolchains()
        .map_err(|_e| "Can't get toolchains")
        .and_then(|mut t| {
            t.take(embuild::cmake::file_api::codemodel::Language::C)
                .ok_or("No C toolchain")
        })
        .and_then(|t| t.compiler.path.ok_or("No compiler path set"))
        .expect("unable to determine compiler path");

    // Parse include arguments
    // Regexes are correct and never change, therefore it is ok to unwrap here.
    let arg_splitter = regex::Regex::new(r##"(?:[^\\]"[^"]*[^\\]")?(\s)"##).unwrap();
    let apostrophe_remover = regex::Regex::new(r##"^"(?<content>.*)"$"##).unwrap();
    let esp_clang_args = arg_splitter
        .split(esp_include_path.args.as_str())
        .map(|x| apostrophe_remover.replace(x.trim(), "$content").to_string())
        .collect::<Vec<String>>();
    let bindgen_builder = embuild::bindgen::Factory {
        clang_args: esp_clang_args.clone(),
        linker: Some(compiler),
        mcu: None,
        force_cpp: false,
        sysroot: None,
    }
    .builder()
    .expect("unable to create bindgen builder for libcoap bindings from ESP-IDF");

    let clang_target = if esp_arch.starts_with("riscv32") {
        "riscv32"
    } else {
        esp_arch.as_str()
    };
    let short_target = if esp_arch.starts_with("riscv32") {
        "riscv"
    } else {
        esp_arch.as_str()
    };
    let target_mcu = get_target_mcu();

    bindgen_builder
        .clang_args(&esp_clang_args)
        .clang_arg("-target")
        .clang_arg(clang_target)
        .clang_arg("-DESP_PLATFORM")
        .clang_arg("-DLWIP_IPV4=1")
        .clang_arg("-DLWIP_IPV6=1")
        .clang_arg(format!("-I{}/components/newlib/platform_include", esp_idf_path))
        .clang_arg(format!("-I{}/components/lwip/port/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/lwip/port/esp32xx/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/lwip/lwip/src/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/lwip/port/freertos/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/esp_system/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/freertos/config/include/freertos", esp_idf_path))
        .clang_arg(format!("-I{}/components/freertos/esp_additions/include", esp_idf_path))
        .clang_arg(format!(
            "-I{}/components/freertos/esp_additions/include/freertos",
            esp_idf_path
        ))
        .clang_arg(format!(
            "-I{}/components/freertos/esp_additions/arch/{}/include",
            esp_idf_path, short_target
        )) // for older espidf
        .clang_arg(format!(
            "-I{}/components/freertos/config/{}/include",
            esp_idf_path, short_target
        )) // for newer espidf
        .clang_arg(format!("-I{}/components/{}/include", esp_idf_path, short_target))
        .clang_arg(format!("-I{}/components/{}/{}/include", esp_idf_path, short_target, target_mcu))
        .clang_arg(format!("-I{}/components/esp_hw_support/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/esp_common/include", esp_idf_path))
        .clang_arg(format!(
            "-I{}/components/freertos/FreeRTOS-Kernel-SMP/include",
            esp_idf_path
        ))
        .clang_arg(format!(
            "-I{}/components/freertos/FreeRTOS-Kernel-SMP/portable/{}/include/freertos",
            esp_idf_path, short_target
        ))
        .clang_arg(format!("-I{}/components/soc/{}/include", esp_idf_path, target_mcu))
        .clang_arg(format!("-I{}/components/heap/include", esp_idf_path))
        .clang_arg(format!("-I{}/components/esp_rom/include", esp_idf_path))
        .clang_arg(format!(
            "-I{}/managed_components/espressif__coap/port/include",
            esp_idf_buildroot
        ))
        .clang_arg(format!(
            "-I{}/managed_components/espressif__coap/libcoap/include",
            esp_idf_buildroot
        ))
        .clang_arg(format!("-I{}/build/config/", esp_idf_buildroot))
        .allowlist_type("epoll_event")
}

fn get_builder() -> bindgen::Builder {
    bindgen::Builder::default().blocklist_type("epoll_event")
}

fn build_vendored_library(
    out_dir: &OsString,
    dtls_backend: Option<&DtlsBackend>,
    mut builder: bindgen::Builder,
) -> bindgen::Builder {
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
        e => e.expect("unable to clear libcoap build directory"),
    }
    fs_extra::dir::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("libcoap"),
        Path::new(&out_dir),
        &copy_options,
    )
    .expect("unable to prepare libcoap build source directory");
    let current_dir_backup = env::current_dir().expect("unable to get current directory");
    env::set_current_dir(&libcoap_src_dir).expect("unable to change to libcoap build dir");
    Command::new(libcoap_src_dir.join("autogen.sh"))
        .status()
        .expect("unable to execute autogen.sh");
    let mut build_config = autotools::Config::new(&libcoap_src_dir);
    build_config.out_dir(out_dir);
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
                            tinydtls_include
                                .to_str()
                                .expect("DEP_TINYDTLS_INCLUDE is not a valid string"),
                            Path::new(&tinydtls_include)
                                .join("tinydtls")
                                .to_str()
                                .expect("DEP_TINYDTLS_INCLUDE is not a valid string")
                        ),
                    );
                };

                if let Some(tinydtls_libs) = env::var_os("DEP_TINYDTLS_LIBS") {
                    build_config.env(
                        "TinyDTLS_LIBS",
                        format!(
                            "-L{}",
                            tinydtls_libs.to_str().expect("DEP_TINYDTLS_LIBS is invalid string")
                        ),
                    );

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
                    build_config.env(
                        "OpenSSL_CFLAGS",
                        format!(
                            "-I{}",
                            openssl_include.to_str().expect("DEP_OPENSSL_INCLUDE is invalid path")
                        ),
                    );
                    build_config.env(
                        "PKG_CONFIG_PATH",
                        Path::new(openssl_include.as_os_str())
                            .parent()
                            .expect("DEP_OPENSSL_INCLUDE has no parent directory")
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
                    // the config.h of mbedtls-sys-auto is generated separately from all other
                    // includes in the root of mbedtls-sys-auto's OUT_DIR.
                    // In order to let libcoap read use the correct config file, we need to copy
                    // this file into our own OUT_DIR under include/mbedtls/config.h, so that we
                    // can then set OUT_DIR/include as an additional include path.
                    let config_h = env::var_os("DEP_MBEDTLS_CONFIG_H")
                        .expect("DEP_MBEDTLS_INCLUDE is set but DEP_MBEDTLS_CONFIG_H is not");
                    let config_path = Path::new(&config_h);
                    let out_include = Path::new(&out_dir).join("include");
                    std::fs::create_dir_all(out_include.join("mbedtls"))
                        .expect("unable to prepare include directory for mbedtls config.h");
                    std::fs::copy(config_path, out_include.join("mbedtls").join("config.h"))
                        .expect("unable to copy mbedtls config.h to include directory");
                    let mbedtls_library_path = config_path
                        .parent()
                        .expect("DEP_MBEDTLS_CONFIG_H has no parent directory")
                        .join("build")
                        .join("library");
                    build_config.env(
                        "MbedTLS_CFLAGS",
                        format!(
                            "-I{} -I{}",
                            out_include.to_str().expect("OUT_DIR is not a valid string"),
                            mbedtls_include
                                .to_str()
                                .expect("DEP_MBEDTLS_INCLUDE is not a valid string")
                        ),
                    );
                    build_config.env(
                        "MbedTLS_LIBS",
                        format!(
                            "-L{0} -l:libmbedtls.a -l:libmbedcrypto.a -l:libmbedx509.a",
                            mbedtls_library_path
                                .to_str()
                                .expect("DEP_MBEDTLS_CONFIG_H is not a valid string"),
                        ),
                    );
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
        .disable("gcov", None);

    // Enable debug symbols if enabled in Rust
    match env::var_os("DEBUG")
        .expect("env variable DEBUG that should have been set by cargo is not set")
        .to_str()
        .expect("env variable DEBUG is not valid")
    {
        "0" | "false" => {},
        _ => {
            build_config.with("debug", None);
        },
    }
    // Enable dependency features based on selected cargo features.
    build_config
        .enable("oscore", Some(if cfg!(feature = "oscore") { "yes" } else { "no" }))
        .enable("ipv4-support", Some(if cfg!(feature = "ipv4") { "yes" } else { "no" }))
        .enable("ipv6-support", Some(if cfg!(feature = "ipv6") { "yes" } else { "no" }))
        .enable(
            "af-unix-support",
            Some(if cfg!(feature = "af-unix") { "yes" } else { "no" }),
        )
        .enable("tcp", Some(if cfg!(feature = "tcp") { "yes" } else { "no" }))
        .enable(
            "websockets",
            Some(if cfg!(feature = "websockets") { "yes" } else { "no" }),
        )
        .enable("async", Some(if cfg!(feature = "async") { "yes" } else { "no" }))
        .enable(
            "observe-persist",
            Some(if cfg!(feature = "observe-persist") { "yes" } else { "no" }),
        )
        .enable("q-block", Some(if cfg!(feature = "q-block") { "yes" } else { "no" }))
        .enable(
            "thread-safe",
            Some(if cfg!(feature = "thread-safe") { "yes" } else { "no" }),
        )
        .enable(
            "thread-recursive-lock-detection",
            Some(if cfg!(feature = "thread-recursive-lock-detection") {
                "yes"
            } else {
                "no"
            }),
        )
        .enable(
            "small-stack",
            Some(if cfg!(feature = "small-stack") { "yes" } else { "no" }),
        )
        .enable("server-mode", Some(if cfg!(feature = "server") { "yes" } else { "no" }))
        .enable("client-mode", Some(if cfg!(feature = "client") { "yes" } else { "no" }))
        .with("epoll", Some(if cfg!(feature = "epoll") { "yes" } else { "no" }));

    // Run build
    let dst = build_config.build();

    // Add the built library to the search path
    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib")
            .to_str()
            .expect("libcoap build output dir is not a valid string")
    );
    println!(
        "cargo:include={}",
        dst.join("include")
            .to_str()
            .expect("libcoap build output dir is not a valid string")
    );
    builder = builder
        .clang_arg(format!(
            "-I{}",
            dst.join("include")
                .to_str()
                .expect("libcoap build output dir is not a valid string")
        ))
        .clang_arg(format!(
            "-L{}",
            dst.join("lib")
                .to_str()
                .expect("libcoap build output dir is not a valid string")
        ));
    env::set_current_dir(current_dir_backup).expect("unable to switch back to source dir");
    builder
}

fn main() {
    println!("cargo::rustc-check-cfg=cfg(feature_checks_available)");
    println!("cargo::rustc-check-cfg=cfg(inlined_coap_send_rst)");
    println!("cargo:rerun-if-changed=src/libcoap/");
    println!("cargo:rerun-if-changed=src/wrapper.h");
    // Read required environment variables.
    let out_dir = env::var_os("OUT_DIR").expect("unsupported OUT_DIR");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("invalid TARGET_OS environment variable");

    let mut bindgen_builder = match target_os.as_str() {
        "espidf" => get_builder_espidf(),
        _ => get_builder(),
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
            // more than one backend was set, so unwrapping is ok here.
            println!("cargo:warning=Multiple DTLS backends enabled for libcoap-sys. Only one can be enabled, choosing {:?} as the backend to use. This may cause problems.", dtls_backend.as_ref().unwrap());
        }
        if dtls_backend.is_none() {
            println!("cargo:warning=No DTLS backend selected for libcoap-sys, aborting build.");
            panic!("No DTLS backend selected for libcoap-sys, aborting build")
        }
    }

    // Build vendored library if feature was set.
    if cfg!(feature = "vendored") && target_os.as_str() != "espidf" {
        bindgen_builder = build_vendored_library(&out_dir, dtls_backend.as_ref(), bindgen_builder);
    };

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

                        // Try to find mbedtls using pkg-config, will emit cargo link statements if successful
                        if pkg_config::Config::new()
                            .statik(cfg!(feature = "static"))
                            .probe("mbedtls")
                            .is_err()
                        {
                            // couldn't find using pkg-config, just try linking with given library
                            // search path.
                            println!("cargo:rustc-link-lib=mbedtls",);
                            println!("cargo:rustc-link-lib=mbedx509",);
                            println!("cargo:rustc-link-lib=mbedcrypto",);
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

    let libcoap_defines = Rc::new(RefCell::new(LibcoapMetadata::default()));

    let cfg_info = Box::new(CoapDefineParser {
        defines: Rc::clone(&libcoap_defines),
    });

    bindgen_builder = bindgen_builder
        .header("src/wrapper.h")
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        // Causes invalid syntax for some reason, so we have to disable it.
        .generate_comments(false)
        .dynamic_link_require_all(true)
        .allowlist_function("(oscore|coap)_.*")
        .allowlist_type("(oscore|coap)_.*")
        .allowlist_var("(oscore|coap)_.*")
        .allowlist_function("(OSCORE|COAP)_.*")
        .allowlist_type("(OSCORE|COAP)_.*")
        .allowlist_var("(OSCORE|COAP|LIBCOAP)_.*")
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
        bindgen_builder = bindgen_builder.parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    }
    let bindings = bindgen_builder.generate().expect("unable to generate bindings");

    // Check if required features are available in libcoap.
    let libcoap_defines = libcoap_defines.take();
    if libcoap_defines.feature_defines_available {
        println!("cargo:rustc-cfg=feature_checks_available");
        println!(
            "cargo:warning=Available features: {:?}",
            libcoap_defines.feature_defines
        );
        for feature in COMPILE_TIME_FEATURE_CHECKS {
            let feature_env_var_name = "CARGO_FEATURE_".to_string() + &feature.replace('-', "_").to_uppercase();
            if env::var(&feature_env_var_name).is_ok() && !libcoap_defines.feature_defines.contains(feature) {
                panic!("Required feature {feature} is not available in the used version of libcoap!");
            }
        }
        if dtls_backend != libcoap_defines.dtls_backend {
            // Should be fine, as applications should expect that the DTLS library could differ.
            println!("cargo:warning=DTLS library used by libcoap does not match chosen one. This might lead to issues.")
        }
    } else {
        println!("cargo:warning=The used version of libcoap does not provide a coap_defines.h file, either because it is too old (<4.3.5) or because this file is somehow not included. Compile-time feature checks are not available, and the availability of some features (small-stack, IPv4/IPv6,) can not be asserted at all!");
    }

    let out_path = PathBuf::from(out_dir);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("unable to write generated bindings to file");
}

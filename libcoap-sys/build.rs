// SPDX-License-Identifier: BSD-2-CLAUSE
/*
 * build.rs - build script for libcoap Rust bindings.
 * Copyright (c) 2021 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::{
    default::Default,
    env,
    path::{Path, PathBuf},
    process::Command,
};

use bindgen::EnumVariation;

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

fn main() {
    println!("cargo:rerun-if-changed=src/libcoap/");
    println!("cargo:rerun-if-changed=src/wrapper.h");
    let mut pkgconf = pkg_config::Config::new();
    let mut bindgen_builder = bindgen::Builder::default();

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
    if cfg!(feature = "vendored") {
        // Read required environment variables.
        let out_dir = std::env::var_os("OUT_DIR").unwrap();
        // Read Makeflags into vector of strings
        let make_flags = std::env::var_os("CARGO_MAKEFLAGS")
            .unwrap()
            .into_string()
            .unwrap()
            .split(' ')
            .map(String::from)
            .collect();

        // Even though libcoap supports out-of-source builds, autogen.sh (or the corresponding
        // autotools) modify files in the source tree, which causes verification problems when
        // running cargo package.
        // Therefore, we copy the libcoap source over to the output directory and build from there.
        let copy_options = fs_extra::dir::CopyOptions {
            overwrite: true,
            ..Default::default()
        };
        fs_extra::dir::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("libcoap"),
            Path::new(&out_dir),
            &copy_options,
        )
        .unwrap();
        let libcoap_src_dir = Path::new(&out_dir).join("libcoap");
        Command::new(libcoap_src_dir.join("autogen.sh")).status().unwrap();

        let mut build_config = autotools::Config::new(libcoap_src_dir);
        build_config.out_dir(out_dir);
        if dtls_backend.is_some() {
            build_config
                .enable("dtls", None)
                .with(dtls_backend.unwrap().to_string().as_str(), None);

            if dtls_backend == Some(DtlsBackend::TinyDtls) {
                // We do not ship tinydtls with our source distribution. Instead, we use tinydtls-sys.
                build_config.with("system-tinydtls", None);
                build_config.without("vendored-tinydtls", None);
                // If tinydtls-sys is built with the vendored feature, the library is built alongside
                // the Rust crate. To use the version built by the tinydtls-sys build script, we use the
                // environment variables set by the build script.
                if let Some(tinydtls_libs) = env::var_os("DEP_TINYDTLS_LIBS") {
                    build_config.env(
                        "TinyDTLS_LIBS",
                        format!("-L{} -l:libtinydtls.a", tinydtls_libs.to_str().unwrap(),),
                    );
                }
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
                }
            }
        } else {
            build_config.disable("dtls", None);
        }
        build_config
            // Set Makeflags
            .make_args(make_flags)
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
        match std::env::var_os("DEBUG").unwrap().to_str().unwrap() {
            "0" | "false" => {}
            _ => {
                build_config.with("debug", None);
            }
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

        // Add the built library to the search path
        println!("cargo:rustc-link-search=native={}", dst.join("lib").to_str().unwrap());
        println!("cargo:include={}", dst.join("include").to_str().unwrap());
        bindgen_builder = bindgen_builder
            .clang_arg(format!("-I{}", dst.join("include").to_str().unwrap()))
            .clang_arg(format!("-L{}", dst.join("lib").to_str().unwrap()));
        pkgconf.arg(format!(
            "--with-path={}",
            dst.join("lib").join("pkgconfig").to_str().unwrap()
        ));
    }

    pkgconf.statik(cfg!(feature = "static"));
    for link_lib in pkgconf
        .probe(
            format!(
                "libcoap-3-{}",
                &dtls_backend
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "notls".to_string())
            )
            .as_str(),
        )
        .unwrap()
        .libs
    {
        println!(
            "cargo:rustc-link-lib={}{}",
            cfg!(feature = "static").then(|| "static=").unwrap_or(""),
            &link_lib
        );
    }

    bindgen_builder = bindgen_builder
        .header("src/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        .rustfmt_bindings(false)
        // Causes invalid syntax for some reason, so we have to disable it.
        .generate_comments(false)
        .dynamic_link_require_all(true)
        .allowlist_function("coap_.*")
        .allowlist_type("coap_.*")
        .allowlist_var("coap_.*")
        .allowlist_function("COAP_.*")
        .allowlist_type("COAP_.*")
        .allowlist_var("COAP_.*")
        // We use the definitions made by the libc crate instead
        .blocklist_type("sockaddr(_in|_in6)?")
        .blocklist_type("in6?_(addr|port)(_t)?")
        .blocklist_type("epoll_event")
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
        .size_t_is_usize(true);
    let bindings = bindgen_builder.generate().unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();
}

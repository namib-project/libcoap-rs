use std::{env, path::PathBuf, process::Command};

use bindgen::EnumVariation;

#[derive(Debug)]
enum DtlsBackend {
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
    println!("cargo:rerun-if-changed=dep/");
    println!("cargo:rerun-if-changed=libcoap_wrapper.h");
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
        let pkg_dir = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
        let out_dir = std::env::var_os("OUT_DIR").unwrap();
        // Read Makeflags into vector of strings
        let make_flags = std::env::var_os("CARGO_MAKEFLAGS")
            .unwrap()
            .into_string()
            .unwrap()
            .split(" ")
            .map(String::from)
            .collect();
        // Run autogen to create configure-script and Makefile
        //Command::new("./dep/libcoap/autogen.sh")
        //    .arg("--clean")
        //    .status()
        //    .unwrap();
        Command::new("./dep/libcoap/autogen.sh").status().unwrap();
        // Run build for libcoap.
        let mut build_config = autotools::Config::new("./dep/libcoap");

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

        // Enable dependency features based on selected cargo features.
        build_config
            .enable("async", Some(if cfg!(feature = "async") { "yes" } else { "no" }))
            .enable("tcp", Some(if cfg!(feature = "tcp") { "yes" } else { "no" }))
            .enable("server-mode", Some(if cfg!(feature = "server") { "yes" } else { "no" }))
            .enable("client-mode", Some(if cfg!(feature = "client") { "yes" } else { "no" }))
            .with("epoll", Some(if cfg!(feature = "epoll") { "yes" } else { "no" }));

        if cfg!(feature = "dtls") {
            build_config.enable("dtls", None);
            match &dtls_backend {
                // If the dtls feature is enabled we have already checked whether a backend was set.
                None => unreachable!(),
                Some(be) => build_config.with(be.to_string().as_str(), None),
            };
            // TinyDTLS does not like being built out-of-source, while libcoap doesn't like
            // installing its headers into the source directory (which would be the case for
            // in-source builds). Therefore, we apply this really ugly workaround.
            if let Some(DtlsBackend::TinyDtls) = dtls_backend {
                Command::new("mkdir")
                    .arg("-p")
                    .arg(format!("{}/build/ext", out_dir.to_str().unwrap()))
                    .status()
                    .unwrap();
                Command::new("ln")
                    .arg("-s")
                    .arg("--force")
                    .arg(format!("{}/dep/libcoap/ext/tinydtls", pkg_dir.to_str().unwrap()))
                    .arg(format!("{}/build/ext/tinydtls", out_dir.to_str().unwrap()))
                    .status()
                    .unwrap();
            }
        } else {
            build_config.disable("dtls", None);
        }
        // Run build
        let dst = build_config.build();

        // Add the built library to the search path
        println!("cargo:rustc-link-search=native={}/lib", dst.to_str().unwrap());
        println!("cargo:include={}/include", dst.to_str().unwrap());
        //bindgen_builder = bindgen_builder.detect_include_paths(false);
        bindgen_builder = bindgen_builder.clang_arg(format!("-I\"{}/include\"", dst.to_str().unwrap()))
    }

    println!(
        "cargo:rustc-link-lib={}coap-3-{}",
        cfg!(feature = "static").then(|| "static=").unwrap_or(""),
        &dtls_backend
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or("notls".to_string())
    );

    bindgen_builder = bindgen_builder
        .header("libcoap_wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .allowlist_function("coap_.*")
        .allowlist_type("coap_.*")
        .allowlist_var("coap_.*")
        .allowlist_function("COAP_.*")
        .allowlist_type("COAP_.*")
        .allowlist_var("COAP_.*")
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        .rustfmt_bindings(false)
        .dynamic_link_require_all(true);
    let bindings = bindgen_builder.generate().unwrap();

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs")).unwrap();
}

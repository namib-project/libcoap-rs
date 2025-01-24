// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * build/bindings.rs - Binding generation tools for the libcoap-sys build script.
 */

use std::{cell::RefCell, fmt::Debug, path::PathBuf, rc::Rc};

use anyhow::{Context, Result};
use bindgen::callbacks::{DeriveTrait, ImplementsTrait, IntKind, ParseCallbacks};

use crate::metadata::{DtlsBackend, LibcoapDefineInfo, LibcoapFeature};

/// Implementation of bindgen's [ParseCallbacks] that allow reading some meta-information about the
/// used libcoap version from its defines (package version, supported features, ...)
#[derive(Debug, Default)]
pub struct LibcoapDefineParser {
    defines: Rc<RefCell<LibcoapDefineInfo>>,
}

impl LibcoapDefineParser {
    pub fn new() -> (Rc<RefCell<LibcoapDefineInfo>>, Self) {
        let target = std::env::var_os("TARGET").unwrap_or_default();
        let host = std::env::var_os("HOST").unwrap_or_default();

        if target != host {
            println!(concat!(
                "cargo:warning=libcoap-rs compile-time feature checks may be inaccurate when cross",
                " compiling, see https://libcoap.net/doc/reference/4.3.5/man_coap_supported.html",
                " for more information."
            ));
        }

        let value: LibcoapDefineParser = Default::default();
        (Rc::clone(&value.defines), value)
    }
}

impl ParseCallbacks for LibcoapDefineParser {
    fn int_macro(&self, name: &str, value: i64) -> Option<IntKind> {
        let mut defines = self.defines.borrow_mut();
        defines.supported_features |= LibcoapFeature::features_from_define(name, value);
        if let Some(dtls_backend) = DtlsBackend::library_from_define(name, value) {
            if let Some(old_backend) = defines.dtls_backend.replace(dtls_backend) {
                println!("cargo:warning=The libcoap header files indicate that more than one DTLS library is active at the same time ({dtls_backend} and {old_backend}), which should not be possible. Are the header paths misconfigured?");
            }
        }
        None
    }

    fn str_macro(&self, name: &str, value: &[u8]) {
        if name == "LIBCOAP_PACKAGE_VERSION" {
            let version_str = String::from_utf8_lossy(value);
            self.defines.borrow_mut().version = Some(version_str.to_string())
        }
    }
}

#[derive(Debug, Default)]
struct LibcoapBindingHelper;

impl ParseCallbacks for LibcoapBindingHelper {
    // Even if we don't use CargoCallbacks, we want to rebuild if relevant environment variables
    // change.
    fn read_env_var(&self, key: &str) {
        println!("cargo:rerun-if-env-changed={key}")
    }

    fn blocklisted_type_implements_trait(&self, name: &str, derive_trait: DeriveTrait) -> Option<ImplementsTrait> {
        // This is based on what libc reports for Unix-based OSes
        #[cfg(unix)]
        match (name, derive_trait) {
            (
                "struct epoll_event" | "fd_set" | "struct sockaddr_in" | "struct sockaddr_in6" | "struct sockaddr",
                DeriveTrait::Debug | DeriveTrait::Hash | DeriveTrait::PartialEqOrPartialOrd | DeriveTrait::Copy,
            ) => Some(ImplementsTrait::Yes),
            (
                "struct epoll_event" | "fd_set" | "struct sockaddr_in" | "struct sockaddr_in6" | "struct sockaddr",
                DeriveTrait::Default,
            ) => Some(ImplementsTrait::No),
            (
                "time_t" | "socklen_t" | "sa_family_t",
                DeriveTrait::Debug
                | DeriveTrait::Hash
                | DeriveTrait::PartialEqOrPartialOrd
                | DeriveTrait::Copy
                | DeriveTrait::Default,
            ) => Some(ImplementsTrait::Yes),
            (_, _) => None,
        }
        #[cfg(not(unix))]
        // Let's just assume that bindgen's default behavior is fine.
        None
    }
}

pub fn generate_libcoap_bindings(
    bindgen_builder_configurator: impl FnOnce(bindgen::Builder) -> Result<bindgen::Builder>,
    rerun_on_header_file_changes: bool,
) -> Result<bindgen::Bindings> {
    let source_root = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is not set (are we not running as a cargo build script?)"),
    );
    let mut builder = bindgen::Builder::default()
        .header(
            source_root
                .join("src")
                .join("wrapper.h")
                .to_str()
                .context("unable to convert header path to &str")?
                .to_string(),
        )
        .parse_callbacks(Box::new(LibcoapBindingHelper))
        .generate_comments(true)
        .generate_cstr(true)
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
        .blocklist_type("epoll_event")
        // Are generated because they are typedef-ed inside of the C headers, blocklisting them
        // will instead replace them with the appropriate rust types.
        // See https://github.com/rust-lang/rust-bindgen/issues/1215 for an open issue concerning
        // this problem.
        .blocklist_type("__(u)?int(8|16|32|64|128)_t")
        .size_t_is_usize(true);

    // The `rerun_on_header_files()` method only applies to the top level header (in our case
    // src/wrapper.h, so we must not add CargoCallbacks at all if we want to get our desired
    // effect).
    // To still handle environment variable changes properly, LibcoapBindingHeader already includes
    // the relevant parts of CargoCallbacks.
    if rerun_on_header_file_changes {
        builder = builder.parse_callbacks(Box::new(
            bindgen::CargoCallbacks::new().rerun_on_header_files(rerun_on_header_file_changes),
        ))
    }
    builder = bindgen_builder_configurator(builder)?;

    builder.generate().context("unable to generate bindings")
}

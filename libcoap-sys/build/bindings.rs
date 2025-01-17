use std::{cell::RefCell, fmt::Debug, path::PathBuf, rc::Rc};

use anyhow::{Context, Result};
use bindgen::{
    callbacks::{IntKind, ParseCallbacks},
    EnumVariation,
};

use crate::metadata::{LibcoapDefineInfo, LibcoapFeature};

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
            println!("cargo:warning=libcoap-rs compile-time feature checks may be inaccurate when cross compiling, see https://libcoap.net/doc/reference/4.3.5/man_coap_supported.html for more information.");
        }

        let value: LibcoapDefineParser = Default::default();
        (Rc::clone(&value.defines), value)
    }
}

impl ParseCallbacks for LibcoapDefineParser {
    fn int_macro(&self, name: &str, value: i64) -> Option<IntKind> {
        self.defines.borrow_mut().supported_features |= LibcoapFeature::features_from_define(name, value);
        None
    }

    fn str_macro(&self, name: &str, value: &[u8]) {
        /*// Will allow this here, as we might want to add additional cfg flags later on.
        #[allow(clippy::single_match)]
        match name {
            "LIBCOAP_PACKAGE_VERSION" => {
                let version_str = String::from_utf8_lossy(value);
                println!("cargo:rustc-cfg=libcoap_version=\"{}\"", version_str.as_ref());
                println!("cargo:libcoap_version={}", version_str.as_ref());
                let version = Version::from(version_str.as_ref()).expect("invalid libcoap version");
                match version.compare(Version::from("4.3.4").unwrap()) {
                    Cmp::Gt => println!("cargo:rustc-cfg=non_inlined_coap_send_rst"),
                    _ => {},
                }
                self.defines.borrow_mut().package_version = version.to_string();
            },
            _ => {},
        }*/
    }

    fn include_file(&self, filename: &str) {
        /*let header_path = Path::new(filename);
        if header_path.file_name().eq(&Some(OsStr::new("coap_defines.h"))) {
            self.defines.borrow_mut().feature_defines_available = true;
        }*/
    }
}

pub fn generate_libcoap_bindings(
    bindgen_builder_configurator: impl FnOnce(bindgen::Builder) -> Result<bindgen::Builder>,
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
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        // Causes invalid syntax for some reason, so we have to disable it.
        .generate_comments(true)
        .generate_cstr(true)
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
        .blocklist_type("epoll_event")
        // Are generated because they are typedef-ed inside of the C headers, blocklisting them
        // will instead replace them with the appropriate rust types.
        // See https://github.com/rust-lang/rust-bindgen/issues/1215 for an open issue concerning
        // this problem.
        .blocklist_type("__(u)?int(8|16|32|64|128)_t")
        .size_t_is_usize(true);
    builder = bindgen_builder_configurator(builder)?;

    builder.generate().context("unable to generate bindings")
}

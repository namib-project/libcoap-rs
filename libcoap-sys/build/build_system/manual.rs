use std::{cell::RefCell, env, env::VarError, path::PathBuf};

use anyhow::{Context, Result};
use enumset::EnumSet;
use version_compare::Version;

use crate::{
    bindings::{generate_libcoap_bindings, LibcoapDefineParser},
    build_system::BuildSystem,
    metadata::{DtlsBackend, LibcoapDefineInfo, LibcoapFeature},
};

pub struct ManualBuildSystem {
    out_dir: PathBuf,
    include_dirs: Vec<PathBuf>,
    define_info: Option<LibcoapDefineInfo>,
}

impl ManualBuildSystem {
    pub fn link_with_libcoap(out_dir: PathBuf, requested_dtls_backend: Option<DtlsBackend>) -> Result<Self> {
        println!("cargo:rerun-if-env-changed=LIBCOAP_RS_INCLUDE_DIRS");
        println!("cargo:rerun-if-env-changed=LIBCOAP_RS_LIB_DIRS");
        println!("cargo:rerun-if-env-changed=LIBCOAP_RS_STATIC");
        println!("cargo:rerun-if-env-changed=LIBCOAP_RS_ADDITIONAL_LIBRARIES");

        // Parse environment variables.
        let include_dirs: Vec<PathBuf> = env::var("LIBCOAP_RS_INCLUDE_DIRS")
            .context("LIBCOAP_RS_INCLUDE_DIRS has not been set or is not valid unicode")?
            .split(":")
            .map(PathBuf::from)
            .collect();
        let lib_dirs: Vec<PathBuf> = env::var("LIBCOAP_RS_LIB_DIRS")
            .context("LIBCOAP_RS_LIB_DIRS has not been set or is not valid unicode")?
            .split(":")
            .map(PathBuf::from)
            .collect();
        let additional_libraries: Vec<String> = match env::var("LIBCOAP_RS_ADDITIONAL_LIBRARIES") {
            Ok(v) => v.split(":").map(ToString::to_string).collect(),
            Err(VarError::NotPresent) => vec![],
            Err(e) => return Err(e).context("Unable to parse LIBCOAP_RS_ADDITIONAL_LIBRARIES environment variable."),
        };
        let use_static = match env::var("LIBCOAP_RS_STATIC") {
            Ok(v) => !(v == "0" || v.is_empty()),
            Err(VarError::NotPresent) => false,
            Err(e) => return Err(e).context("Unable to parse LIBCOAP_RS_STATIC environment variable."),
        };

        // Determine name of libcoap library.
        let library_name = if let Some(backend) = requested_dtls_backend {
            format!("coap-3-{}", backend.library_suffix())
        } else {
            "coap-3".to_string()
        };

        // Add given library paths to search path.
        for lib_dir in lib_dirs {
            println!("cargo:rustc-link-search={}", lib_dir.display());
        }
        // Instruct rustc to link with the desired version of libcoap.
        println!(
            "cargo:rustc-link-lib={}{}",
            if use_static { "static=" } else { "" },
            library_name
        );

        // Instruct rustc to link with additional libraries (note that this *must* happen *after*
        // linking with libcoap, at least with some linkers).
        for additional_library in additional_libraries {
            println!("cargo:rustc-link-lib={}", additional_library);
        }

        Ok(Self {
            out_dir,
            include_dirs,
            define_info: None,
        })
    }
}

impl BuildSystem for ManualBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        self.define_info.as_ref().map(|v| v.supported_features)
    }

    fn detected_dtls_backend(&self) -> Option<DtlsBackend> {
        self.define_info.as_ref().and_then(|v| v.dtls_backend)
    }

    fn version(&self) -> Option<Version> {
        self.define_info
            .as_ref()
            .and_then(|i| i.version.as_ref().map(|v| Version::from(v.as_str())))
            .expect("unable to parse version string obtained from coap_defines.h")
    }

    fn generate_bindings(&mut self) -> anyhow::Result<PathBuf> {
        let (define_info, define_parser) = LibcoapDefineParser::new();
        let bindings = generate_libcoap_bindings(
            |builder| {
                Ok(builder
                    .parse_callbacks(Box::new(define_parser))
                    // If the pkg-config provided include path coincides with a system include directory,
                    // setting the "-I{}" command line argument will not do anything, potentially resulting
                    // in clang using different CoAP headers than provided by pkg-config, e.g., if there
                    // is an old libcoap in /usr/local/include, but the desired one has its headers in /usr/include.
                    // Therefore, we use `-isystem` instead.
                    // See also: https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-I-dir
                    .clang_args(self.include_dirs.iter().map(|v| format!("-isystem{}", v.display()))))
            },
            true,
        )?;

        self.define_info = Some(RefCell::take(&define_info));

        let out_path = self.out_dir.join("bindings.rs");
        bindings
            .write_to_file(&out_path)
            .context("unable to write bindings to file")?;
        Ok(out_path)
    }
}

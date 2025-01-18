use std::{cell::RefCell, path::PathBuf};

use anyhow::{anyhow, Context};
use enumset::EnumSet;
use pkg_config::Library;
use version_compare::Version;

use crate::{
    bindings::{generate_libcoap_bindings, LibcoapDefineParser},
    build_system::BuildSystem,
    metadata::{DtlsBackend, LibcoapDefineInfo, LibcoapFeature, MINIMUM_LIBCOAP_VERSION},
};

pub struct PkgConfigBuildSystem {
    define_info: Option<LibcoapDefineInfo>,
    out_dir: PathBuf,
    library: Library,
}

impl PkgConfigBuildSystem {
    /// Obtain some built version of libcoap and set the appropriate linker flags to link with it
    /// (and its dependencies, if any).
    pub fn link_with_libcoap(out_dir: PathBuf, requested_dtls_backend: Option<DtlsBackend>) -> anyhow::Result<Self> {
        let mut prober = pkg_config::Config::new();
        let prober = prober
            .atleast_version(MINIMUM_LIBCOAP_VERSION)
            .cargo_metadata(true)
            .env_metadata(true);
        let library = if let Some(requested_dtls_backend) = requested_dtls_backend {
            // Use the libcoap version corresponding to the requested DTLS library, if one has been set.
            prober.probe(&format!("libcoap-3-{}", requested_dtls_backend.library_suffix()))
        } else {
            // Otherwise, use the "default" version.
            prober.probe("libcoap-3")
        };

        library
            .map(|lib| Self {
                out_dir,
                define_info: None,
                library: lib,
            })
            .context("unable to probe library using pkg-config")
    }
}

impl BuildSystem for PkgConfigBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        self.define_info.as_ref().map(|v| v.supported_features)
    }

    fn version(&self) -> Option<Version> {
        Version::from(&self.library.version)
            .map(Some)
            .expect("unable to parse version string obtained from pkg-config")
    }

    fn generate_bindings(&mut self) -> anyhow::Result<PathBuf> {
        let (define_info, define_parser) = LibcoapDefineParser::new();
        let bindings = generate_libcoap_bindings(|builder| {
            Ok(builder
                .parse_callbacks(Box::new(define_parser))
                // If the pkg-config provided include path coincides with a system include directory,
                // setting the "-I{}" command line argument will not do anything, potentially resulting
                // in clang using different CoAP headers than provided by pkg-config, e.g., if there
                // is an old libcoap in /usr/local/include, but the desired one has its headers in /usr/include.
                // Therefore, we use `-isystem` instead.
                // See also: https://clang.llvm.org/docs/ClangCommandLineReference.html#cmdoption-clang-I-dir
                .clang_args(self.library.include_paths.iter().map(|v| format!("-isystem{}", v.display())))
            )
        })?;

        self.define_info = Some(RefCell::take(&define_info));

        if let Some(version) = &self.define_info.as_ref().unwrap().version {
            if Version::from(&self.library.version) != Version::from(version) {
                return Err(anyhow!("The library version indicated by pkg-config does not match the one indicated by the headers. Are the include paths misconfigured?"))
            }
        }

        let out_path = self.out_dir.join("bindings.rs");
        bindings
            .write_to_file(&out_path)
            .context("unable to write bindings to file")?;
        Ok(out_path)
    }
}

use std::cell::RefCell;
use std::env;
use std::env::VarError;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{anyhow, ensure, Context, Result};
use enumset::EnumSet;
use version_compare::Version;
use crate::bindings::{generate_libcoap_bindings, LibcoapDefineParser};
use crate::build_system::BuildSystem;
use crate::metadata::{DtlsBackend, LibcoapDefineInfo, LibcoapFeature};

const VENDORED_LIBCOAP_VERSION: &str = "4.3.5";

pub struct VendoredBuildSystem {
    out_dir: PathBuf,
    define_info: Option<LibcoapDefineInfo>,
    include_paths: Vec<PathBuf>,
}

impl VendoredBuildSystem {
    /// Obtain some built version of libcoap and set the appropriate linker flags to link with it
    /// (and its dependencies, if any).
    pub fn build_libcoap(out_dir: PathBuf, requested_features: EnumSet<LibcoapFeature>, requested_dtls_backend: Option<DtlsBackend>) -> Result<Self> {
        println!("cargo:rerun-if-changed=src/libcoap");

        let libcoap_src_dir = out_dir.join("libcoap");
        let libcoap_build_prefix = out_dir.join("build");

        // Even though libcoap supports out-of-source builds, autogen.sh (or the corresponding
        // autotools) modify files in the source tree, which causes verification problems when
        // running cargo package.
        // Therefore, we copy the libcoap source over to the output directory and build from there.
        let copy_options = fs_extra::dir::CopyOptions {
            overwrite: true,
            ..Default::default()
        };
        std::fs::create_dir_all(&libcoap_src_dir)?;
        std::fs::create_dir_all(&libcoap_build_prefix)?;
        std::fs::remove_dir_all(&libcoap_src_dir).context("unable to clear libcoap build directory")?;
        std::fs::remove_dir_all(&libcoap_build_prefix).context("unable to clear libcoap build directory")?;
        std::fs::create_dir_all(&libcoap_build_prefix)?;
        std::fs::create_dir_all(&libcoap_src_dir)?;
        fs_extra::dir::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("libcoap"),
            &out_dir,
            &copy_options,
        )
            .context("unable to prepare libcoap build source directory")?;

        env::set_current_dir(&libcoap_src_dir).expect("unable to change to libcoap build dir");
        ensure!(Command::new(libcoap_src_dir.join("autogen.sh"))
            .status()
            .context("unable to execute autogen.sh")?.success(), "autogen.sh returned an error code");

        let mut build_config = autotools::Config::new(&libcoap_src_dir);

        let mut build_config = build_config
            // Disable shared library compilation because the vendored library will always be
            // statically linked
            .out_dir(&libcoap_build_prefix)
            .disable("shared", None)
            .enable("static", None)
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
            // We do not include the TinyDTLS submodule in our source distribution, make sure that
            // libcoap doesn't try to use it.
            // This will generate a warning message if TinyDTLS isn't explicitly enabled, but this
            // has no negative consequences.
            .without("submodule-tinydtls", None);

        for feature in requested_features {
            if let Some(feature_flag) = feature.configure_flag_name() {
                build_config = build_config.enable(feature_flag, None);
            }
        }
        for feature in EnumSet::<LibcoapFeature>::all().difference(requested_features) {
            if let Some(feature_flag) = feature.configure_flag_name() {
                build_config = build_config.disable(feature_flag, None);
            }
        }
        let pkg_config_path_bak = env::var_os("PKG_CONFIG_PATH");

        let link_using_pkgconfig = if requested_features.contains(LibcoapFeature::Dtls) {

            // Check if we have any DTLS libraries already added as a Rust dependency.
            // For each one, set the appropriate PKG_CONFIG_PATHs, CFLAGS and/or LIBS to use them
            // instead of system versions if they are going to be used.
            let mut additional_pkg_config_paths: Vec<PathBuf> = vec![];
            // May be unused if none of the DTLS crate features has been enabled.
            #[allow(unused_mut)]
            let mut dtls_libraries_linked_by_other_crates = EnumSet::<DtlsBackend>::empty();
            #[cfg(feature = "dtls-tinydtls-sys")]
            {
                let (pkg_config_path, linked) = Self::configure_tinydtls_sys(build_config)?;
                if let Some(pkg_config_path) = pkg_config_path {
                    additional_pkg_config_paths.push(pkg_config_path)
                }
                if linked {
                    dtls_libraries_linked_by_other_crates |= DtlsBackend::TinyDtls
                }
            }
            #[cfg(feature = "dtls-openssl-sys")]
            {
                let (pkg_config_path, linked) = Self::configure_openssl_sys(build_config)?;
                if let Some(pkg_config_path) = pkg_config_path {
                    additional_pkg_config_paths.push(pkg_config_path)
                }
                if linked {
                    dtls_libraries_linked_by_other_crates |= DtlsBackend::OpenSsl
                }
            }
            #[cfg(feature = "dtls-mbedtls-sys")]
            {
                let (pkg_config_path, linked) = Self::configure_mbedtls_sys(&out_dir, build_config)?;
                if let Some(pkg_config_path) = pkg_config_path {
                    additional_pkg_config_paths.push(pkg_config_path)
                }
                if linked {
                    dtls_libraries_linked_by_other_crates |= DtlsBackend::MbedTls
                }
            }

            // Add libcoap's own build directory to the PKG_CONFIG_PATH (might be used later on to
            // find the generated .pc file to link against libcoap).
            additional_pkg_config_paths.push(libcoap_build_prefix.join("lib").join("pkgconfig"));

            let pkg_config_path = match env::var("PKG_CONFIG_PATH") {
                Ok(v) => { format!("{}:{}", additional_pkg_config_paths.iter().map(|v| v.to_str().ok_or(anyhow!("unable to convert PKG_CONFIG_PATH value to UTF-8"))).collect::<Result<Vec<&str>>>()?.join(":"), v) }
                Err(VarError::NotPresent) => { additional_pkg_config_paths.iter().map(|v| v.to_str().ok_or(anyhow!("unable to convert PKG_CONFIG_PATH value to UTF-8"))).collect::<Result<Vec<&str>>>()?.join(":") },
                Err(e) => Err(e).context("PKG_CONFIG_PATH is not a valid UTF-8 string")?
            };
            build_config.env("PKG_CONFIG_PATH", &pkg_config_path);

            // SAFETY: We are single-threaded here.
            unsafe {
                env::set_var("PKG_CONFIG_PATH", pkg_config_path)
            }

            // Choose a DTLS backend.
            let selected_dtls_backend = if let Some(requested_dtls_backend) = requested_dtls_backend {
                // If one has been explicitly requested by the user, use that one.
                Some(requested_dtls_backend)
            } else if cfg!(feature = "dtls-openssl-sys") {
                // If we do have a library already linked via a rust dependency, prefer those, but
                // maintain the order also used in libcoap itself.
                Some(DtlsBackend::OpenSsl)
            } else if cfg!(feature = "dtls-mbedtls-sys") {
                Some(DtlsBackend::MbedTls)
            } else if cfg!(feature = "dtls-tinydtls-sys") {
                Some(DtlsBackend::TinyDtls)
            } else {
                // Otherwise, we will rely on libcoap to find us a suitable DTLS library.
                None
            };

            // If we are not using one of the DTLS libraries already linked by another rust crate,
            // we need to link the DTLS library as well. Set a boolean variable to keep track of this.
            let dtls_library_already_linked = if let Some(selected_dtls_backend) = selected_dtls_backend {
                build_config = build_config.with(selected_dtls_backend.as_str(), None);
                if dtls_libraries_linked_by_other_crates.contains(selected_dtls_backend) {
                    println!("cargo:rustc-cfg=used_dtls_crate=\"{}\"", selected_dtls_backend.as_str())
                }
                dtls_libraries_linked_by_other_crates.contains(selected_dtls_backend)
            } else {
                false
            };

            !dtls_library_already_linked
        } else {
            false
        };

        build_config.build();

        if link_using_pkgconfig {
            // We need to link both libcoap and its DTLS library. Use the generated pkg-config
            // file to determine how to do this.
            let library = pkg_config::Config::new().statik(true).exactly_version(VENDORED_LIBCOAP_VERSION).probe("libcoap-3").context("unable to link against build version of libcoap using pkg-config (which is necessary if you're not using a Rust dependency to link the DTLS library)")?;

            // SAFETY: We are still single-threaded here.
            unsafe {
                env::set_var("PKG_CONFIG_PATH", pkg_config_path_bak.unwrap_or(OsString::new()))
            }
            Ok(Self {
                out_dir,
                define_info: None,
                include_paths: library.include_paths,
            })
        } else {
            // SAFETY: We are still single-threaded here.
            unsafe {
                env::set_var("PKG_CONFIG_PATH", pkg_config_path_bak.unwrap_or(OsString::new()))
            }
            println!("cargo:rustc-link-search={}", libcoap_build_prefix.join("lib").to_str().context("unable to convert OUT_DIR to a valid UTF-8 string.")?);
            println!("cargo:rustc-link-lib=static=coap-3");
            Ok(Self {
                out_dir,
                define_info: None,
                include_paths: vec![libcoap_build_prefix.join("include")],
            })
        }
    }

    #[cfg(feature = "dtls-tinydtls-sys")]
    fn configure_tinydtls_sys(mut build_config: &mut autotools::Config) -> Result<(Option<PathBuf>, bool)> {
        if env::var_os("TinyDTLS_CFLAGS").is_some() || env::var_os("TinyDTLS_LIBS").is_some() {
            // Do not use tinydtls-sys if the user manually set either the corresponding LIBS or
            // CFLAGS variable.
            // However, do warn the user that this might cause issues.
            println!("cargo:warning=You have enabled the tinydtls-sys dependency, but have overridden either the TinyDTLS_CFLAGS or TinyDTLS_LIBS environment variable used by libcoap to find TinyDTLS.");
            println!("cargo:warning=Note that attempting to link more than one version of the same library at once may cause unexpected issues and/or cryptic compilation errors, especially if both versions are statically linked.");
            Ok((None, false))
        } else {
            let tinydtls_include = env::var_os("DEP_TINYDTLS_INCLUDE").expect("tinydtls-sys dependency has been added, but DEP_TINYDTLS_INCLUDE has not been set");
            let tinydtls_libs = env::var_os("DEP_TINYDTLS_LIBS").expect("tinydtls-sys dependency has been added, but DEP_TINYDTLS_LIBS has not been set");
            build_config = build_config.env("TinyDTLS_CFLAGS",
                                            format!(
                                                "-I{} -I{}",
                                                tinydtls_include
                                                    .to_str()
                                                    .context("DEP_TINYDTLS_INCLUDE path is not a valid UTF-8 string")?,
                                                Path::new(&tinydtls_include)
                                                    .join("tinydtls")
                                                    .to_str()
                                                    .context("DEP_TINYDTLS_INCLUDE path is not a valid UTF-8 string")?
                                            ));

            // Need to set TinyDTLS_LIBS explicitly to force static linking (TinyDTLS also builds a shared version of the library).
            build_config = build_config.env(
                "TinyDTLS_LIBS",
                format!(
                    "-L{} -l:libtinydtls.a",
                    tinydtls_libs.to_str().context("DEP_TINYDTLS_LIBS path is not a valid UTF-8 string")?
                ));

            // Add TinyDTLS's pkg-config directory to the path for version checking.
            Ok((
                Some(PathBuf::from(tinydtls_libs)
                    .join("lib")
                    .join("pkgconfig")), true))
        }
    }

    #[cfg(feature = "dtls-openssl-sys")]
    fn configure_openssl_sys(build_config: &mut autotools::Config) -> Result<(Option<PathBuf>, bool)> {
        if env::var_os("OpenSSL_CFLAGS").is_some() || env::var_os("OpenSSL_LIBS").is_some() {
            // Do not use tinydtls-sys if the user manually set either the corresponding LIBS or
            // CFLAGS variable.
            // However, do warn the user that this might cause issues.
            println!("cargo:warning=You have enabled the openssl-sys dependency, but have overridden either the OpenSSL_CFLAGS or OpenSSL_LIBS environment variable used by libcoap to find OpenSSL.");
            println!("cargo:warning=Note that attempting to link more than one version of the same library at once may cause unexpected issues and/or cryptic compilation errors, especially if both versions are statically linked.");
            Ok((None, false))
        } else {
            let openssl_include = env::var_os("DEP_OPENSSL_INCLUDE").expect("openssl-sys dependency has been added, but DEP_OPENSSL_INCLUDE has not been set");
            let openssl_libs =
                Path::new(openssl_include.as_os_str())
                    .parent()
                    .context("DEP_OPENSSL_INCLUDE has no parent directory")?
                    .join("lib");

            // Just add the OpenSSL directory to the PKG_CONFIG_PATH, that way libcoap will find it.
            Ok((Some(openssl_libs.join("pkgconfig")), true))
        }
    }

    #[cfg(feature = "dtls-mbedtls-sys")]
    fn configure_mbedtls_sys(out_dir: &Path, mut build_config: &mut autotools::Config) -> Result<(Option<PathBuf>, bool)> {
        if env::var_os("MbedTLS_CFLAGS").is_some() || env::var_os("MbedTLS_LIBS").is_some() {
            // Do not use tinydtls-sys if the user manually set either the corresponding LIBS or
            // CFLAGS variable.
            // However, do warn the user that this might cause issues.
            println!("cargo:warning=You have enabled the mbedtls-sys dependency, but have overridden either the MbedTLS_CFLAGS or MbedTLS_LIBS environment variable used by libcoap to find MbedTLS.");
            println!("cargo:warning=Note that attempting to link more than one version of the same library at once may cause unexpected issues and/or cryptic compilation errors, especially if both versions are statically linked.");
            Ok((None, false))
        } else {
            let mbedtls_include = env::var_os("DEP_MBEDTLS_INCLUDE").expect("mbedtls-sys dependency has been added, but DEP_MBEDTLS_INCLUDE has not been set");

            // Can't use pkg-config here, as pkg-config was only added to MbedTLS recently.

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
                .context("unable to prepare include directory for mbedtls config.h")?;
            std::fs::copy(config_path, out_include.join("mbedtls").join("config.h"))
                .context("unable to copy mbedtls config.h to include directory")?;
            let mbedtls_library_path = config_path
                .parent()
                .context("DEP_MBEDTLS_CONFIG_H has no parent directory")?
                .join("build")
                .join("library");

            build_config = build_config.env(
                "MbedTLS_CFLAGS",
                format!(
                    "-I{} -I{}",
                    out_include.to_str().expect("OUT_DIR is not a valid UTF-8 string"),
                    mbedtls_include
                        .to_str()
                        .expect("DEP_MBEDTLS_INCLUDE is not a valid UTF-8 string")
                ),
            );
            build_config = build_config.env(
                "MbedTLS_LIBS",
                format!(
                    "-L{0} -l:libmbedtls.a -l:libmbedcrypto.a -l:libmbedx509.a",
                    mbedtls_library_path
                        .to_str()
                        .expect("DEP_MBEDTLS_CONFIG_H is not a valid string"),
                ),
            );

            // If MbedTLS_CFLAGS and MbedTLS_LIBS are both set, libcoap will fall back to
            // determining the library version using other methods. No need to add to pkg-config
            // path here (as of now).
            Ok((None, true))
        }
    }
}

impl BuildSystem for VendoredBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        self.define_info.as_ref().map(|v| v.supported_features)
    }

    fn version(&self) -> Option<Version> {
        Version::from(VENDORED_LIBCOAP_VERSION)
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
                .clang_args(self.include_paths.iter().map(|v| format!("-isystem{}", v.display())))
            )
        })?;

        self.define_info = Some(RefCell::take(&define_info));

        if let Some(version) = &self.define_info.as_ref().unwrap().version {
            if Version::from(VENDORED_LIBCOAP_VERSION) != Version::from(version) {
                return Err(anyhow!("The library version indicated by the headers does not match the vendored version that should be in use. Are the include paths misconfigured?"))
            }
        }

        let out_path = self.out_dir.join("bindings.rs");
        bindings
            .write_to_file(&out_path)
            .context("unable to write bindings to file")?;
        Ok(out_path)
    }
}

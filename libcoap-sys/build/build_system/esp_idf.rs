use crate::build_system::BuildSystem;
use crate::metadata::{DtlsBackend, LibcoapFeature};
use anyhow::{anyhow, Context, Result};
use enumset::EnumSet;
use std::env;
use std::fs::File;
use std::io::Write;
use std::iter::once;
use std::path::PathBuf;
use syn::{ForeignItem, Ident, Item};
use version_compare::Version;

pub struct EspIdfBuildSystem {
    out_dir: PathBuf,
    esp_idf_bindings_file: PathBuf,
    requested_features: EnumSet<LibcoapFeature>,
}

impl EspIdfBuildSystem {
    pub fn new(
        out_dir: PathBuf,
        requested_features: EnumSet<LibcoapFeature>,
        requested_dtls_backend: Option<DtlsBackend>,
    ) -> Result<Self> {
        embuild::espidf::sysenv::output();
        let esp_idf_bindings_file = env::var_os("DEP_ESP_IDF_ROOT")
            .map(PathBuf::from)
            .expect("Environment variable DEP_ESP_IDF_ROOT has not been set by esp-idf-sys")
            .join("bindings.rs");

        if let Some(backend) = requested_dtls_backend {
            if backend != DtlsBackend::MbedTls {
                return Err(anyhow!("libcoap only supports the MbedTLS DTLS backend when compiling for the ESP-IDF, but you have requested the {backend} backend."));
            }
        }

        Ok(Self {
            out_dir,
            esp_idf_bindings_file,
            requested_features,
        })
    }
}

impl BuildSystem for EspIdfBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        // We ensure the availability of some requested features by generating checks for the
        // cfg values set by esp-idf-sys based on the used sdkconfig.
        // Therefore, we can tell the build script feature checker that all requested features are
        // available (to mute the warning about there being no feature check).

        // However, do warn the user if features are requested that cannot be checked this way, but
        // would be checkable if the defines-based checker was used.
        let uncheckable_features: EnumSet<LibcoapFeature> = self
            .requested_features
            .iter()
            .filter(|v| v.define_name().is_some() && v.sdkconfig_flag_name().is_none())
            .collect();
        if !uncheckable_features.is_empty() {
            println!("cargo:warning=When building for ESP-IDF, the availability of the following requested features that usually can be checked during compile time can only be checked during runtime instead: {}", uncheckable_features.iter().map(|v| v.as_str()).collect::<Vec<&'static str>>().join(", "))
        }

        Some(self.requested_features)
    }

    fn detected_dtls_backend(&self) -> Option<DtlsBackend> {
        // If DTLS is a requested feature, we check during compile time whether MbedTLS is
        // supposed to be enabled.
        self.requested_features
            .contains(LibcoapFeature::Dtls)
            .then_some(DtlsBackend::MbedTls)
    }

    fn version(&self) -> Option<Version> {
        None
    }

    fn generate_bindings(&mut self) -> Result<PathBuf> {
        // Find, read and parse the Rust bindings generated by esp-idf-sys.
        let esp_bindings_file =
            std::fs::read_to_string(&self.esp_idf_bindings_file).context("unable to read ESP-IDF bindings file")?;
        let parsed_esp_bindings_file =
            syn::parse_file(&esp_bindings_file).context("unable to parse ESP-IDF bidnings file")?;

        // Create file for our own bindings.
        let bindings_file_path = self.out_dir.join("bindings.rs");
        let mut libcoap_bindings_file = File::create(&bindings_file_path).context("unable to create bindings file")?;

        // Iterate over all items in the esp-idf-sys bindings file.
        for item in parsed_esp_bindings_file.items {
            // Find the list of identifiers provided by this item.
            let ident: Box<dyn Iterator<Item = Ident>> = match item {
                Item::Const(v) => Box::new(once(v.ident)),
                Item::Enum(v) => Box::new(once(v.ident)),
                Item::ExternCrate(v) => Box::new(once(v.ident)),
                Item::Fn(v) => Box::new(once(v.sig.ident)),
                Item::Macro(v) => Box::new(v.ident.into_iter()),
                Item::Mod(v) => Box::new(once(v.ident)),
                Item::Static(v) => Box::new(once(v.ident)),
                Item::Struct(v) => Box::new(once(v.ident)),
                Item::Trait(v) => Box::new(once(v.ident)),
                Item::TraitAlias(v) => Box::new(once(v.ident)),
                Item::Type(v) => Box::new(once(v.ident)),
                Item::Union(v) => Box::new(once(v.ident)),
                Item::ForeignMod(v) => Box::new(v.items.into_iter().filter_map(|fe| match fe {
                    ForeignItem::Fn(fi) => Some(fi.sig.ident),
                    ForeignItem::Static(fi) => Some(fi.ident),
                    ForeignItem::Type(fi) => Some(fi.ident),
                    _ => None,
                })),
                _ => Box::new(std::iter::empty()),
            };

            for ident in ident.map(|i| i.to_string()) {
                // If the item belongs to the libcoap crate (starts with coap or oscore), re-export it in our bindings.
                if ident.to_lowercase().starts_with("coap") || ident.to_lowercase().starts_with("oscore") {
                    writeln!(&mut libcoap_bindings_file, "pub use esp_idf_sys::{};", ident)
                        .context("unable to write to bindings file")?;
                }
            }
        }

        for (feature_name, feature_flag) in self
            .requested_features
            .iter()
            .filter_map(|v| v.sdkconfig_flag_name().map(|flag| (v.as_str(), flag)))
        {
            // For some reason, embuild adds expected cfg flags for some, but not all feature-related sdkconfig flags, causing warnings if we don't do this.
            println!("cargo::rustc-check-cfg=cfg(esp_idf_{})", feature_flag.to_lowercase());

            writeln!(
                &mut libcoap_bindings_file,
                // Only show these errors if the coap component is enabled at all (in order to only
                // show the relevant compilation error).
                "#[cfg(all(esp_idf_comp_espressif__coap_enabled, not(esp_idf_{})))]",
                feature_flag.to_lowercase()
            )
            .context("unable to write to bindings file")?;
            writeln!(&mut libcoap_bindings_file, "compile_error!(\"Requested feature \\\"{feature_name}\\\" is not enabled in ESP-IDF sdkconfig.defaults (set `CONFIG_{feature_flag}=y` to fix this)\");")
                .context("unable to write to bindings file")?;
        }

        Ok(bindings_file_path)
    }
}

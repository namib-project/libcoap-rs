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
    dtls_requested: bool,
}

impl EspIdfBuildSystem {
    pub fn new(out_dir: PathBuf, requested_dtls_backend: Option<DtlsBackend>) -> Result<Self> {
        let esp_idf_bindings_file = env::var_os("DEP_ESP_IDF_ROOT")
            .map(PathBuf::from)
            .expect("Environment variable DEP_ESP_IDF_ROOT has not been set by esp-idf-sys")
            .join("bindings.rs");

        let dtls_requested = if let Some(backend) = requested_dtls_backend {
            if backend != DtlsBackend::MbedTls {
                return Err(anyhow!("libcoap only supports the MbedTLS DTLS backend when compiling for the ESP-IDF, but you have requested the {backend} backend."));
            }
            true
        } else {
            false
        };

        Ok(Self {
            out_dir,
            esp_idf_bindings_file,
            dtls_requested,
        })
    }
}

impl BuildSystem for EspIdfBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        None
    }

    fn version(&self) -> Option<Version> {
        None
    }

    fn generate_bindings(&mut self) -> Result<PathBuf> {
        let esp_bindings_file =
            std::fs::read_to_string(&self.esp_idf_bindings_file).context("unable to read ESP-IDF bindings file")?;
        let parsed_esp_bindings_file =
            syn::parse_file(&esp_bindings_file).context("unable to parse ESP-IDF bidnings file")?;
        let bindings_file_path = self.out_dir.join("bindings.rs");
        let mut libcoap_bindings_file = File::create(&bindings_file_path).context("unable to create bindings file")?;
        for item in parsed_esp_bindings_file.items {
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
                if ident.to_lowercase().starts_with("coap") || ident.to_lowercase().starts_with("oscore") {
                    write!(&mut libcoap_bindings_file, "pub use esp_idf_sys::{};\n", ident)
                        .context("unable to write to bindings file")?;
                }
            }
        }
        Ok(bindings_file_path)
    }
}

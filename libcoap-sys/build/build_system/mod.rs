use std::path::PathBuf;

use anyhow::Result;
use enumset::EnumSet;
use version_compare::Version;

use crate::metadata::{DtlsBackend, LibcoapFeature};

pub mod esp_idf;
pub mod manual;
pub mod pkgconfig;
pub mod vendored;

pub trait BuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>>;

    fn detected_dtls_backend(&self) -> Option<DtlsBackend>;

    fn version(&self) -> Option<Version>;

    fn generate_bindings(&mut self) -> Result<PathBuf>;
}

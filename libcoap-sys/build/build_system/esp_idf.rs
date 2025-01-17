use crate::build_system::BuildSystem;
use crate::metadata::LibcoapFeature;
use anyhow::Result;
use enumset::EnumSet;
use std::path::PathBuf;
use version_compare::Version;

pub struct EspIdfBuildSystem {
    out_dir: PathBuf,
}

impl EspIdfBuildSystem {
    pub fn new(out_dir: PathBuf) -> Result<Self> {
        Ok(Self { out_dir })
    }
}

impl BuildSystem for EspIdfBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        None
    }

    fn version(&self) -> Option<Version> {
        todo!()
    }

    fn generate_bindings(&mut self) -> Result<PathBuf> {
        todo!()
    }
}

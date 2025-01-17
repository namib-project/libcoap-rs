use std::path::PathBuf;

use anyhow::{bail, Result};
use enumset::EnumSet;
use version_compare::Version;

use crate::{build_system::BuildSystem, metadata::LibcoapFeature};

pub struct ManualBuildSystem;

impl ManualBuildSystem {
    pub fn link_with_libcoap(out_dir: PathBuf) -> Result<Self> {
        bail!("not yet implemented")
    }
}

impl BuildSystem for ManualBuildSystem {
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>> {
        todo!()
    }

    fn version(&self) -> Option<Version> {
        todo!()
    }

    fn generate_bindings(&mut self) -> anyhow::Result<PathBuf> {
        todo!()
    }
}

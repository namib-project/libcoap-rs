use std::path::PathBuf;

use anyhow::Result;
use enumset::EnumSet;
use version_compare::Version;

use crate::metadata::{DtlsBackend, LibcoapFeature};

pub mod esp_idf;
pub mod manual;
pub mod pkgconfig;
pub mod vendored;

/// Trait that is implemented by build systems for libcoap.
///
/// It is assumed that the constructor structs implementing this trait already performs all
/// necessary steps to link against libcoap, and that only binding generation and compile-time
/// checks remain.
///
/// If you want to implement your own build system, you may want to use the `manual` build system
/// as a basis.
///
/// In order to implement the compile-time checks, you may want to use
/// [`LibcoapDefineParser`](crate::bindings::LibcoapDefineParser), at least in cases where you have
/// the corresponding `coap_defines.h` header file available.
pub trait BuildSystem {
    /// Returns the set of features that are supported by the linked version of libcoap, or `None`
    /// if this detection is not possible or has not been performed yet.
    ///
    /// It is assumed that after `generate_bindings()` is called, a `None` return value indicates
    /// that compile-time feature detection is unsupported.
    fn detected_features(&self) -> Option<EnumSet<LibcoapFeature>>;

    /// Returns the DTLS backend that has been used in the `libcoap` version this build
    /// system built against, or `None` if this detection is not possible or has not been performed
    /// yet.
    ///
    /// It is assumed that after `generate_bindings()` is called, a `None` return value indicates
    /// that compile-time DTLS library detection is unsupported.
    fn detected_dtls_backend(&self) -> Option<DtlsBackend>;

    /// Returns the `libcoap` library version this build system built against, or `None` if this
    /// detection is not possible or has not been performed yet.
    ///
    /// It is assumed that after `generate_bindings()` is called, a `None` return value indicates
    /// that compile-time DTLS library detection is unsupported.
    fn version(&self) -> Option<Version>;

    /// Generate Rust bindings to the `libcoap` C library that we linked against and return a
    /// `PathBuf` to the generated bindings file to use.
    fn generate_bindings(&mut self) -> Result<PathBuf>;
}

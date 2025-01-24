// SPDX-License-Identifier: BSD-2-Clause
/*
 * lib.rs - Main library entry point for raw libcoap bindings.
 * This file is part of the libcoap-sys crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Auto-generated unsafe bindings to [libcoap](https://github.com/obgm/libcoap), generated using
//! [bindgen](https://crates.io/crates/bindgen).
//!
//! This crate allows direct (but unsafe) usage of the libcoap C library from Rust. The declarations
//! made in this library are generated automatically using bindgen, for further documentation on how
//! to use them, refer to the [libcoap documentation](https://libcoap.net/documentation.html).
//!
//! In most cases you probably want to use the safe wrapper provided by the
//! [libcoap_rs](https://github.com/namib-project/libcoap-rs/tree/main/libcoap) crate or another
//! CoAP library written in pure Rust such as [coap-rs](https://github.com/covertness/coap-rs)
//! instead.
//!
//! The TLDR for building libcoap-sys (and resolving the most common Build Issues)
//! ------------------------------------------------------------------------------
//! It is strongly recommended that you read the remainder of this page in order to fully understand
//! the build process and possible causes of errors, especially if you're cross-compiling or
//! building for embedded targets.
//!
//! However, if you lack the time to do so, the following instructions should work in most cases:
//!
//! 1. Add a dependency to this crate and add all features you need for your crate to work.
//!    Call [`coap_startup_with_feature_checks()`] instead of [`coap_startup()`] during
//!    initialization to ensure that all of these features are actually available in the linked
//!    version of `libcoap`.
//!
//! 2. If you require DTLS support and run into `Required feature "dtls-(psk|pki|rpk|...)" is not
//!    supported by libcoap` errors, manually select a DTLS library that supports all of your
//!    required DTLS features by setting the `LIBCOAP_RS_DTLS_BACKEND` environment variable to your
//!    desired choice (the library name in all-lowercase should work).
//!
//! 3. If you're building a binary crate (or tests, examples, ...) and are getting non-DTLS-related
//!    `Required feature "<FEATURE>" is not supported by libcoap` errors, enable the `vendored`
//!    feature to build and statically link a version of libcoap that supports exactly the features
//!    you requested.
//!
//! 4. Inspect your dependency tree to determine whether you already have a DTLS library's sys-crate
//!    (`openssl-sys`, `tinydtls-sys` or `mbedtls-sys-auto`) in your dependency tree.
//!    If this is the case, enable the `dtls-<LIBRARY NAME>-sys` feature for all of them.
//!    This may resolve issues related to linking multiple versions of the same library at once, and
//!    could also help in reducing binary size.
//!    
//! If you're still unable to compile `libcoap-sys`, refer to the documentation below.
//! If the documentation below does not solve your issue, feel free to open an issue
//! [on GitHub](https://github.com/namib-project/libcoap-rs/) and ask for help.
//!
//! Optional Features
//! --------------
//! Most features specified in this crate's Cargo.toml directly correspond to a feature that can be
//! enabled or disabled in libcoap's configure-script and/or CMake configuration, refer to the
//! libcoap documentation for more details on these features.
//!
//! The `default` feature should match the default features enabled in the configure script of the
//! minimum supported version of libcoap.
//!
//! Depending on the build system and linked version of libcoap, the features actually provided may
//! differ from the ones indicated by the crate features.
//! If you want to ensure that all features that are enabled for this crate are actually supported
//! by the linked version of libcoap, you may call [`coap_startup_with_feature_checks()`].
//!
//! Aside from the features relating to libcoap functionality, the following features may also be
//! enabled for this crate:
//! - `vendored`: Build and statically link against a version of libcoap bundled with this crate
//!     instead of using a system-provided one[^1].
//! - `dtls-<LIBRARY NAME>-sys`: Allows the [vendored](#vendored-build-system) libcoap version to link against the
//!     same version of a DTLS library that is used by the corresponding <LIBRARY NAME>-sys
//!     crate[^2].
//!     Note, however, that this does not imply that this DTLS library *will* be used, refer to
//!     the [documentation below](#dtls-library-selection) for more information.
//!
//!     If a different build system than `vendored` is used, this feature is effectively a no-op.
//! - `dtls-<LIBRARY NAME>-sys-vendored` instructs the sys-crate of the DTLS library corresponding
//!     to the feature name to use a vendored version of the underlying library (implies
//!     `dtls-<LIBRARY NAME>-sys`).
//! - `dtls-(cid|psk|pki|pkcs11|rpk)`: Require support for specific DTLS features in `libcoap`.
//!     These features can not be enabled explicitly while building `libcoap`, support for them is
//!     automatically made available based on the used DTLS library (see
//!     [the corresponding section below](#dtls-library-selection)).
//!
//!     Enabling these features will add appropriate checks during compile- and/or runtime
//!     initialization to ensure these features are available in the used DTLS library (or panic
//!     otherwise).
//!
//! [^1]: Note that when building for the ESP-IDF, this feature will be a no-op, as the version
//!       provided by the ESP-IDF will always be used.
//! [^2]: In the case of `mbedtls`, `mbedtls-sys-auto` is used instead, as `mbedtls-sys` is
//!       unmaintained.
//!
//! Build Process
//! -------------
//! In general, `libcoap-sys` supports four different build systems, which will be explained in more
//! detail in the following sections:
//! - `vendored`: Build libcoap from source using a bundled version of the library (requires the
//!               `vendored` feature to be enabled.
//! - `pkgconfig`: Link against a system-provided version of libcoap, obtaining the library and
//!                include paths using the `pkg-config` utility.
//! - `manual`: Provide include and library directories+compiler/linker flags via environment
//!             variables.
//! - `espidf`: Build for the ESP family of microcontrollers using the ESP-IDF framework (used
//!             instead of the regular `vendored` build if the build system is set to `vendored` and
//!             building for an ESP-IDF Rust target).
//!
//! The build system that should be used can be specified manually by setting the
//! `LIBCOAP_RS_BUILD_SYSTEM` environment variable to the corresponding value.
//!
//! If you have explicitly specified a build system and building using that system fails, no other
//! system will be tried.
//!
//! If you do not explicitly provide a build system to use, the build script will follow these
//! steps to determine a suitable build system:
//!
//! 1. If the `vendored` crate feature is enabled, or we are building for the ESP-IDF, act as if the
//!    build system is set to `vendored`. If a vendored build is attempted and fails, return with an
//!    error and do not try anything else.
//! 2. Otherwise, try `pkgconfig` first.
//! 3. If `pkgconfig` doesn't work, fall back to `manual` (which will fail if the environment
//!    variables aren't set).
//! 4. If `manual` doesn't work, return an error indicating the issues with all previously attempted
//!    build systems.
//!
//! ## Generic Information (applies to all build systems)
//! The following information applies to all build systems (although some specifics may be detailed
//! in the respective build system's section).
//!
//! ### C Standard Library Functions
//! Some `libcoap` functions utilize types from the C standard library (e.g., `sockaddr_in` in
//! `coap_address_t`).
//!
//! For most targets, the data types defined in the [`libc`](https://docs.rs/libc/latest/libc/)
//! crate will be used to provide those data types.
//! However, some targets (especially embedded ones such as `espidf`) will use a different library
//! instead, which may cause compilation issues in code that assumes `libc` data types to be
//! compatible.
//!
//! For your convenience, this crate re-exports the used standard library crate as the `c_stdlib`
//! module. For best interoperability, you should `use` this module instead of using the actual
//! crates directly to import the required data types.
//!
//! ### DTLS Library Selection
//!
//! In order to provide DTLS support, `libcoap` must be combined with a DTLS library/backend.
//! DTLS libraries are mutually exclusive, and multiple versions of `libcoap` linked against
//! different DTLS libraries may be installed in a system simultaneously, so `libcoap-sys` must
//! decide on a variant of `libcoap` to link against during build.
//!
//! While the default mechanism for determining a DTLS library differs between build systems, you
//! may select a DTLS library explicitly by setting the `LIBCOAP_RS_DTLS_BACKEND` environment
//! variable to any of the supported values (`gnutls`, `openssl`, `mbedtls`, `tinydtls`, or
//! `wolfssl`). Refer to the build-system-specific documentation for information about supported
//! DTLS libraries and specifics.
//!
//! Note that some DTLS-related features (such as `dtls-(cid|psk|pki|pkcs11|rpk)`) are dependent on
//! the used DTLS backend, refer to [the `coap_encryption(3)` man page](https://libcoap.net/doc/reference/4.3.5/man_coap_encryption.html)
//! for information on supported features for each DTLS library.
//!
//! ### Feature Support and Compile-Time/Initialization Checks
//! During compilation, each build system will attempt to ensure that the used version of `libcoap`
//! does in fact support all [features](#optional-features) that were enabled in `Cargo.toml`.
//! The exact method differs based on each build system, but most will attempt to parse the
//! `coap3/coap_defines.h` header file in order to determine missing features (with `espidf` being a
//! notable exception).
//!
//! If a build system detects that a requested feature is missing, an appropriate error message will
//! be returned. In most cases, these errors must be resolved by linking to a different version of
//! `libcoap`.
//!
//! Unfortunately, for various reasons, this compile-time feature check may produce false
//! positive and/or false negative results (especially when cross compiling[^3])
//! is not available for all features (especially ones dependent on the DTLS library) and may not
//! even be available at all on some platforms.
//!
//! Therefore, library users should assume that the compile-time checks may not provide accurate
//! results, and should call [`coap_startup_with_feature_checks()`] during initialization to perform
//! run-time checks for all requested features. This run-time check will always work and be
//! accurate.
//!
//! Lastly, if you encounter a false positive error (i.e., a compile time error that indicates that
//! some feature is missing, even though you are 100% certain that it is available), you may bypass
//! the compile-time checks by setting `LIBCOAP_RS_BYPASS_COMPILE_FEATURE_CHECKS` to any non-zero
//! value.
//! Note, however, that this might lead to cryptic errors if your assumption was wrong and the
//! feature is not available after all.
//!
//! In most cases, a false positive might be caused by the include paths/header files used for
//! binding generation refering to a different version of `libcoap` than the one that is linked
//! against, which could also cause difficult-to-debug issues and indicates a more severe problem
//! with the build process.
//!
//! [^3]: For this reason, using this method while cross-compiling [is noted to be unsafe in `libcoap`'s documentation](https://libcoap.net/doc/reference/4.3.5/man_coap_supported.html).
//!
//! ## Vendored Build System
//!
//! The vendored build system uses a bundled version of libcoap (usually the latest stable version
//! at the time of release) to build and statically link against.
//! Under the hood, it uses the [`autotools`](https://docs.rs/autotools/latest/autotools/) crate to
//! configure and run the build process, and you may therefore customize the build's compiler and
//! linker flags by setting the environment variables used in `libcoap`'s `configure` script.
//!
//! This build system will enable only those features in `libcoap` that are requested as
//! `Cargo.toml` features, and will explicitly disable all other ones.
//!
//! If a DTLS library is explicitly selected by the user, it will instruct libcoap to link against
//! that library by setting the corresponding `--with-<LIBRARY NAME>` configure flag.
//!
//! If you enable the `dtls-<LIBRARY NAME>-sys` features and do not set the `<LIBRARY NAME>_CFLAGS`
//! or `<LIBRARY NAME>_LIBS` environment variables, this build system will set these environment
//! variables to ensure that if this DTLS library is the one that libcoap uses, we link against
//! exactly the same version as used in the `<LIBRARY NAME>-sys` crate.
//! This is especially relevant if those crates also provide a `vendored` version in order to avoid
//! multiple versions of the same library being in use.
//! If a different DTLS library is used, this feature should have no effect (it will set the
//! environment variable, but `libcoap` will ignore it).
//!
//! If you do not specify a DTLS library, this build system will follow the same default order that
//! libcoap does (gnutls > openssl > wolfssl > mbedtls > tinydtls), unless you enabled one of the
//! `dtls-<LIBRARY NAME>-sys` features, in which case those will have priority.
//! If multiple of these features are enabled, they are prioritized in the same order as used by
//! `libcoap` (openssl > mbedtls > tinydtls).
//!
//! ## `pkg-config` Build System
//!
//! The `pkg-config` build system utilizes the `pkg-config` utility available on most Unix-like
//! systems to link against a system-provided version of `libcoap`.
//! To do so, it uses the [`pkg_config`](https://docs.rs/pkg-config/latest/pkg_config/) crate, and
//! you may therefore customize the build process by setting the environment variables described in
//! that library's documentation (which may be of special relevance if you try to cross compile).
//!
//! By default, it will probe `pkg-config` for a library with the name `libcoap-3`, which will
//! usually symlink to the DTLS library variant of libcoap that was installed most recently.
//! If you have explicitly requested use of a specific DTLS library, this build system will attempt
//! to find the `libcoap-3-<LIBRARY NAME>` library instead.
//!
//! However, library selection does not take into account any other requested features (i.e., it
//! will not check for feature support before generating the bindings), but will use header-based
//! compile-time feature checks (see the general section) to ensure support for all required
//! features after binding generation.
//!
//! The `dtls-<LIBRARY NAME>-sys` features have no effect on this build system, but note that static
//! linking against a system-provided version of `libcoap` may cause issues if it causes multiple
//! versions of the same DTLS library to be statically linked into the same Rust binary.
//!
//! ## `manual` Build System
//!
//! This build system is intended as a fallback solution if all other options fail. It will attempt
//! to generate bindings and link against the version of `libcoap` that is described by the
//! following environment variables:
//!
//! - `LIBCOAP_RS_INCLUDE_DIRS`: Paths that should be added to `clang`'s include path to search for
//!                              header files (e.g., `/usr/local/include`, _not_
//!                              `/usr/local/include/coap3`). Multiple values are separated by
//!                              colons (`:`).
//! - `LIBCOAP_RS_LIB_DIRS`:     Paths that should be added to `rustc`'s library path to search for
//!                              object files to link against. Multiple values are separated by
//!                              colons (`:`).
//! - `LIBCOAP_RS_STATIC`:       Set to any non-zero and non-empty value to instruct `rustc` to use
//!                              static linking instead of dynamic linking for `libcoap`.
//! - `LIBCOAP_RS_ADDITIONAL_LIBRARIES`: Additional libraries (such as DTLS libraries) that should
//!                              be linked against, separated by colons (`:`).
//!                              Note that these will be added after `libcoap`, and that the order
//!                              in which they are specified matters for most linkers.
//!                              You may also request static linking by prepending `static=` to the
//!                              library name.
//!
//! ## `espidf` Build System
//!
//! This build system will be used instead of the regular `vendored` build if you are building for
//! targets that are based on the `ESP-IDF`.
//!
//! If `libcoap-sys` is a direct dependency, it will automatically enable the
//! [`espressif/coap`](https://components.espressif.com/components/espressif/coap) component in
//! order to instruct `esp-idf-sys` to compile and link `libcoap` and generate bindings for it.
//!
//! If you encounter errors that indicate that the `espressif/coap` component may not be enabled in
//! the ESP-IDF, this could have the following reasons:
//! - You may have to run `cargo clean`, as the `esp-idf-sys` build script does not always detect
//!     changes in requested extra components properly.
//! - `libcoap-sys` is a transient dependency: the `esp-idf-sys` build script
//!     [only considers metadata from the root crate and its direct dependencies](https://docs.esp-rs.org/esp-idf-sys/esp_idf_sys/#extra-esp-idf-components)
//!     to determine which components to install.
//!     In order to solve this, you can either add `libcoap-sys` as a direct dependency, or copy
//!     this crate's `src/wrapper.h` file and add the following snippet to your own `Cargo.toml`.
//!     ```cargo
//!     [[package.metadata.esp-idf-sys.extra_components]]
//!     remote_component = { name = "espressif/coap", version = "4.3.5~3" }
//!     bindings_header = "src/wrapper.h"
//!     ```
//!     Afterward, run `cargo clean` (see the issue mentioned above) and try again.
//!
//! It will then parse the generated bindings file and re-export all symbols in `esp-idf-sys` that
//! are related to `libcoap`.
//!
//! Note that `esp-idf-sys` may use a different version of `bindgen` than the other build systems
//! and that bindings might differ slightly as a result.
//!
//! Unlike most other targets, this one will use `esp-idf-sys` instead of `libc` to provide its
//! standard library types (see the generic information section above).

// Bindgen translates the C headers, clippy's and rustfmt's recommendations are not applicable here.
#![allow(clippy::all)]
#![allow(non_camel_case_types)]
#![allow(deref_nullptr)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ffi::c_void;

use c_stdlib::{epoll_event, fd_set, memcmp, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, socklen_t, time_t};
/// Re-export of the crate that provides libc data types used by libcoap.
///
/// In most cases, this will be libc, but on the ESP-IDF, it will be esp_idf_sys.
#[cfg(target_os = "espidf")]
pub use esp_idf_sys as c_stdlib;
/// Re-export of the crate that provides libc data types used by libcoap.
///
/// In most cases, this will be libc, but on the ESP-IDF, it will be esp_idf_sys.
#[cfg(not(target_os = "espidf"))]
pub use libc as c_stdlib;
// use dtls backend libraries in cases where they set our linker flags, otherwise rustc will
// optimize them out, resulting in missing symbols.
#[allow(unused_imports)]
#[cfg(used_dtls_crate = "mbedtls")]
use mbedtls_sys as _;
#[allow(unused_imports)]
#[cfg(used_dtls_crate = "openssl")]
use openssl_sys as _;
#[allow(unused_imports)]
#[cfg(used_dtls_crate = "tinydtls")]
use tinydtls_sys as _;


// Add check whether the libcoap component is enabled when building for the ESP-IDF.
#[cfg(all(target_os = "espidf", not(esp_idf_comp_espressif__coap_enabled)))]
compile_error!(concat!(
    "You are building libcoap-sys for an ESP-IDF target, but have not added the\n",
    "espressif/coap remote component (see the libcoap-sys documentation for more information)"
));

include!(env!("BINDINGS_FILE"));

/// Compares instances of coap_str_const_t and/or coap_string_t.
///
/// This macro is a reimplementation of the macro defined in coap_str.h, see
/// <https://libcoap.net/doc/reference/develop/group__string.html#ga7f43c10b486dc6d45c37fcaf987d711b>.
#[macro_export]
macro_rules! coap_string_equal {
    ( $string1:expr, $string2:expr ) => {{
        use libcoap_sys::coap_string_equal_internal;
        let s1 = $string1;
        let s2 = $string2;
        coap_string_equal_internal((*s1).s, (*s1).length, (*s2).s, (*s2).length)
    }};
}

/// Internal only function for CoAP string comparisons.
///
/// *DO NOT USE THIS FUNCTION DIRECTLY.* It is only public because it is used by the
/// [coap_string_equal] macro, which is the function you probably wanted to call instead.
///
/// # Safety
///
/// This function should not be called directly, use [coap_string_equal] instead.
pub unsafe fn coap_string_equal_internal(
    str1_ptr: *const u8,
    str1_len: usize,
    str2_ptr: *const u8,
    str2_len: usize,
) -> bool {
    str1_len == str2_len
        && (str1_len == 0
            || !str1_ptr.is_null()
                && !str2_ptr.is_null()
                && memcmp(str1_ptr as *const c_void, str2_ptr as *const c_void, str1_len as _) == 0)
}

/// Execute feature check function and panic with an error message if the feature is not supported.
///
/// SAFETY: check_fn will be called, make sure to wrap this macro in unsafe if the function is
/// unsafe.
#[cfg(any(not(target_os = "espidf"), esp_idf_comp_espressif__coap_enabled))]
macro_rules! feature_check {
    ($feature:literal, $check_fn:ident) => {
        #[cfg(feature = $feature)]
        // SAFETY: Function is always safe to call.
        if $check_fn() != 1 {
            panic!("Required feature \"{}\" is not supported by libcoap", $feature)
        }
    };
    ( $(($feature:literal, $check_fn:ident)),* ) => {
        $(
            feature_check!($feature, $check_fn);
        )*
    }
}

#[cfg(any(not(target_os = "espidf"), esp_idf_comp_espressif__coap_enabled))]
macro_rules! dtls_backend_string {
    ($backend:ident) => {
        match $backend {
            coap_tls_library_t_COAP_TLS_LIBRARY_OPENSSL => "openssl",
            coap_tls_library_t_COAP_TLS_LIBRARY_GNUTLS => "gnutls",
            coap_tls_library_t_COAP_TLS_LIBRARY_MBEDTLS => "mbedtls",
            coap_tls_library_t_COAP_TLS_LIBRARY_TINYDTLS => "tinydtls",
            coap_tls_library_t_COAP_TLS_LIBRARY_WOLFSSL => "wolfssl",
            coap_tls_library_t_COAP_TLS_LIBRARY_NOTLS => "notls",
            _ => "unknown",
        }
    };
}

#[cfg(any(not(target_os = "espidf"), esp_idf_comp_espressif__coap_enabled))]
macro_rules! panic_wrong_dtls {
    ($presumed_backend:ident, $detected_backend:ident) => {
        panic!(
            concat!(
                "compile-time detected DTLS backend \"{}\" does not match run-time detected DTLS backend \"{}\".\n",
                "This almost certainly means that libcoap-sys was linked against a different version of \n",
                "libcoap than the one whose headers were used for binding generation."
            ),
            dtls_backend_string!($presumed_backend),
            dtls_backend_string!($detected_backend)
        )
    };
}

/// Initialize the CoAP library and additionally perform runtime checks to ensure that required
/// features (as enabled in `Cargo.toml`) are available and that the used DTLS library matches the
/// one that was determined during compile-time.
///
/// You *should* prefer using this function over [`coap_startup()`], as without calling this function
/// some of the features enabled using the Cargo features may not actually be available.
///
/// Either this function or [`coap_startup()`] must be run once before any libcoap function is called.
///
/// If you are absolutely 100% certain that all features you require are always available (or are
/// prepared to deal with error return values/different behavior on your own if they aren't), you
/// may use [`coap_startup()`] instead.
// Make sure that if we're compiling for the ESP-IDF, this function is only compiled if the
// libcoap component is installed in the ESP-IDF.
// This way, these function calls will not cause missing function or struct definition errors that
// clutter up the error log, and the only error message will be the way more descriptive
// compile_error macro invocation at the start of this file.
#[cfg(any(not(target_os = "espidf"), esp_idf_comp_espressif__coap_enabled))]
pub fn coap_startup_with_feature_checks() {
    unsafe {
        feature_check!(
            ("af-unix", coap_af_unix_is_supported),
            ("async", coap_async_is_supported),
            ("client", coap_client_is_supported),
            ("dtls", coap_dtls_is_supported),
            ("dtls-cid", coap_dtls_cid_is_supported),
            ("dtls-psk", coap_dtls_psk_is_supported),
            ("dtls-pki", coap_dtls_pki_is_supported),
            ("dtls-pkcs11", coap_dtls_pkcs11_is_supported),
            ("dtls-rpk", coap_dtls_rpk_is_supported),
            ("epoll", coap_epoll_is_supported),
            ("ipv4", coap_ipv4_is_supported),
            ("ipv6", coap_ipv6_is_supported),
            ("observe-persist", coap_observe_persist_is_supported),
            ("oscore", coap_oscore_is_supported),
            ("q-block", coap_q_block_is_supported),
            ("server", coap_server_is_supported),
            ("tcp", coap_tcp_is_supported),
            ("thread-safe", coap_threadsafe_is_supported),
            ("tls", coap_tls_is_supported),
            ("websockets", coap_ws_is_supported),
            ("secure-websockets", coap_wss_is_supported)
        );
    }

    // ESP-IDF is missing the coap_tls_library_t type.
    #[cfg(not(target_os = "espidf"))]
    {
        let presumed_dtls_backend = if cfg!(dtls_backend = "openssl") {
            coap_tls_library_t_COAP_TLS_LIBRARY_OPENSSL
        } else if cfg!(dtls_backend = "gnutls") {
            coap_tls_library_t_COAP_TLS_LIBRARY_GNUTLS
        } else if cfg!(dtls_backend = "mbedtls") {
            coap_tls_library_t_COAP_TLS_LIBRARY_MBEDTLS
        } else if cfg!(dtls_backend = "tinydtls") {
            coap_tls_library_t_COAP_TLS_LIBRARY_TINYDTLS
        } else if cfg!(dtls_backend = "wolfssl") {
            coap_tls_library_t_COAP_TLS_LIBRARY_WOLFSSL
        } else {
            coap_tls_library_t_COAP_TLS_LIBRARY_NOTLS
        };

        let actual_dtls_backend = unsafe { *coap_get_tls_library_version() }.type_;

        if presumed_dtls_backend != coap_tls_library_t_COAP_TLS_LIBRARY_NOTLS
            && actual_dtls_backend != presumed_dtls_backend
        {
            panic_wrong_dtls!(presumed_dtls_backend, actual_dtls_backend);
        }
    }

    // SAFETY: Function is always safe to call.
    unsafe { coap_startup() }
}

#[cfg(all(test, not(target_os = "espidf")))]
mod tests {
    use std::{
        ffi::c_void,
        net::{SocketAddr, UdpSocket},
        os::raw::c_int,
        sync::{Arc, Barrier},
    };

    use libc::{in6_addr, in_addr, sa_family_t, size_t, AF_INET, AF_INET6};

    use super::*;

    const COAP_TEST_RESOURCE_URI: &str = "test";
    const COAP_TEST_RESOURCE_RESPONSE: &str = "Hello World!";

    /// Creates a coap_address_t from a &SocketAddr.
    fn coap_address_from_socketaddr(addr: &SocketAddr) -> coap_address_t {
        match addr {
            SocketAddr::V4(addr) => {
                // addr is a bindgen-type union wrapper, so we can't assign to it directly and have
                // to use a pointer instead.
                // SAFETY: addr is not read before it is assigned properly, assignment cannot fail.
                unsafe {
                    let mut coap_addr = coap_address_t {
                        size: std::mem::size_of::<sockaddr_in>() as socklen_t,
                        addr: std::mem::zeroed(),
                    };
                    coap_addr.addr.sin = sockaddr_in {
                        sin_family: AF_INET as sa_family_t,
                        sin_port: addr.port().to_be(),
                        sin_addr: in_addr {
                            s_addr: u32::from_ne_bytes(addr.ip().octets()),
                        },
                        sin_zero: Default::default(),
                    };
                    coap_addr
                }
            },
            SocketAddr::V6(addr) => {
                // addr is a bindgen-type union wrapper, so we can't assign to it directly and have
                // to use a pointer instead.
                // SAFETY: addr is not read before it is assigned properly, assignment cannot fail.
                unsafe {
                    let mut coap_addr = coap_address_t {
                        size: std::mem::size_of::<sockaddr_in6>() as socklen_t,
                        addr: std::mem::zeroed(),
                    };
                    coap_addr.addr.sin6 = sockaddr_in6 {
                        sin6_family: AF_INET6 as sa_family_t,
                        sin6_port: addr.port().to_be(),
                        sin6_addr: in6_addr {
                            s6_addr: addr.ip().octets(),
                        },
                        sin6_flowinfo: addr.flowinfo(),
                        sin6_scope_id: addr.scope_id(),
                    };
                    coap_addr
                }
            },
        }
    }

    /// Response handler for the CoAP client/server test (client-side)
    /// # Safety
    /// Assumes all pointers to be valid and pointing to data structures containing valid data
    /// according to the specification of the method handler function provided in libcoap.
    /// Assumes that the application data in the CoAP context associated with the session is a
    /// pointer to a boolean specifying whether a successful request was received (will be set to
    /// true by this function).
    unsafe extern "C" fn test_resource_handler(
        _resource: *mut coap_resource_t,
        session: *mut coap_session_t,
        _incoming_pdu: *const coap_pdu_t,
        _query: *const coap_string_t,
        response_pdu: *mut coap_pdu_t,
    ) {
        let mut buf: [u8; 3] = [0; 3];
        coap_add_option(
            response_pdu,
            COAP_OPTION_CONTENT_TYPE as coap_option_num_t,
            coap_encode_var_safe(buf.as_mut_ptr(), buf.len(), COAP_MEDIATYPE_TEXT_PLAIN) as usize,
            buf.as_ptr(),
        );
        coap_add_data(
            response_pdu,
            COAP_TEST_RESOURCE_RESPONSE.len(),
            COAP_TEST_RESOURCE_RESPONSE.as_ptr(),
        );
        coap_set_app_data(coap_session_get_context(session), (&true) as *const bool as *mut c_void);
        coap_pdu_set_code(response_pdu, coap_pdu_code_t_COAP_RESPONSE_CODE_CONTENT);
    }

    /// Response handler for the CoAP client/server test (client-side)
    /// # Safety
    /// Assumes all pointers to be valid and pointing to data structures containing valid data
    /// according to the specification of the response handler function provided in libcoap.
    /// Assumes that the application data in the CoAP context associated with the session is a
    /// pointer to a boolean specifying whether a successful response was received (will be set to
    /// true by this function).
    unsafe extern "C" fn test_response_handler(
        session: *mut coap_session_t,
        _sent: *const coap_pdu_t,
        received: *const coap_pdu_t,
        _mid: coap_mid_t,
    ) -> coap_response_t {
        assert_eq!(coap_pdu_get_code(received), coap_pdu_code_t_COAP_RESPONSE_CODE_CONTENT);
        let mut len: size_t = 0;
        let mut data: *const u8 = std::ptr::null();
        assert_ne!(coap_get_data(received, &mut len, &mut data), 0);
        let data = std::slice::from_raw_parts(data, len);

        assert_eq!(data, COAP_TEST_RESOURCE_RESPONSE.as_bytes());
        coap_set_app_data(coap_session_get_context(session), (&true) as *const bool as *mut c_void);
        return coap_response_t_COAP_RESPONSE_OK;
    }

    /// Creates a CoAP server that provides a single resource under COAP_TEST_RESOURCE_URI over the
    /// supplied socket
    fn run_coap_test_server(addr: &SocketAddr, barrier: Arc<Barrier>) {
        // SAFETY: Null pointer is a valid parameter here.
        let context = unsafe { coap_new_context(std::ptr::null()) };
        assert!(!context.is_null());

        let address: coap_address_t = coap_address_from_socketaddr(addr);

        // SAFETY: We asserted that context != null, listen_addr is a reference and can therefore not be null.
        let endpoint = unsafe { coap_new_endpoint(context, &address, coap_proto_t_COAP_PROTO_UDP) };
        assert!(!endpoint.is_null());

        // SAFETY: Since we use a string constant here, the arguments to the function are all valid.
        let uri = unsafe { coap_new_str_const(COAP_TEST_RESOURCE_URI.as_ptr(), COAP_TEST_RESOURCE_URI.len()) };
        assert!(!uri.is_null());

        // SAFETY: We just asserted that uri is valid, COAP_RESOURCE_FLAGS_RELEASE_URI is valid because we will not free the uri ourselves.
        let test_resource = unsafe { coap_resource_init(uri, COAP_RESOURCE_FLAGS_RELEASE_URI as c_int) };
        assert!(!test_resource.is_null());

        // SAFETY: We asserted that test_resource and context are valid, other pointers are always valid.
        // The fact that we cast a constant to a mutable pointer is not problematic, because neither we
        // nor libcoap ever mutate the pointer. This is necessary, because the underlying libcoap
        // struct allows for mutable pointers to be set there, so that applications can use this to
        // modify some application specific state.
        unsafe {
            coap_register_request_handler(
                test_resource,
                coap_request_t_COAP_REQUEST_GET,
                Some(test_resource_handler),
            );
            coap_add_resource(context, test_resource);
            coap_set_app_data(context, (&false) as *const bool as *mut c_void);
        }

        barrier.wait();
        loop {
            let time_spent_millis = unsafe { coap_io_process(context, 10000) };
            // SAFETY: We are the only ones setting or accessing this value, so we know it is a
            // const bool pointer (we have also set it to *false before and only ever set it to
            // *true afterwards).
            if unsafe { *(coap_get_app_data(context) as *const bool).as_ref().unwrap() } {
                break;
            }
            if time_spent_millis == -1 || time_spent_millis >= 10000 {
                panic!("Test timeout exceeded");
            }
        }
        // SAFETY: Context is not referenced outside this function, and handlers (which get the
        // context from libcoap) will not be called after the context is freed.
        // This also seems to free all resources.
        unsafe {
            coap_free_context(context);
        }
    }

    /// Test case that creates a basic coap server and makes a request to it from a separate context
    #[test]
    fn test_coap_client_server_basic() {
        coap_startup_with_feature_checks();
        // This will give us a SocketAddress with a port in the local port range automatically
        // assigned by the operating system.
        // Because the UdpSocket goes out of scope, the Port will be free for usage by libcoap.
        // This seems to be the only portable way to get a port number assigned from the operating
        // system, which is necessary here because of potential parallelisation (we can't just use
        // the default CoAP port if multiple tests are run in parallel).
        // It is assumed here that after unbinding the temporary socket, the OS will not reassign
        // this port until we bind it again. This should work in most cases (unless we run on a
        // system with very few free ports), because at least Linux will not reuse port numbers
        // unless necessary, see https://unix.stackexchange.com/a/132524.
        let server_address = UdpSocket::bind("localhost:0")
            .expect("Failed to bind server socket")
            .local_addr()
            .expect("Failed to get server socket address");

        let preparation_barrier = Arc::new(Barrier::new(2));

        let server_address_clone = server_address.clone();
        let preparation_barrier_clone = preparation_barrier.clone();
        let server_thread_handle =
            std::thread::spawn(move || run_coap_test_server(&server_address_clone, preparation_barrier_clone));

        // SAFETY: Null pointer is a valid parameter here.
        let context = unsafe { coap_new_context(std::ptr::null()) };
        assert!(!context.is_null());

        preparation_barrier.wait();

        let server_address = coap_address_from_socketaddr(&server_address);

        // SAFETY: null pointer is valid argument for local_if, server_address is guaranteed to be
        // a correct value (conversion cannot fail), validity of context was asserted before.
        let client_session =
            unsafe { coap_new_client_session(context, std::ptr::null(), &server_address, coap_proto_t_COAP_PROTO_UDP) };

        // SAFETY: context and client_session were asserted to be valid.
        // Casting *const to *mut is fine because we don't mutate the value pointed to and the
        // pointer is not used by libcoap (the application data pointer is intended to be used by
        // client applications to store and/or modify their own data, which is why it is a mutable
        // pointer in the first place).
        // coap_request_pdu is asserted to be valid before it is used.
        unsafe {
            coap_register_response_handler(context, Some(test_response_handler));
            coap_set_app_data(context, (&false) as *const bool as *mut c_void);
            let coap_request_pdu = coap_new_pdu(
                coap_pdu_type_t_COAP_MESSAGE_NON,
                coap_pdu_code_t_COAP_REQUEST_CODE_GET,
                client_session,
            );
            assert!(!coap_request_pdu.is_null());
            assert_ne!(
                coap_add_option(
                    coap_request_pdu,
                    COAP_OPTION_URI_PATH as coap_option_num_t,
                    COAP_TEST_RESOURCE_URI.len(),
                    COAP_TEST_RESOURCE_URI.as_ptr(),
                ),
                0
            );
            assert_ne!(coap_send(client_session, coap_request_pdu), COAP_INVALID_MID);
        }

        loop {
            // SAFETY: context is asserted to be valid, no known side effects that would violate any guarantees
            let time_spent_millis = unsafe { coap_io_process(context, 10000) };
            // SAFETY: We are the only ones setting or accessing this value, so we know it is a
            // const bool pointer (we have also set it to *false before and only ever set it to
            // *true afterwards).
            if unsafe { *(coap_get_app_data(context) as *const bool).as_ref().unwrap() } {
                break;
            }
            if time_spent_millis == -1 || time_spent_millis >= 10000 {
                panic!("Test timeout exceeded");
            }
        }
        // SAFETY: Context is not references outside this function, and handlers (which get the
        // context from libcoap) will not be called after the context is freed.
        // This also seems to free all resources.
        unsafe {
            coap_free_context(context);
        }
        server_thread_handle.join().expect("Error waiting for server thread");
    }
}

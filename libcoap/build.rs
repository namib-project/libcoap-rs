// SPDX-License-Identifier: BSD-2-CLAUSE

use anyhow::{bail, Result};
use std::env::VarError;
use version_compare::Version;

/// The minimal version of libcoap that is expected to work with libcoap-rs.
///
/// Does not necessarily match the minimum supported version of libcoap-sys, and should be increased
/// whenever we make changes to the safe wrapper that can not feasibly be supported on older
/// versions of libcoap.
const MINIMUM_LIBCOAP_VERSION: &str = "4.3.5";

fn main() -> Result<()> {
    println!("cargo::rustc-check-cfg=cfg(dtls_backend, values(\"gnutls\", \"mbedtls\", \"tinydtls\", \"openssl\", \"wolfssl\"))");
    println!("cargo::rustc-check-cfg=cfg(libcoap_version, values(any()))");

    // If at all possible, you should not write code that is conditional on the DTLS backend (use
    // cargo features instead).
    // If there is no other way (e.g., if there is no way to determine feature support), you must
    // at least write code that can also deal with the variable not being there.
    match std::env::var("DEP_COAP_3_DTLS_BACKEND") {
        Ok(dtls_backend) => {
            println!("cargo::rustc-cfg=dtls_backend=\"{}\"", dtls_backend)
        },
        Err(VarError::NotUnicode(_)) => {
            panic!("DEP_COAP_3_DTLS_BACKEND is not valid unicode")
        },
        Err(VarError::NotPresent) => {},
    }

    match std::env::var("DEP_COAP_3_LIBCOAP_VERSION") {
        Ok(libcoap_version) => {
            let version = Version::from(libcoap_version.as_ref()).expect("invalid libcoap version");
            println!("cargo::rustc-cfg=libcoap_version=\"{}\"", version.as_str());

            if version < Version::from(MINIMUM_LIBCOAP_VERSION).unwrap() {
                // Unlike libcoap-sys, we do return an error here and not just a warning, as
                // unsupported libcoap versions might have semantic differences that break the
                // safety guarantees this wrapper is supposed to provide.

                bail!("The linked version of libcoap is lower than the minimal version required for libcoap-rs ({}), can not build.", MINIMUM_LIBCOAP_VERSION);
            }

            // Uncomment and adjust this in order to create version-dependent cfg-flags.
            // When updating the minimum supported libcoap version, one should also remove all
            // cfg-flags that are only relevant for versions lower than the new minimum
            // supported one, and rewrite code gated on these flags to assume that the minimum
            // version .
            // Note: In most cases, you probably want to check for the presence of a given feature instead.
            //       Matching based on the libcoap version usually only makes sense in order to either
            //       enable optional optimizations possible with newer versions, or to add struct fields
            //       that were added into existing structs without breaking backward compatibility.

            /*if version > Version::from("4.3.5").unwrap() {
                println!("cargo:rustc-cfg=[INSERT FLAG NAME HERE]")
            }*/
        },
        Err(VarError::NotUnicode(_)) => {
            panic!("DEP_COAP_3_LIBCOAP_VERSION is not valid unicode")
        },
        Err(VarError::NotPresent) => {
            println!("cargo:warning=Unable to automatically detect the linked version of libcoap, please manually ensure that the used version is at least {} for libcoap-rs to work as expected.", MINIMUM_LIBCOAP_VERSION);
        },
    }

    Ok(())
}

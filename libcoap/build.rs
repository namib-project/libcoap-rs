// SPDX-License-Identifier: BSD-2-CLAUSE

use version_compare::{Cmp, Version};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(dtls_ec_jpake_support)");
    println!("cargo::rustc-check-cfg=cfg(dtls_cid_support)");
    println!("cargo::rustc-check-cfg=cfg(coap_uri_buf_unused)");
    if let Ok(libcoap_version) = std::env::var("DEP_COAP_3_LIBCOAP_VERSION") {
        let version = Version::from(libcoap_version.as_ref()).expect("invalid libcoap version");
        // libcoap >= 4.3.5rc2 no longer uses the buf and buflen parameters in
        // coap_uri_into_options(), so we can optimize them out and save some memory.
        match version.compare(Version::from("4.3.5rc2").unwrap()) {
            Cmp::Gt | Cmp::Eq => {
                println!("cargo:rustc-cfg=coap_uri_buf_unused");
            },
            _ => {},
        }
        // libcoap >= 4.3.5rc3 supports DTLS EC JPAKE and connection ID extensions, which adds
        // additional fields to some DTLS configuration structs.
        match version.compare(Version::from("4.3.5rc3").unwrap()) {
            Cmp::Gt | Cmp::Eq => {
                println!("cargo:rustc-cfg=dtls_ec_jpake_support");
                println!("cargo:rustc-cfg=dtls_cid_support");
            },
            _ => {},
        }
    }
}

// SPDX-License-Identifier: BSD-2-CLAUSE

//use version_compare::Cmp;
use version_compare::Version;

fn main() {
    if let Ok(libcoap_version) = std::env::var("DEP_COAP_3_LIBCOAP_VERSION") {
        let version = Version::from(libcoap_version.as_ref()).expect("invalid libcoap version");
        println!("cargo:rustc-cfg=libcoap_version=\"{}\"", version.as_str());

        // Uncomment and adjust this in order to create version-dependent cfg-flags.
        // Note: In most cases, you probably want to check for the presence of a given feature instead.
        //       Matching based on the libcoap version usually only makes sense in order to either
        //       enable optional optimizations possible with newer versions, or to add struct fields
        //       that were added into existing structs without breaking backward compatibility.
        /*if version > Version::from("4.3.5").unwrap() {
            println!("cargo:rustc-cfg=[INSERT FLAG NAME HERE]")
        }*/
    }
}

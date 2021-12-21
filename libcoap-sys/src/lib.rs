//! Auto-generated unsafe bindings to [libcoap](https://github.com/obgm/libcoap), generated using
//! [bindgen](https://crates.io/crates/bindgen).
//!
//! This crate allows direct (but unsafe) usage of the libcoap C library from Rust. The declarations
//! made in this library are generated automatically using bindgen, for further documentation on how
//! to use them, refer to the [libcoap documentation](https://libcoap.net/documentation.html).
//!
//! In most cases you probably want to use the safe wrapper provided by the libcoap crate (or
//! another coap library written in pure rust like [coap-rs](https://github.com/covertness/coap-rs)
//! instead.
//!
//! Cargo Features
//! --------------
//! We currently define a number of features that affect the functionality provided by this wrapper
//! and required by the linked libcoap library.
//!
//! Features affecting functionality:
//! - `dtls`: Enable usage of DTLS for transport security. Supports a number of different backends.
//!
//!   Note that while not specified here due to limitations in Cargo's syntax, the DTLS feature
//!   depends on one of the DTLS backends being enabled, and failing to enable a DTLS backend will
//!   result in a build failure.
//!   
//!   If you are developing a library based on libcoap-sys and do not care about the DTLS backend,
//!   enable the dtls feature and let the user decide on the backend to use, either by
//!   re-exporting these features (see [the Cargo Book](https://doc.rust-lang.org/cargo/reference/features.html#dependency-features))
//!   or by assuming that the user will use libcoap-sys as a dependency and enable the
//!   corresponding backend feature themselves, relying on Cargo's feature unification to enable
//!   it for your crate as well.
//!   
//!   Also note that the backends are **mutually exclusive** due to the C library having these
//!   backends as mutually exclusive features. If multiple backends are enabled (e.g. because
//!   multiple dependencies use libcoap-sys and use different backends), we select one based on
//!   the auto-detection order specified in [the libcoap configure script](https://github.com/obgm/libcoap/blob/develop/configure.ac#L494)
//!   (gnutls > openssl > mbedtls > tinydtls).
//!   - `dtls_backend_(openssl|gnutls|mbedtls|tinydtls)`: Enable the corresponding DTLS backend.
//!      
//!      Note that enabling the OpenSSL, GnuTLS, TinyDTLS or MbedTLS backend will also require the
//!      appropiate library to be available (hence the dependency on the corresponding sys-crate).
//!      The TinyDTLS backend is built using a vendored (and statically linked) version of TinyDTLS
//!      by default, see the tinydtls-sys crate for more info.
//!      Choosing a DTLS backend also means that the license terms of these libraries may apply to
//!      you. See the relevant parts of the [libcoap license file](https://github.com/obgm/libcoap/blob/develop/LICENSE)
//!      for more information.
//! - `tcp`: Enable CoAP over TCP support
//! - `async`: Enable async functionality.
//!   
//!   Note that this async functionality is not translated to Rusts async language functionality,
//!   but instead adds functionality to the underlying C library to allow for making asynchronous
//!   requests (i.e. function calls that return before the response has arrived).
//!
//!   Integrating libcoap into Rusts async language features is out of scope for this crate, but
//!   might be implemented in the libcoap (safe abstraction) crate.
//! - `server`: Enable code related to server functionality
//! - `client`: Enable code related to client functionality
//! - `epoll`: Allow the underlying C library to perform IO operations using epoll.
//!
//! Other features:
//! - `vendored`: Use a vendored version of libcoap instead of the system-provided one
//!   Note that `vendored` implies `static`.
//! - `static`: Perform static linking to the libcoap C library.
//!
//! ### Note on features affecting functionality
//! The features that add or remove functionality currently do not change the generated bindings
//! as libcoap's headers (unlike the source files themselves are not affected by the corresponding
//! `#define`s.
//!
//! For library users that link to a shared version of libcoap, this means that the feature flags
//! do not have any effect and the supported features will correspond directly to the features
//! enabled during the build of the shared libcoap instance (using the configure-script).
//!
//! For users of the vendored version of libcoap (see the `vendored` feature), the supported
//! features of the vendored libcoap will be set to match the cargo features during build.
//!
//! However, in both cases, the generated bindings will always assume all features to be present,
//! which will cause a linking error if a function is used that is not included in the linked
//! version of libcoap.

// Bindgen translates the C headers, clippy's and rustfmt's recommendations are not applicable here.
#![allow(clippy::all)]
#![allow(non_camel_case_types)]

use libc::{epoll_event, fd_set, sockaddr, sockaddr_in, sockaddr_in6, socklen_t, time_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    /// Test case that creates a basic coap server and makes a request to it from a separate context
    #[test]
    fn test_coap_client_server_basic() {
        //let server_addr = coap_new_server_address();
        //let server_ctx = coap_new_context();
    }
}

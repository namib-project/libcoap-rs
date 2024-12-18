# libcoap-sys - Raw bindings for libcoap
[![latest release on crates.io](https://img.shields.io/crates/v/libcoap_sys)](https://crates.io/crates/libcoap-sys)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest_release-blue)](https://docs.rs/libcoap_sys/)
[![Documentation (main)](https://img.shields.io/badge/docs-main-blue)](https://namib-project.github.io/libcoap-rs-docs/docs/main/libcoap_sys/)
[![Test and Analyze CI Status](https://github.com/namib-project/libcoap-rs/actions/workflows/test.yml/badge.svg)](https://github.com/namib-project/libcoap-rs/actions/workflows/test.yml)
[![Coverage (main)](https://namib-project.github.io/libcoap-rs-docs/coverage/main/badges/flat.svg)](https://namib-project.github.io/libcoap-rs-docs/coverage/main/)

This crate contains raw unsafe bindings for the [libcoap CoAP libary](https://github.com/obgm/libcoap), which are 
generated using bindgen.

## Features
We currently define a number of features that affect the functionality provided by this wrapper
and required by the linked libcoap library.

Features affecting functionality:
- `dtls`: Enable usage of DTLS for transport security. Supports a number of different backends.

  Note that while not specified here due to limitations in Cargo's syntax, the DTLS feature
  depends on one of the DTLS backends being enabled, and failing to enable a DTLS backend will
  result in a build failure.
  
  If you are developing a library based on libcoap-sys and do not care about the DTLS backend,
  enable the dtls feature and let the user decide on the backend to use, either by
  re-exporting these features (see [the Cargo Book](https://doc.rust-lang.org/cargo/reference/features.html#dependency-features))
  or by assuming that the user will use libcoap-sys as a dependency and enable the
  corresponding backend feature themselves, relying on Cargo's feature unification to enable
  it for your crate as well.
  
  Also note that the backends are **mutually exclusive** due to the C library having these
  backends as mutually exclusive features. If multiple backends are enabled (e.g. because
  multiple dependencies use libcoap-sys and use different backends), we select one based on
  the auto-detection order specified in [the libcoap configure script](https://github.com/obgm/libcoap/blob/develop/configure.ac#L494)
  (gnutls > openssl > mbedtls > tinydtls).
  - `dtls_backend_(openssl|gnutls|mbedtls|tinydtls)`: Enable the corresponding DTLS backend.
     
     Note that enabling the OpenSSL, GnuTLS, TinyDTLS or MbedTLS backend will also require the
     appropriate library to be available (hence the dependency on the corresponding sys-crate).
     The TinyDTLS backend is built using a vendored (and statically linked) version of TinyDTLS
     by default, see the tinydtls-sys crate for more info.
     Choosing a DTLS backend also means that the license terms of these libraries may apply to
     you. See the relevant parts of the [libcoap license file](https://github.com/obgm/libcoap/blob/develop/LICENSE)
     for more information.
- `tcp` (default): Enable CoAP over TCP support
- `async` (default): Enable async functionality.
  
  Note that this async functionality is not translated to Rust's async language functionality,
  but instead adds functionality to the underlying C library to allow for making asynchronous
  requests (i.e. function calls that return before the response has arrived).

  Integrating libcoap into Rusts async language features is out of scope for this crate, but
  might be implemented later on in the libcoap (safe abstraction) crate.
- `server` (default): Enable code related to server functionality
- `client` (default): Enable code related to client functionality
- `epoll` (default): Allow the underlying C library to perform IO operations using epoll.

Other features:
- `vendored` (default): Use a vendored version of libcoap instead of the system-provided one.
  Note that `vendored` implies `static`.
- `static` (default): Perform static linking to the libcoap C library.

### Note on features affecting functionality
The features that add or remove functionality do not change the generated bindings as libcoap's
headers (unlike the source files themselves) are not affected by the corresponding `#define`s.

For library users that link to a shared version of libcoap, this means that the feature flags
do not have any effect and the supported features will correspond directly to the features
enabled during the build of the shared libcoap instance (using the configure-script).

For users of the vendored version of libcoap (see the `vendored` feature), the supported
features of the vendored libcoap will be set to match the cargo features during build.

## License 

The libcoap-sys binding is licensed under the 2-Clause/Simplified BSD License, matching the license of the libcoap C
library it is a binding to.

Note that for the libcoap-sys binding and generated binaries, the license terms of the libcoap C library as well as
linked dependencies (e.g. TLS libraries) may apply.

Additionally, the libcoap C library contains some third-party code, for which different licensing terms apply.

See https://github.com/obgm/libcoap/blob/develop/LICENSE as well as the licenses of dependencies for more
information and terms.

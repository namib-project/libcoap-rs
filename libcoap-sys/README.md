# libcoap-sys - Raw bindings for libcoap

[![latest release on crates.io](https://img.shields.io/crates/v/libcoap_sys)](https://crates.io/crates/libcoap-sys)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest_release-blue)](https://docs.rs/libcoap_sys/)
[![Documentation (main)](https://img.shields.io/badge/docs-main-blue)](https://namib-project.github.io/libcoap-rs-docs/docs/main/libcoap_sys/)
[![Test and Analyze CI Status](https://github.com/namib-project/libcoap-rs/actions/workflows/test.yml/badge.svg)](https://github.com/namib-project/libcoap-rs/actions/workflows/test.yml)
[![Coverage (main)](https://namib-project.github.io/libcoap-rs-docs/coverage/main/badges/flat.svg)](https://namib-project.github.io/libcoap-rs-docs/coverage/main/)

This crate contains raw unsafe bindings for the [libcoap CoAP libary](https://github.com/obgm/libcoap), which are
generated using bindgen.

Refer to this crate's documentation (linked in the badges above) for information on building and using
this crate.

## License

The libcoap-sys binding is licensed under the 2-Clause/Simplified BSD License, matching the license of the libcoap C
library it is a binding to.

Note that for the libcoap-sys binding and generated binaries, the license terms of the libcoap C library as well as
linked dependencies (e.g. TLS libraries) may apply.

Additionally, the libcoap C library contains some third-party code, for which different licensing terms apply.

See https://github.com/obgm/libcoap/blob/develop/LICENSE as well as the licenses of dependencies for more
information and terms.

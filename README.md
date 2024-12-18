# libcoap-rs

[![latest release on crates.io](https://img.shields.io/crates/v/libcoap_rs)](https://crates.io/crates/libcoap-rs)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest_release-blue)](https://docs.rs/libcoap_rs/)
[![Documentation (main)](https://img.shields.io/badge/docs-main-blue)](https://namib-project.github.io/libcoap-rs-docs/docs/main/libcoap_rs/)
[![Test and Analyze CI Status](https://github.com/namib-project/libcoap-rs/actions/workflows/test.yml/badge.svg)](https://github.com/namib-project/libcoap-rs/actions/workflows/test.yml)
[![Coverage (main)](https://namib-project.github.io/libcoap-rs-docs/coverage/main/badges/flat.svg)](https://namib-project.github.io/libcoap-rs-docs/coverage/main/)

Raw binding and safe wrapper for the [libcoap CoAP libary](https://github.com/obgm/libcoap).

Refer to the [documentation](https://docs.rs/libcoap-rs) for more information on using, building and the current state
of supported features.

## License

Matching the license of the libcoap C library, the libcoap-sys and the libcoap crates are licensed under the
2-Clause/Simplified BSD License ([LICENSE-BSD-2-Clause](LICENSE-BSD-2-CLAUSE)
or https://opensource.org/licenses/BSD-2-Clause).

### Note on Third-Party-Code

Note that for the libcoap-sys binding and generated binaries, the license terms of the libcoap C library as well as
linked dependencies (e.g. TLS libraries) may apply.
See https://github.com/obgm/libcoap/blob/develop/LICENSE as well as the licenses of dependency crates for more
information and terms.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.

## Maintainers

This project is currently maintained by the following developers:

|       Name       |    Email Address     |               GitHub Username                |
|:----------------:|:--------------------:|:--------------------------------------------:|
| Hugo Hakim Damer | hdamer@uni-bremen.de | [@pulsastrix](https://github.com/pulsastrix) |

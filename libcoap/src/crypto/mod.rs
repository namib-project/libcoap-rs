// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * crypto/mod.rs - CoAP cryptography provider interfaces and types.
 */

//! Cryptography interfaces and types.
//!
//! Currently, libcoap supports four different types of encrypted communications:
//! - (D)TLS using pre-shared keys (PSK): The simplest method, uses a symmetric/pre-shared key to
//!   perform authentication (see [RFC 4279](https://datatracker.ietf.org/doc/html/rfc4279)).
//! - (D)TLS using raw public keys (RPK): Uses asymmetric key pairs for authentication. The peer's
//!   public key must be known in advance and must be validated by the library user.
//! - (D)TLS using a public key infrastructure (PKI): Uses asymmetric key pairs signed by a
//!   certificate authority, which are authenticated by the TLS library using a set of
//!   pre-configured (or provided) root certificate authorities (the way most of the internet works).
//! - OSCORE (*unsupported by libcoap-rs, see
//!   [issue #23](https://github.com/namib-project/libcoap-rs/issues/23)*): Uses Object Security for
//!   Constrained RESTful Environments (OSCORE, [RFC 8613](https://datatracker.ietf.org/doc/html/rfc8613)) to encrypt messages on the application
//!   layer.
//!
//! # Configuration
//!
//! Logically, `libcoap` provides two different structures for DTLS configuration: One for PSK
//! configuration and another one for both PKI and RPK configurations.
//! Each of these DTLS contexts may be provided to either a
//! [`CoapClientSession`](crate::session::CoapClientSession) on construction or be attached to a
//! [`CoapContext`](crate::CoapContext) for server-side use.
//!
//! A client-side session can only be configured with _either_ a PKI/RPK configuration _or_ a PSK
//! configuration, i.e., you must know in advance which type of encryption to use.
//! The [`CoapContext`](crate::CoapContext) can be configured with both a server-side PKI/RPK
//! configuration _and_ a PSK configuration, but only with one of each type, i.e., you can support
//! both PSK and RPK/PKI, but not both RPK and PKI simultaneously, as the RPK/PKI configuration
//! object can only be configured to enable _either_ PKI _or_ RPK.
//!
//! For more information on how to configure the different types of encryption, see the module-level
//! documentation for the [PKI/RPK](pki_rpk) and [PSK](psk) submodules.
//!
//! You may also refer to the [libcoap documentation on encryption](https://libcoap.net/doc/reference/develop/man_coap_encryption.html)
//! for supplementary information.
//!
//! # Compilation and TLS library support
//!
//! Support for DTLS requires the `dtls-rpk`, `dtls-pki`, or `dtls-psk` features to be enabled,
//! depending on the DTLS variants you wish to support.
//!
//! libcoap may be built with different TLS libraries as backends, and support for the different
//! variants of DTLS and certain features within those may differ between libraries.
//! Assuming you have not called any unsafe functions that circumvent this check, enabling one of
//! the three DTLS variant features while using a TLS library that does not support this feature
//! will result in either a compilation error or a panic on when calling [`CoapContext::new`](crate::CoapContext::new),
//! irrespective of whether you actually use DTLS.
//!
//! Refer to the [libcoap_sys] documentation for more information on the build process specifics
//! regarding DTLS libraries.

#[cfg(any(feature = "dtls-rpk", feature = "dtls-pki"))]
pub mod pki_rpk;
#[cfg(feature = "dtls-psk")]
pub mod psk;

use std::fmt::Debug;

/// Client-side context for cryptography.
///
/// Can be provided to a client-side session constructor for encrypted sessions (such as
/// [`CoapClientSession::connect_dtls`](crate::session::CoapClientSession::connect_dtls)).
///
/// The available enum variants depend on the enabled DTLS features (`dtls-psk`, `dtls-pki`, and/or
/// `dtls-rpk`).
#[derive(Clone, Debug)]
pub enum ClientCryptoContext<'a> {
    /// Context for a client-side DTLS session with pre-shared keys.
    #[cfg(feature = "dtls-psk")]
    Psk(psk::ClientPskContext<'a>),
    /// Context for a client-side DTLS session using a public key infrastructure for certificate
    /// validation.
    #[cfg(feature = "dtls-pki")]
    Pki(pki_rpk::PkiRpkContext<'a, pki_rpk::Pki>),
    /// Context for a client-side DTLS session using raw public keys.
    #[cfg(feature = "dtls-rpk")]
    Rpk(pki_rpk::PkiRpkContext<'a, pki_rpk::Rpk>),
}

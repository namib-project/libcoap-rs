// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto/pki_rpk/mod.rs - Interfaces and types for PKI/RPK support in libcoap-rs.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
//! Types and traits related to (D)TLS with raw public keys and/or public key infrastructure support
//! for CoAP.
//!
//! In order to configure PKI and/or RPK support, the following general steps need to be followed:
//! 1. Create a key definition for the desired DTLS variant, see [`PkiKeyDef`](pki_rpk::PkiKeyDef)
//!    and [`RpkKeyDef`](pki_rpk::RpkKeyDef) for more detailed information.
//! 2. Create a [`PkiRpkContextBuilder`](pki_rpk::PkiRpkContextBuilder) using the provided key and
//!    (optionally) make some additional configuration changes (see the builder struct
//!    documentation).
//! 3. Call [`PkiRpkContextBuilder::build`](pki_rpk::PkiRpkContextBuilder::build) to create a
//!    [`PkiRpkContext`](pki_rpk::PkiRpkContext).
//! 4. Provide the created context to [`CoapClientSession::connect_dtls`](crate::session::CoapClientSession::connect_dtls)
//!    (for client-side sessions) or [`CoapContext::set_pki_rpk_context`](crate::CoapContext::set_pki_rpk_context)
//!    (for server-side sessions).
//! 5. On servers, run [`CoapContext::add_endpoint_dtls`](crate::CoapContext::add_endpoint_dtls) to
//!    add a DTLS endpoint.
//!
//! Note that [`PkiRpkContextBuilder`](pki_rpk::PkiRpkContextBuilder) uses generics with the marker
//! structs [`Pki`](pki_rpk::Pki) and [`Rpk`](pki_rpk::Rpk) to statically indicate the DTLS variant
//! and [`NonCertVerifying`](pki_rpk::NonCertVerifying) and [`CertVerifying`](pki_rpk::CertVerifying)
//! to indicate whether the peer certificate should be verified (PKI only, RPK will always use
//! [`NonCertVerifying`](pki_rpk::NonCertVerifying)).
//!
//! # Examples
#![cfg_attr(
    feature = "dtls-rpk",
    doc = r##"
Creating and connecting a client-side session with DTLS RPK configured:
```no_run
use libcoap_rs::CoapContext;
use libcoap_rs::crypto::pki_rpk::{NonCertVerifying, PkiRpkContextBuilder, Rpk, RpkKeyDef};
use libcoap_rs::session::{CoapClientSession, CoapSession};

// RPK is only supported if the key is provided as a byte array in memory, providing file paths
// directly is unsupported.
let client_private_key = Vec::from(include_str!("../../../resources/test-keys/client/client.key.pem"));
let client_public_key = Vec::from(include_str!("../../../resources/test-keys/client/client.pub.pem"));

// Create key definition.
let client_key_def = RpkKeyDef::with_pem_memory(client_public_key, client_private_key);

// Create the cryptography context. Note that you might have to explicitly specify that
// PKI certificate validation should not be performed, even though enabling it while passing a
// RPK key definition is impossible due to a lack of a constructor for
// `PkiRpkContextBuilder<Rpk, CertVerifying>`.
// This is a type system limitation.
let crypto_ctx = PkiRpkContextBuilder::<_, NonCertVerifying>::new(client_key_def);

let key_validator = |asn1_public_key: &[u8], session: &CoapSession, validated: bool| {
    if !validated {
        false
    } else {
        // Here, you would add code to validate that the peer's public key is actually the one you
        // expect, and return either true (accept key) or false (reject key).
        // `asn1_encoded_key` should be the certificate structure defined in
        // [RFC 7250, section 3](https://datatracker.ietf.org/doc/html/rfc7250#section-3), which you
        // might be able to parse with crates like
        // [x509-cert](https://docs.rs/x509-cert/latest/x509_cert/index.html) and
        // [spki](https://docs.rs/spki/0.7.3/spki/index.html) to obtain and match the
        // SubjectPublicKeyInformation encoded within.
        //
        // Instead of using a lambda like this, you could also implement `RpkValidator` on any
        // arbitrary type of your choice, e.g., a structure containing a storage of allowed public
        // keys.
        # true
    }
};

// Set the RPK validator and build the context.
let crypto_ctx = crypto_ctx.rpk_validator(key_validator).build();

let mut coap_ctx = CoapContext::new().expect("unable to create CoAP context");
let session = CoapClientSession::connect_dtls(&mut coap_ctx, "example.com:5684".parse().unwrap(), crypto_ctx);

// The session might not be immediately established, but you can already create and send
// requests as usual after this point.
// To check for errors and/or disconnections, you might want to call and check the return value
// of `session.state()` occasionally.
// For error handling, you might also want to register an event handler with the CoAP context.
// Remaining code omitted for brevity, see the crate-level docs for a full example of client
// operation.
```

Creating a server that supports DTLS RPK configured:
```no_run
use libcoap_rs::CoapContext;
use libcoap_rs::crypto::pki_rpk::{NonCertVerifying, PkiRpkContextBuilder, Rpk, RpkKeyDef};
use libcoap_rs::session::{CoapClientSession, CoapSession};

fn key_validator(asn1_public_key: &[u8], session: &CoapSession, validated: bool) -> bool {
    // Here, you would add code to validate that the peer's public key is actually the one you
    // expect, and return either true (accept key) or false (reject key).
    // `asn1_encoded_key` should be the certificate structure defined in
    // [RFC 7250, section 3](https://datatracker.ietf.org/doc/html/rfc7250#section-3), which you
    // might be able to parse with crates like
    // [x509-cert](https://docs.rs/x509-cert/latest/x509_cert/index.html) and
    // [spki](https://docs.rs/spki/0.7.3/spki/index.html) to obtain and match the
    // SubjectPublicKeyInformation encoded within.
    //
    // Instead of using a function like this, you could also implement `RpkValidator` on any
    // arbitrary type of your choice, e.g., a structure containing a storage of allowed public
    // keys.
    # true
}

// RPK is only supported if the key is provided as a byte array in memory, providing file paths
// directly is unsupported.
let server_private_key = Vec::from(include_str!("../../../resources/test-keys/server/server.key.pem"));
let server_public_key = Vec::from(include_str!("../../../resources/test-keys/server/server.pub.pem"));

// Create key definition.
let server_key_def = RpkKeyDef::with_pem_memory(server_public_key, server_private_key);

// Create the cryptography context. Note that you might have to explicitly specify that
// PKI certificate validation should not be performed, even though enabling it while passing a
// RPK key definition is impossible due to a lack of a constructor for
// `PkiRpkContextBuilder<Rpk, CertVerifying>`.
// This is a type system limitation.
let crypto_ctx = PkiRpkContextBuilder::<_, NonCertVerifying>::new(server_key_def);
// Set the RPK validator and build the context.
let crypto_ctx = crypto_ctx.rpk_validator(key_validator).build();

let mut coap_ctx = CoapContext::new().expect("unable to create CoAP context");
coap_ctx.set_pki_rpk_context(crypto_ctx);
coap_ctx.add_endpoint_dtls("[::1]:5684".parse().unwrap()).expect("unable to create DTLS endpoint");

// For error handling, you might want to register an event handler with the CoAP context.
// Remaining code omitted for brevity, see the crate-level docs for a full example of server
// operation.
```
"##
)]
#![cfg_attr(
    feature = "dtls-pki",
    doc = r##"

Creating and connecting a client-side session with DTLS PKI configured:
```no_run
use std::ffi::{c_uint, CStr};
use std::net::SocketAddr;
use libcoap_rs::CoapContext;
use libcoap_rs::crypto::pki_rpk::{CertVerifying, PkiKeyDef, PkiRpkContextBuilder};
use libcoap_rs::session::{CoapClientSession, CoapSession};
use std::ffi::CString;

// Paths to private key and certificate.
// The certificate may also contain intermediates. However, they might *not* be provided to the
// peer (i.e., the peer might have to already know all intermediates beforehand in order for
// validation to succeed).
let client_private_key = "../../../resources/test-keys/client/client.key.pem";
let client_public_cert = "../../../resources/test-keys/client/client.crt.pem";

// Create key definition.
// Note: the first argument (`ca_cert`) is not used to send intermediates and root certificates
// to the peer (unlike what you might expect if you have experience setting up HTTP servers).
// It is exclusively used to determine a list of CA names that a server will provide to a client
// to indicate to it which certificates it should send.
// For client-side operation, `ca_cert` is not used.
let client_key_def = PkiKeyDef::with_pem_files(
                        None::<String>,
                        client_public_cert,
                        client_private_key);

// The name of the server we want to connect to.
let server_name = "example.com";

// Validator function for certificate common names.
// Typically, this function should have the following behavior:
// - If !validated, something went wrong during TLS-level certificate checks, so reject.
// - If depth == 0, we are checking the client certificate, whose common name should equal the
//   server name we want to connect to, return the equality check result.
// - If depth > 0, we are checking an intermediate or root CA certificate. As we usually trust
//   all CAs in the trust store and validation of those is already performed by the TLS library,
//   always accept.
let c_server_name = CString::new(server_name).unwrap();
let cn_validator = |
     cn: &CStr,
     asn1_public_cert: &[u8],
     session: &CoapSession,
     depth: c_uint,
     validated: bool| {
    if !validated {
        false
    } else if depth == 0 {
        cn == c_server_name.as_c_str()
    } else {
        true
    }
};

// Create the cryptography context. Note that you must explicitly specify whether
// PKI certificate validation should be performed using the context builder's generics.
let crypto_ctx = PkiRpkContextBuilder::<_, CertVerifying>::new(client_key_def)
                 // Provide the server with a Server Name Indication (might be required by
                 // some servers to use the right certificate).
                 .client_sni(server_name).unwrap()
                 // Use the CN validator we defined earlier.
                 .cn_validator(cn_validator)
                 // Enable certificate chain validation (in case you have intermediate CAs) and set
                 // verification depth (recommended value here is 3).
                 .cert_chain_validation(3)
                 .build();

let mut coap_ctx = CoapContext::new().expect("unable to create CoAP context");
let session = CoapClientSession::connect_dtls(
             &mut coap_ctx,
             SocketAddr::new(server_name.parse().expect("error in name resolution"), 5684),
             crypto_ctx);

// The session might not be immediately established, but you can already create and send
// requests as usual after this point.
// To check for errors and/or disconnections, you might want to call and check the return value
// of `session.state()` occasionally.
// For error handling, you might also want to register an event handler with the CoAP context.
// Remaining code omitted for brevity, see the crate-level docs for a full example of client
// operation.
```

Creating a server that supports DTLS RPK configured:
```no_run
use std::ffi::{c_uint, CStr};
use std::net::SocketAddr;
use libcoap_rs::CoapContext;
use libcoap_rs::crypto::pki_rpk::{CertVerifying, PkiKeyDef, PkiRpkContextBuilder, KeyDef, Pki};
use libcoap_rs::session::{CoapClientSession, CoapSession};
use std::ffi::CString;

// Paths to private key and certificate.
// The certificate may also contain intermediates. However, they might *not* be provided to the
// peer (i.e., the peer might have to already know all intermediates beforehand in order for
// validation to succeed).
let server_private_key = "../../../resources/test-keys/server/server.key.pem";
let server_public_cert = "../../../resources/test-keys/server/server.crt.pem";
let ca_cert = "../../../resources/test-keys/ca/ca.crt.pem";

// Create key definition.
// Note: the first argument (`ca_cert`) is not used to send intermediates and root certificates
// to the peer (unlike what you might expect if you have experience setting up HTTP servers).
// It is exclusively used to determine a list of CA names that a server will provide to a client
// to indicate to it which certificates it should send.
let server_key_def = PkiKeyDef::with_pem_files(Some(ca_cert), server_public_cert, server_private_key);

// The name of the server we use.
let server_name = "example.com";

// Key provider for Server Name Indications.
// If the client provides a server name using the Server Name Indication extension, this
// callback is called to determine the key the server should use instead of the one provided as
// the default to `PkiRpkContextBuilder::new`.
// Typically, you would want to maintain a map from potential server names to key definitions,
// and return either `Some(Box::new(key))` for the appropriate map entry or `None` if the server
// name is unknown.
let c_server_name = CString::new(server_name).unwrap();
let sni_cb = |sni: &CStr| -> Option<Box<dyn KeyDef<KeyType = Pki>>> {
    (sni == c_server_name.as_c_str()).then_some(Box::new(server_key_def.clone()))
};

// Just like the client, the server may also have a CN validator defined to determine whether
// the common name of the client is acceptable. Here, we omit this validator for brevity.

// Create the cryptography context. Note that you must explicitly specify whether
// PKI certificate validation should be performed using the context builder's generics.
let crypto_ctx = PkiRpkContextBuilder::<_, CertVerifying>::new(server_key_def.clone())
                 .sni_key_provider(sni_cb)
                 // Enable certificate chain validation (in case you have intermediate CAs) and set
                 // verification depth (recommended value here is 3).
                 .cert_chain_validation(3)
                 .build();

let mut coap_ctx = CoapContext::new().expect("unable to create CoAP context");
coap_ctx.set_pki_rpk_context(crypto_ctx);
coap_ctx.add_endpoint_dtls("[::1]:5684".parse().unwrap()).expect("unable to create DTLS endpoint");

// For error handling, you might want to register an event handler with the CoAP context.
// Remaining code omitted for brevity, see the crate-level docs for a full example of server
// operation.
```
"##
)]

/// Data structures and builders for PKI/RPK keys.
mod key;
/// Code specific to PKI support.
#[cfg(feature = "dtls-pki")]
mod pki;
/// Code specific to RPK support.
#[cfg(feature = "dtls-rpk")]
mod rpk;

use std::{
    cell::RefCell,
    ffi::{c_char, c_int, c_uint, c_void, CStr, CString, NulError},
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ptr::NonNull,
    rc::{Rc, Weak},
};

pub use key::*;
use libcoap_sys::{
    coap_context_set_pki, coap_context_t, coap_dtls_key_t, coap_dtls_pki_t, coap_new_client_session_pki, coap_proto_t,
    coap_session_t, COAP_DTLS_PKI_SETUP_VERSION,
};
#[cfg(feature = "dtls-pki")]
pub use pki::*;
#[cfg(feature = "dtls-rpk")]
pub use rpk::*;

use crate::{
    error::{ContextConfigurationError, SessionCreationError},
    session::CoapSession,
    types::CoapAddress,
    CoapContext,
};

/// A context configuration for server-side PKI or RPK based DTLS encryption.
#[derive(Clone, Debug)]
pub enum ServerPkiRpkCryptoContext<'a> {
    /// PKI based configuration.
    #[cfg(feature = "dtls-pki")]
    Pki(PkiRpkContext<'a, Pki>),
    // RPK based configuration.
    #[cfg(feature = "dtls-rpk")]
    Rpk(PkiRpkContext<'a, Rpk>),
}

impl ServerPkiRpkCryptoContext<'_> {
    /// Apply this cryptographic context to the given raw `coap_context_t`.
    ///
    /// # Errors
    ///
    /// Will return [`ContextConfigurationError::Unknown`] if the call to the underlying libcoap
    /// function fails.
    ///
    /// # Safety
    /// The provided CoAP context must be valid and must not outlive this PkiRpkContext.
    pub(crate) unsafe fn apply_to_context(
        &self,
        ctx: NonNull<coap_context_t>,
    ) -> Result<(), ContextConfigurationError> {
        match self {
            #[cfg(feature = "dtls-pki")]
            ServerPkiRpkCryptoContext::Pki(v) => v.apply_to_context(ctx),
            #[cfg(feature = "dtls-rpk")]
            ServerPkiRpkCryptoContext::Rpk(v) => v.apply_to_context(ctx),
        }
    }
}

/// Marker indicating that a cryptographic context does not do TLS library-side certificate
/// verification.
///
/// # Implementation details (informative, not covered by semver guarantees)
/// A [`PkiRpkContext`] that is [`NonCertVerifying`] will set the `verify_peer_cert` field of the
/// underlying [`coap_dtls_pki_t`] to `0`.
pub struct NonCertVerifying;

/// Marker indicating that a cryptographic context does perform TLS library-side certificate
/// verification.
///
/// # Implementation details (informative, not covered by semver guarantees)
/// A [`PkiRpkContext`] that is [`CertVerifying`] will set the `verify_peer_cert` field of the
/// underlying [`coap_dtls_pki_t`] to `1`.
pub struct CertVerifying;

trait CertVerificationModeSealed {}

/// Trait for markers that indicate whether a PKI/RPK DTLS context performs certificate validation.
#[allow(private_bounds)]
pub trait CertVerificationMode: CertVerificationModeSealed {}

impl CertVerificationModeSealed for NonCertVerifying {}

impl CertVerificationModeSealed for CertVerifying {}

impl CertVerificationMode for NonCertVerifying {}

impl CertVerificationMode for CertVerifying {}

/// Builder for a PKI or RPK configuration context.
pub struct PkiRpkContextBuilder<'a, KTY: KeyType, V: CertVerificationMode> {
    ctx: PkiRpkContextInner<'a, KTY>,
    verifying: PhantomData<V>,
}

impl<'a, KTY: KeyType> PkiRpkContextBuilder<'a, KTY, NonCertVerifying> {
    /// Creates a new context builder with the given `key` as the default key to use.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Providing a raw public key will set `is_rpk_not_cert` to `1` in the underlying
    /// [`coap_dtls_pki_t`] structure. `pki_key` will be set to the provided key regardless of key
    /// type.
    pub fn new<K: KeyDef<KeyType = KTY> + 'a>(key: K) -> Self {
        let mut result = PkiRpkContextBuilder::<KTY, NonCertVerifying> {
            ctx: PkiRpkContextInner {
                raw_cfg: Box::new(coap_dtls_pki_t {
                    version: COAP_DTLS_PKI_SETUP_VERSION as u8,
                    verify_peer_cert: 0,
                    check_common_ca: 0,
                    allow_self_signed: 0,
                    allow_expired_certs: 0,
                    cert_chain_validation: 0,
                    cert_chain_verify_depth: 0,
                    check_cert_revocation: 0,
                    allow_no_crl: 0,
                    allow_expired_crl: 0,
                    allow_bad_md_hash: 0,
                    allow_short_rsa_length: 0,
                    is_rpk_not_cert: 0,
                    use_cid: 0,
                    reserved: Default::default(),
                    validate_cn_call_back: None,
                    cn_call_back_arg: std::ptr::null_mut(),
                    validate_sni_call_back: None,
                    sni_call_back_arg: std::ptr::null_mut(),
                    additional_tls_setup_call_back: None,
                    client_sni: std::ptr::null_mut(),
                    pki_key: key.as_raw_dtls_key(),
                }),
                provided_keys: vec![Box::new(key)],
                provided_key_descriptors: vec![],
                cn_callback: None,
                sni_key_provider: None,
                client_sni: None,
            },
            verifying: Default::default(),
        };
        KTY::set_key_type_defaults(result.ctx.raw_cfg.as_mut());
        result
    }
}

impl<KTY: KeyType, V: CertVerificationMode> PkiRpkContextBuilder<'_, KTY, V> {
    /// Enables/disables use of DTLS connection identifiers
    /// ([RFC 9146](https://datatracker.ietf.org/doc/html/rfc9146)) for the built context *if used
    /// in a client-side session*.
    ///
    /// For server-side sessions, this setting is ignored, and connection identifiers will always be
    /// used if supported by the underlying DTLS library.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `use_cid` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn use_cid(mut self, use_cid: bool) -> Self {
        self.ctx.raw_cfg.use_cid = use_cid.into();
        self
    }

    /// Sets the server name indication that should be sent to servers if the built
    /// [`PkiRpkContext`] is used in a client-side session.
    ///
    /// `client_sni` should be convertible into a byte string that does not contain null bytes.
    /// Typically, you would provide a `&str` or `String`.
    ///
    /// # Errors
    ///
    /// Will return [`NulError`] if the provided byte string contains null bytes.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `client_sni` in the underlying [`coap_dtls_pki_t`] structure.
    ///
    /// The provided `client_sni` will be converted into a `Box<[u8]>`, which will be owned and
    /// stored by the built context.
    pub fn client_sni(mut self, client_sni: impl Into<Vec<u8>>) -> Result<Self, NulError> {
        // For some reason, client_sni is not immutable here.
        // While I don't see any reason why libcoap would modify the string, it is not strictly
        // forbidden for it to do so, so simply using CString::into_raw() is not an option (as it
        // does not allow modifications to client_sni that change the length).
        let sni = CString::new(client_sni.into())?
            .into_bytes_with_nul()
            .into_boxed_slice();
        self.ctx.client_sni = Some(sni);
        self.ctx.raw_cfg.client_sni = self.ctx.client_sni.as_mut().unwrap().as_mut_ptr() as *mut c_char;
        Ok(self)
    }
}

impl<KTY: KeyType> PkiRpkContextBuilder<'_, KTY, CertVerifying> {
    /// Enables or disables checking whether both peers' certificates are signed by the same CA.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `check_common_ca` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn check_common_ca(mut self, check_common_ca: bool) -> Self {
        self.ctx.raw_cfg.check_common_ca = check_common_ca.into();
        self
    }

    /// Allows or disallows use of self-signed certificates by the peer.
    ///
    /// If `check_common_ca` has been enabled, this setting will be **ignored**.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `allow_self_signed` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn allow_self_signed(mut self, allow_self_signed: bool) -> Self {
        self.ctx.raw_cfg.allow_self_signed = allow_self_signed.into();
        self
    }

    /// Allows or disallows usage of expired certificates by the peer.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `allow_expired_certs` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn allow_expired_certs(mut self, allow_expired_certs: bool) -> Self {
        self.ctx.raw_cfg.allow_expired_certs = allow_expired_certs.into();
        self
    }

    /// Enables or disables verification of the entire certificate chain (up to
    /// `cert_chain_verify_depth`).
    ///
    /// If `cert_chain_verify_depth` is `0`, certificate chain validation is disabled.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `cert_chain_verify_depth` and `cert_chain_validation` in the
    /// underlying [`coap_dtls_pki_t`] structure.
    pub fn cert_chain_validation(mut self, cert_chain_verify_depth: u8) -> Self {
        self.ctx.raw_cfg.cert_chain_validation = if cert_chain_verify_depth == 0 { 0 } else { 1 };
        self.ctx.raw_cfg.cert_chain_verify_depth = cert_chain_verify_depth;
        self
    }

    /// Enables or disables certificate revocation checking.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `check_cert_revocation` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn check_cert_revocation(mut self, check_cert_revocation: bool) -> Self {
        self.ctx.raw_cfg.check_cert_revocation = check_cert_revocation.into();
        self
    }

    /// Allows or disallows disabling certificate revocation checking if a certificate does not have
    /// a CRL.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `allow_no_crl` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn allow_no_crl(mut self, allow_no_crl: bool) -> Self {
        self.ctx.raw_cfg.allow_no_crl = allow_no_crl.into();
        self
    }

    /// Allows or disallows disabling certificate revocation checking if a certificate has an
    /// expired CRL.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `allow_expired_crl` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn allow_expired_crl(mut self, allow_expired_crl: bool) -> Self {
        self.ctx.raw_cfg.allow_expired_crl = allow_expired_crl.into();
        self
    }

    /// Allows or disallows use of unsupported MD hashes.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `allow_bad_md_hash` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn allow_bad_md_hash(mut self, allow_bad_md_hash: bool) -> Self {
        self.ctx.raw_cfg.allow_bad_md_hash = allow_bad_md_hash.into();
        self
    }

    /// Allows or disallows small RSA key sizes.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `allow_short_rsa_length` in the underlying [`coap_dtls_pki_t`] structure.
    pub fn allow_short_rsa_length(mut self, allow_short_rsa_length: bool) -> Self {
        self.ctx.raw_cfg.allow_short_rsa_length = allow_short_rsa_length.into();
        self
    }
}

impl<'a, KTY: KeyType, V: CertVerificationMode> PkiRpkContextBuilder<'a, KTY, V> {
    /// Sets the key provider that provides keys for a SNI provided by a client (only used in
    /// server-side operation).
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Setting a `sni_key_provider` will set the `validate_sni_call_back` of the underlying
    /// [`coap_dtls_pki_t`] to a wrapper function, which will then call the key provider.
    ///
    /// Keys returned by the key provider will be stored in the context for at least as long as they
    /// are used by the respective session.
    pub fn sni_key_provider(mut self, sni_key_provider: impl PkiRpkSniKeyProvider<KTY> + 'a) -> Self {
        self.ctx.sni_key_provider = Some(Box::new(sni_key_provider));
        self.ctx.raw_cfg.validate_sni_call_back = Some(dtls_pki_sni_callback::<KTY>);
        self
    }

    /// Builds the configured `PkiRpkContext` by consuming this builder.
    pub fn build(self) -> PkiRpkContext<'a, KTY> {
        let ctx = Rc::new(RefCell::new(self.ctx));
        {
            let mut ctx_borrow = ctx.borrow_mut();
            if ctx_borrow.raw_cfg.validate_cn_call_back.is_some() {
                ctx_borrow.raw_cfg.cn_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void;
            }
            if ctx_borrow.raw_cfg.validate_sni_call_back.is_some() {
                ctx_borrow.raw_cfg.sni_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void;
            }
        }
        PkiRpkContext { inner: ctx }
    }
}

/// Inner structure of a [`PkiRpkContext`].
struct PkiRpkContextInner<'a, KTY: KeyType> {
    /// Raw PKI/RPK configuration structure.
    raw_cfg: Box<coap_dtls_pki_t>,
    /// Store for key definitions that we provided in previous callback invocations.
    provided_keys: Vec<Box<dyn KeyDef<KeyType = KTY> + 'a>>,
    /// Store for raw key definitions provided to libcoap.
    ///
    /// The stored raw pointers must all have been created by a call to `Box::into_raw`, and must
    /// remain valid as long as the respective session is still active.
    ///
    /// Using `Vec<coap_dtls_key_t>` instead is not an option, as a Vec resize may cause the
    /// instances to be moved to a different place in memory, invalidating pointers provided to
    /// libcoap.
    provided_key_descriptors: Vec<*mut coap_dtls_key_t>,
    /// User-provided CN callback that should be wrapped (either a PKI CN callback or a RPK public
    /// key validator).
    cn_callback: Option<CnCallback<'a>>,
    /// User-provided SNI key provider.
    sni_key_provider: Option<Box<dyn PkiRpkSniKeyProvider<KTY> + 'a>>,
    /// Byte string that client-side sessions using this context should send as SNI.
    ///
    /// Is referenced in raw_cfg and must therefore not be mutated for the lifetime of this context.
    client_sni: Option<Box<[u8]>>,
}

impl<KTY: KeyType> Debug for PkiRpkContextInner<'_, KTY> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiContextInner")
            .field(
                "raw_cfg",
                &format!("(does not implement Debug), address: {:p}", self.raw_cfg),
            )
            .field("provided_keys", &self.provided_keys)
            .field(
                "provided_key_descriptors",
                &format!(
                    "(values do not implement Debug), length: {}",
                    self.provided_key_descriptors.len()
                ),
            )
            .field("cn_callback", &"(value does not implement Debug)")
            .field("sni_key_provider", &"(value does not implement Debug)")
            .field("client_sni", &self.client_sni)
            .finish()
    }
}

impl<KTY: KeyType> Drop for PkiRpkContextInner<'_, KTY> {
    fn drop(&mut self) {
        for key_ref in std::mem::take(&mut self.provided_key_descriptors).into_iter() {
            // SAFETY: If the inner context is dropped, this implies that the pointers returned in
            // previous callbacks are no longer used (because of the contracts of apply_to_context()
            // and create_raw_session()). We can therefore restore and drop these values without
            // breaking the aliasing rules.
            unsafe {
                drop(Box::from_raw(key_ref));
            }
        }
        if !self.raw_cfg.cn_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been using a call to `Weak::into_raw` with the
            //         correct type, otherwise, the value will always be null.
            unsafe {
                Weak::from_raw(self.raw_cfg.cn_call_back_arg as *mut RefCell<Self>);
            }
        }
        if !self.raw_cfg.sni_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been using a call to `Weak::into_raw` with the
            //         correct type, otherwise, the value will always be null.
            unsafe {
                Weak::from_raw(self.raw_cfg.sni_call_back_arg as *mut RefCell<Self>);
            }
        }
    }
}

/// A configuration context for PKI or RPK based DTLS operation.
///
/// Whether PKI or RPK is configured for this context is indicated by the `KTY` generic, which may
/// either be [`Pki`] or [`Rpk`].
#[derive(Clone, Debug)]
pub struct PkiRpkContext<'a, KTY: KeyType> {
    /// Inner structure that is referenced by this context.
    inner: Rc<RefCell<PkiRpkContextInner<'a, KTY>>>,
}

impl<KTY: KeyType> PkiRpkContext<'_, KTY> {
    /// Creates a raw [`coap_session_t`] that is bound and uses this encryption context.
    ///
    /// # Safety
    ///
    /// This PkiRpkContext must outlive the returned [`coap_session_t`].
    pub(crate) unsafe fn create_raw_session(
        &self,
        ctx: &mut CoapContext<'_>,
        addr: &CoapAddress,
        proto: coap_proto_t,
    ) -> Result<NonNull<coap_session_t>, SessionCreationError> {
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null,
        // raw_cfg is of valid format (as constructed by the builder).
        {
            let mut inner = (*self.inner).borrow_mut();
            NonNull::new(unsafe {
                coap_new_client_session_pki(
                    ctx.as_mut_raw_context(),
                    std::ptr::null(),
                    addr.as_raw_address(),
                    proto,
                    inner.raw_cfg.as_mut(),
                )
            })
            .ok_or(SessionCreationError::Unknown)
        }
    }

    /// Configures the provided raw [`coap_context_t`] to use this encryption context for RPK or PKI
    /// based server-side operation.
    ///
    /// # Errors
    ///
    /// Will return [`ContextConfigurationError::Unknown`] if the call to the underlying libcoap
    /// function fails.
    ///
    /// # Safety
    ///
    /// The provided CoAP context must be valid and must not outlive this [`PkiRpkContext`].
    unsafe fn apply_to_context(&self, mut ctx: NonNull<coap_context_t>) -> Result<(), ContextConfigurationError> {
        let mut inner = self.inner.borrow_mut();
        // SAFETY: context is valid as per caller contract, raw_cfg is a valid configuration as
        // ensured by the builder.
        match unsafe { coap_context_set_pki(ctx.as_mut(), inner.raw_cfg.as_mut()) } {
            1 => Ok(()),
            _ => Err(ContextConfigurationError::Unknown),
        }
    }
}

impl<'a, KTY: KeyType> PkiRpkContext<'a, KTY> {
    /// Wrapper function for the user-provided CN callback.
    ///
    /// Calls the user-provided CN callback and converts its return value into the integer values
    /// libcoap expects.
    // cn and depth are unused only if dtls-pki feature is not enabled
    #[cfg_attr(not(feature = "dtls-pki"), allow(unused_variables))]
    fn cn_callback(
        &self,
        cn: &CStr,
        asn1_public_cert: &[u8],
        session: &CoapSession,
        depth: c_uint,
        validated: bool,
    ) -> c_int {
        let inner = (*self.inner).borrow();
        // This function is only ever called if a CN key provider is set, so it's fine to unwrap
        // here.
        if match inner.cn_callback.as_ref().unwrap() {
            #[cfg(feature = "dtls-pki")]
            CnCallback::Pki(pki) => pki.validate_cn(cn, asn1_public_cert, session, depth, validated),
            #[cfg(feature = "dtls-rpk")]
            CnCallback::Rpk(rpk) => rpk.validate_rpk(asn1_public_cert, session, validated),
        } {
            1
        } else {
            0
        }
    }

    /// Wrapper function for the user-provided SNI callback.
    ///
    /// Stores the returned key in a way that ensures it is accessible for libcoap for the lifetime
    /// of this encryption context.  
    ///
    /// **Important:** After the underlying [`PkiRpkContextInner`] is dropped, the returned
    /// pointer will no longer be valid and should no longer be dereferenced.
    fn sni_callback(&self, sni: &CStr) -> *mut coap_dtls_key_t {
        let mut inner = self.inner.borrow_mut();
        // This function is only ever called if an SNI key provider is set, so it's fine to unwrap
        // here.
        let key = inner.sni_key_provider.as_ref().unwrap().key_for_sni(sni);
        if let Some(key) = key {
            let key_ref = Box::into_raw(Box::new(key.as_raw_dtls_key()));
            inner.provided_keys.push(key);
            inner.provided_key_descriptors.push(key_ref);
            key_ref
        } else {
            std::ptr::null_mut()
        }
    }

    /// Restores a [`PkiRpkContext`] from a pointer to its inner structure (i.e. from the
    /// user-provided pointer given to DTLS callbacks).
    ///
    /// # Panics
    ///
    /// Panics if the given pointer is a null pointer or the inner structure was already dropped.
    ///
    /// # Safety
    /// The provided pointer must be a valid reference to a [`RefCell<PkiRpkContextInner<KTY>>`]
    /// instance created from a call to [`Weak::into_raw()`].
    unsafe fn from_raw(raw_ctx: *const RefCell<PkiRpkContextInner<'a, KTY>>) -> Self {
        assert!(!raw_ctx.is_null(), "provided raw DTLS PKI context was null");
        let inner_weak = Weak::from_raw(raw_ctx);
        let inner = inner_weak
            .upgrade()
            .expect("provided DTLS PKI context was already dropped!");
        let _ = Weak::into_raw(inner_weak);
        PkiRpkContext { inner }
    }
}

/// User-provided CN callback.
///
/// Depending on whether the encryption context is configured for RPK or PKI operation, the callback
/// will be either a [`PkiCnValidator`] or a [`RpkValidator`].
enum CnCallback<'a> {
    /// CN callback for PKI based configuration.
    #[cfg(feature = "dtls-pki")]
    Pki(Box<dyn PkiCnValidator + 'a>),
    /// CN callback for RPK based configuration.
    #[cfg(feature = "dtls-rpk")]
    Rpk(Box<dyn RpkValidator + 'a>),
}

/// Trait for things that can provide RPK/PKI DTLS keys for a given Server Name Indication.
pub trait PkiRpkSniKeyProvider<KTY: KeyType> {
    /// Provide a key for the server name indication given as `sni`, or `None` if the SNI is not
    /// valid and no key is available.
    ///
    /// Note that libcoap will remember the returned key and re-use it for future handshakes with
    /// the same SNI (even if the peer is not the same), the return value should therefore not
    /// depend on the provided `session`.
    fn key_for_sni(&self, sni: &CStr) -> Option<Box<dyn KeyDef<KeyType = KTY>>>;
}

impl<KTY: KeyType, T: Fn(&CStr) -> Option<Box<dyn KeyDef<KeyType = KTY>>>> PkiRpkSniKeyProvider<KTY> for T {
    fn key_for_sni(&self, sni: &CStr) -> Option<Box<dyn KeyDef<KeyType = KTY>>> {
        self(sni)
    }
}

/// Raw CN callback that can be provided to libcoap.
///
/// # Safety
///
/// This function expects the arguments to be provided in a way that libcoap would when invoking
/// this function as a CN callback.
///
/// Additionally, `session` must be a valid argument to [`CoapSession::from_raw`], and `arg` must be
/// a valid argument to [`PkiRpkContext::from_raw`] (where the key type of `PkiRpkContext` matches
/// the key type of this function).
unsafe extern "C" fn dtls_pki_cn_callback<KTY: KeyType>(
    cn: *const c_char,
    asn1_public_cert: *const u8,
    asn1_length: usize,
    session: *mut coap_session_t,
    depth: c_uint,
    validated: c_int,
    arg: *mut c_void,
) -> c_int {
    let session = CoapSession::from_raw(session);
    let cn = CStr::from_ptr(cn);
    let asn1_public_cert = std::slice::from_raw_parts(asn1_public_cert, asn1_length);
    let validated = validated == 1;
    let context = PkiRpkContext::from_raw(arg as *const RefCell<PkiRpkContextInner<KTY>>);
    context.cn_callback(cn, asn1_public_cert, &session, depth, validated)
}

/// Raw PKI/RPK SNI callback that can be provided to libcoap.
///
/// # Safety
///
/// This function expects the arguments to be provided in a way that libcoap would when invoking
/// this function as an PKI/RPK SNI callback.
///
/// Additionally, `arg` must be a valid argument to [`PkiRpkContext::from_raw`] (where the key type
/// of `PkiRpkContext` matches the key type of this function).
unsafe extern "C" fn dtls_pki_sni_callback<KTY: KeyType>(sni: *const c_char, arg: *mut c_void) -> *mut coap_dtls_key_t {
    let sni = CStr::from_ptr(sni);
    let context = PkiRpkContext::from_raw(arg as *const RefCell<PkiRpkContextInner<KTY>>);
    context.sni_callback(sni)
}

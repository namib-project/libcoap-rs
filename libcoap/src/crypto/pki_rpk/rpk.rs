// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto/pki_rpk/rpk.rs - Interfaces and types for RPK support in libcoap-rs.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use crate::crypto::pki_rpk;
use crate::crypto::pki_rpk::key::{KeyComponentSealed, KeyTypeSealed};
use crate::crypto::pki_rpk::{
    Asn1PrivateKeyType, CnCallback, KeyComponent, KeyDef, KeyDefSealed, NonCertVerifying, PemMemoryKeyComponent,
    Pkcs11KeyComponent, PkiRpkContext, PkiRpkContextBuilder, ServerPkiRpkCryptoContext,
};
use crate::crypto::ClientCryptoContext;
use crate::session::CoapSession;
use libcoap_sys::{
    coap_const_char_ptr_t, coap_dtls_key_t, coap_dtls_key_t__bindgen_ty_1, coap_dtls_pki_t, coap_pki_define_t,
    coap_pki_key_define_t, coap_pki_key_t,
};
use std::ffi::CString;
use std::fmt::Debug;

/// (Marker) key type for asymmetric DTLS keys not signed by a CA (raw public keys).
#[derive(Debug, Clone, Copy)]
pub struct Rpk {}

impl KeyTypeSealed for Rpk {
    fn set_key_type_defaults(ctx: &mut coap_dtls_pki_t) {
        ctx.is_rpk_not_cert = 1;
    }
}

// If PKI is enabled, implement conversions for PKI contexts to RPK-supporting server/client-side
// cryptographic contexts.

impl<'a> From<PkiRpkContext<'a, Rpk>> for ClientCryptoContext<'a> {
    fn from(value: PkiRpkContext<'a, Rpk>) -> Self {
        ClientCryptoContext::Rpk(value)
    }
}

impl<'a> From<PkiRpkContext<'a, Rpk>> for ServerPkiRpkCryptoContext<'a> {
    fn from(value: PkiRpkContext<'a, Rpk>) -> Self {
        ServerPkiRpkCryptoContext::Rpk(value)
    }
}

impl<'a> PkiRpkContextBuilder<'a, Rpk, NonCertVerifying> {
    /// Sets the raw public key validator for this encryption context.
    ///
    /// The raw public key validator's [`validate_rpk`](RpkValidator::validate_rpk) function will be
    /// called after the TLS-level validation checks have been completed in order to check whether
    /// the RPK provided by the peer is allowed/as expected.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Setting an RPK validator will set the `validate_cn_call_back` of the underlying
    /// [`coap_dtls_pki_t`] to a wrapper function, which will then call the RPK validator.
    pub fn rpk_validator(mut self, validator: impl RpkValidator + 'a) -> Self {
        self.ctx.cn_callback = Some(CnCallback::Rpk(Box::new(validator)));
        self.ctx.raw_cfg.validate_cn_call_back = Some(pki_rpk::dtls_pki_cn_callback::<Rpk>);
        self
    }
}

/// Trait for types that can validate that a raw public key is the one expected for a given peer.
pub trait RpkValidator {
    /// Validates the raw public key of a peer.
    ///
    /// This function is provided with the public key (`asn1_public_key`), the respective `session`,
    /// and the TLS library's `validated` status, and should return `true` if the connection is to
    /// be accepted and `false` if the connection should be aborted.
    ///
    /// `asn1_encoded_key` should be the certificate structure defined in
    /// [RFC 7250, section 3](https://datatracker.ietf.org/doc/html/rfc7250#section-3), which you
    /// might be able to parse with crates like
    /// [x509-cert](https://docs.rs/x509-cert/latest/x509_cert/index.html) and
    /// [spki](https://docs.rs/spki/0.7.3/spki/index.html) to obtain and match the
    /// SubjectPublicKeyInformation encoded within.
    ///
    /// See [the libcoap documentation](https://libcoap.net/doc/reference/4.3.5/group__dtls.html#gaef7a2800757a4922102311c94c3fa529)
    /// for more information.
    fn validate_rpk(&self, asn1_public_key: &[u8], session: &CoapSession, validated: bool) -> bool;
}

impl<T: Fn(&[u8], &CoapSession, bool) -> bool> RpkValidator for T {
    fn validate_rpk(&self, asn1_public_key: &[u8], session: &CoapSession, validated: bool) -> bool {
        self(asn1_public_key, session, validated)
    }
}

/// Key definition for a DTLS key consisting of a private and public key component without a signed
/// certificate.
///
/// # Note on key construction
///
/// For maximum compatibility, you should stick to the `with_*` constructors defined for this type.
/// While in theory you could use an arbitrary combination of key component types for a key
/// definition, those defined using `with_*` match explicit key types provided in libcoap and should
/// therefore always be supported.
#[derive(Clone, Debug)]
pub struct RpkKeyDef<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> {
    public_key: PK,
    private_key: SK,
    user_pin: Option<CString>,
    asn1_private_key_type: Asn1PrivateKeyType,
}

impl<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> RpkKeyDef<PK, SK> {
    /// Creates a new key definition using the given components.
    ///
    /// # Parameters
    ///
    /// - `public_key`:  The public key component of this key.
    /// - `private_key`: The private key.
    /// - `user_pin`:    The PIN that should be used when unlocking a token (for PKCS11 keys stored
    ///                  on a token, ignored otherwise)
    /// - `asn1_private_key_type`: The type of the private key (only used for DER/ASN.1 encoded
    ///                  keys).
    pub fn new(
        public_key: PK,
        private_key: SK,
        user_pin: Option<CString>,
        asn1_private_key_type: Asn1PrivateKeyType,
    ) -> Self {
        Self {
            public_key,
            private_key,
            user_pin,
            asn1_private_key_type,
        }
    }
}

impl RpkKeyDef<PemMemoryKeyComponent, PemMemoryKeyComponent> {
    /// Creates a new key definition using PEM-encoded byte sequences in memory as components.
    ///
    /// See the documentation of [`RpkKeyDef::new`] for more information on the parameters.
    pub fn with_pem_memory(
        public_key: impl Into<PemMemoryKeyComponent>,
        private_key: impl Into<PemMemoryKeyComponent>,
    ) -> Self {
        Self::new(public_key.into(), private_key.into(), None, Asn1PrivateKeyType::None)
    }
}

impl RpkKeyDef<Pkcs11KeyComponent, Pkcs11KeyComponent> {
    /// Creates a new key definition using PKCS11 URIs as components.
    ///
    /// See the documentation of [`RpkKeyDef::new`] for more information on the parameters.
    pub fn with_pkcs11(
        public_key: impl Into<Pkcs11KeyComponent>,
        private_key: impl Into<Pkcs11KeyComponent>,
        user_pin: Option<CString>,
    ) -> Self {
        Self::new(
            public_key.into(),
            private_key.into(),
            user_pin,
            Asn1PrivateKeyType::None,
        )
    }
}

impl<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> KeyDefSealed for RpkKeyDef<PK, SK> {
    fn as_raw_dtls_key(&self) -> coap_dtls_key_t {
        let (public_cert, public_cert_len) = self.public_key.as_raw_key_component();
        let (private_key, private_key_len) = self.private_key.as_raw_key_component();

        coap_dtls_key_t {
            key_type: coap_pki_key_t::COAP_PKI_KEY_DEFINE,
            key: coap_dtls_key_t__bindgen_ty_1 {
                define: coap_pki_key_define_t {
                    ca: coap_const_char_ptr_t {
                        u_byte: std::ptr::null(),
                    },
                    public_cert,
                    private_key,
                    ca_len: 0,
                    public_cert_len,
                    private_key_len,
                    ca_def: coap_pki_define_t::COAP_PKI_KEY_DEF_PEM,
                    public_cert_def: <PK as KeyComponentSealed<Rpk>>::DEFINE_TYPE,
                    private_key_def: <SK as KeyComponentSealed<Rpk>>::DEFINE_TYPE,
                    private_key_type: self.asn1_private_key_type.into(),
                    user_pin: self.user_pin.as_ref().map(|v| v.as_ptr()).unwrap_or(std::ptr::null()),
                },
            },
        }
    }
}

impl<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> KeyDef for RpkKeyDef<PK, SK> {
    type KeyType = Rpk;
}

impl KeyComponentSealed<Rpk> for PemMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_RPK_BUF;
}

impl KeyComponentSealed<Rpk> for Pkcs11KeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PKCS11_RPK;
}

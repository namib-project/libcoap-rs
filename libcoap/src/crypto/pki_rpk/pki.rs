// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto/pki_rpk/pki.rs - Interfaces and types for PKI support in libcoap-rs.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use crate::crypto::pki_rpk;
use crate::crypto::pki_rpk::key::{KeyComponentSealed, KeyTypeSealed};
use crate::crypto::pki_rpk::{
    Asn1PrivateKeyType, CertVerificationMode, CertVerifying, CnCallback, DerFileKeyComponent, DerMemoryKeyComponent,
    EngineKeyComponent, KeyComponent, KeyDef, KeyDefSealed, NonCertVerifying, PemFileKeyComponent,
    PemMemoryKeyComponent, Pkcs11KeyComponent, PkiRpkContext, PkiRpkContextBuilder, ServerPkiRpkCryptoContext,
};
use crate::crypto::ClientCryptoContext;
use crate::session::CoapSession;
use libcoap_sys::{
    coap_const_char_ptr_t, coap_dtls_key_t, coap_dtls_key_t__bindgen_ty_1, coap_dtls_pki_t, coap_pki_define_t,
    coap_pki_define_t_COAP_PKI_KEY_DEF_DER, coap_pki_define_t_COAP_PKI_KEY_DEF_DER_BUF,
    coap_pki_define_t_COAP_PKI_KEY_DEF_ENGINE, coap_pki_define_t_COAP_PKI_KEY_DEF_PEM,
    coap_pki_define_t_COAP_PKI_KEY_DEF_PEM_BUF, coap_pki_define_t_COAP_PKI_KEY_DEF_PKCS11, coap_pki_key_define_t
    , coap_pki_key_t_COAP_PKI_KEY_DEFINE,
};
use std::ffi::{c_uint, CStr, CString};
use std::fmt::Debug;

/// (Marker) key type for keys with a certificate signed by a trusted CA.
#[derive(Debug, Clone, Copy)]
pub struct Pki {}

impl KeyTypeSealed for Pki {
    fn set_key_type_defaults(ctx: &mut coap_dtls_pki_t) {
        ctx.is_rpk_not_cert = 0;
    }
}

// If PKI is enabled, implement conversions for PKI contexts to PKI-supporting server/client-side
// cryptographic contexts.

impl<'a> From<PkiRpkContext<'a, Pki>> for ServerPkiRpkCryptoContext<'a> {
    fn from(value: PkiRpkContext<'a, Pki>) -> Self {
        ServerPkiRpkCryptoContext::Pki(value)
    }
}

impl<'a> From<PkiRpkContext<'a, Pki>> for ClientCryptoContext<'a> {
    fn from(value: PkiRpkContext<'a, Pki>) -> Self {
        ClientCryptoContext::Pki(value)
    }
}

impl<'a> PkiRpkContextBuilder<'a, Pki, NonCertVerifying> {
    /// Enables PKI certificate verification of the peer's certificate when using the build
    /// encryption context.
    ///
    /// Note: While this will enable peer certificate validation, the other settings relating to
    /// certificate validation will not automatically be enabled.
    /// In particular, you might want to consider enabling certificate chain validation using
    /// [`PkiRpkContextBuilder::cert_chain_validation`].
    ///
    /// Depending on your circumstances, you might want to add additional root certificates
    /// using [`CoapContext::set_pki_root_cas`](crate::CoapContext::set_pki_root_ca_paths).
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `verify_peer_cert` to `1` in the underlying [`coap_dtls_pki_t`]
    /// structure.
    pub fn verify_peer_cert(mut self) -> PkiRpkContextBuilder<'a, Pki, CertVerifying> {
        self.ctx.raw_cfg.verify_peer_cert = 1;
        PkiRpkContextBuilder::<Pki, CertVerifying> {
            ctx: self.ctx,
            verifying: Default::default(),
        }
    }
}

impl<'a> PkiRpkContextBuilder<'a, Pki, CertVerifying> {
    pub fn new<K: KeyDef<KeyType = Pki> + 'a>(key: K) -> Self {
        PkiRpkContextBuilder::<'a, Pki, NonCertVerifying>::new(key).verify_peer_cert()
    }
}

impl<'a, V: CertVerificationMode> PkiRpkContextBuilder<'a, Pki, V> {
    /// Sets the common name validator for this encryption context.
    ///
    /// The common name validator's [`validate_cn`](PkiCnValidator::validate_cn) function will be
    /// called after the TLS level validation checks have been completed in order to check whether
    /// the common name provided by the peer is allowed/as expected.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Setting a `cn_validator` will set the `validate_cn_call_back` of the underlying
    /// [`coap_dtls_pki_t`] to a wrapper function, which will then call the CN validator.
    pub fn cn_validator(mut self, validator: impl PkiCnValidator + 'a) -> Self {
        self.ctx.cn_callback = Some(CnCallback::Pki(Box::new(validator)));
        self.ctx.raw_cfg.validate_cn_call_back = Some(pki_rpk::dtls_pki_cn_callback::<Pki>);
        self
    }
}

/// Trait for types that can check whether a peer's or CA certificate's common name is allowed/as
/// expected for a session.
pub trait PkiCnValidator {
    /// Validates the common name of a peer or intermediate certificate.
    ///
    /// Aside from the common name given as `cn`, this function is also provided with the raw bytes
    /// of the ASN.1/DER encoded public certificate (`asn1_public_cert`), the respective `session`,
    /// the TLS library's `validated` status and the current `depth` that should be validated.
    ///
    /// `depth` will be 0 for the peer's certificate, and larger than 0 for a CA certificate.
    ///
    /// Should return `true` if the connection is to be accepted and `false` if the connection
    /// should be aborted.
    ///
    /// See [the libcoap documentation](https://libcoap.net/doc/reference/4.3.5/group__dtls.html#gaef7a2800757a4922102311c94c3fa529)
    /// for more background information.
    fn validate_cn(
        &self,
        cn: &CStr,
        asn1_public_cert: &[u8],
        session: &CoapSession,
        depth: c_uint,
        validated: bool,
    ) -> bool;
}

impl<T: Fn(&CStr, &[u8], &CoapSession, c_uint, bool) -> bool> PkiCnValidator for T {
    fn validate_cn(
        &self,
        cn: &CStr,
        asn1_public_cert: &[u8],
        session: &CoapSession,
        depth: c_uint,
        validated: bool,
    ) -> bool {
        self(cn, asn1_public_cert, session, depth, validated)
    }
}

/// Key definition for a DTLS key consisting of a private key and a CA-signed certificate.
///
/// Optionally, it may also contain a CA certificate whose name will be sent to clients to indicate
/// the key that they should themselves send.
///
/// # Note on key construction
///
/// For maximum compatibility, you should stick to the `with_*` constructors defined for this type.
/// While in theory you could use an arbitrary combination of key component types for a key
/// definition, those defined using `with_*` match explicit key types provided in libcoap and should
/// therefore always be supported.
///
/// # The CA certificate field
///
/// **Important:** The CA certificate field/parameter is not to be confused with the CA certificate
/// you may set while configuring HTTP servers. The CA certificate will **not** be sent in full to
/// the peer during connection establishment and does not have to refer to the CA that signed the
/// public certificate.
/// It will only be used to set the CA list sent to the client for client certificate validation.
///
/// Therefore, in order for TLS certificate validation to succeed, the peer must already know the
/// root CA's and all intermediate CAs' certificates.
#[derive(Clone, Debug)]
pub struct PkiKeyDef<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> {
    ca_cert: Option<CA>,
    public_cert: PK,
    private_key: SK,
    user_pin: Option<CString>,
    asn1_private_key_type: Asn1PrivateKeyType,
}

impl<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> PkiKeyDef<CA, PK, SK> {
    /// Creates a new key definition using the given components.
    ///
    /// # Parameters
    ///
    /// - `ca_cert`:     The certificate of the CA whose name should be provided to clients when
    ///                  requesting client certificates.
    ///                  **Important:** See the section in the struct-level documentation regarding
    ///                  this field for more information.
    /// - `public_cert`: The public (signed) certificate of this key.
    /// - `private_key`: The private key.
    /// - `user_pin`:    The PIN that should be used when unlocking a token (for PKCS11 keys stored
    ///                  on a token, ignored otherwise)
    /// - `asn1_private_key_type`: The type of the private key (only used for DER/ASN.1 encoded
    ///                  keys).
    pub fn new(
        ca_cert: Option<CA>,
        public_cert: PK,
        private_key: SK,
        user_pin: Option<CString>,
        asn1_private_key_type: Asn1PrivateKeyType,
    ) -> Self {
        Self {
            ca_cert,
            public_cert,
            private_key,
            user_pin,
            asn1_private_key_type,
        }
    }
}

impl PkiKeyDef<PemFileKeyComponent, PemFileKeyComponent, PemFileKeyComponent> {
    /// Creates a new key definition using PEM-encoded files as components.
    ///
    /// See the documentation of [PkiKeyDef::new] for more information on the parameters, especially
    /// regarding the `ca_cert` field.
    pub fn with_pem_files(
        ca_cert: Option<impl Into<PemFileKeyComponent>>,
        public_cert: impl Into<PemFileKeyComponent>,
        private_key: impl Into<PemFileKeyComponent>,
    ) -> Self {
        Self::new(
            ca_cert.map(|v| v.into()),
            public_cert.into(),
            private_key.into(),
            None,
            Asn1PrivateKeyType::None,
        )
    }
}

impl PkiKeyDef<PemMemoryKeyComponent, PemMemoryKeyComponent, PemMemoryKeyComponent> {
    /// Creates a new key definition using PEM-encoded byte sequences in memory as components.
    ///
    /// See the documentation of [`PkiKeyDef::new`] for more information on the parameters, especially
    /// regarding the `ca_cert` field.
    pub fn with_pem_memory(
        ca_cert: Option<impl Into<PemMemoryKeyComponent>>,
        public_cert: impl Into<PemMemoryKeyComponent>,
        private_key: impl Into<PemMemoryKeyComponent>,
    ) -> Self {
        Self::new(
            ca_cert.map(|v| v.into()),
            public_cert.into(),
            private_key.into(),
            None,
            Asn1PrivateKeyType::None,
        )
    }
}

impl PkiKeyDef<DerFileKeyComponent, DerFileKeyComponent, DerFileKeyComponent> {
    /// Creates a new key definition using DER-encoded files as components.
    ///
    /// See the documentation of [`PkiKeyDef::new`] for more information on the parameters, especially
    /// regarding the `ca_cert` field.
    pub fn with_asn1_files(
        ca_cert: Option<impl Into<DerFileKeyComponent>>,
        public_cert: impl Into<DerFileKeyComponent>,
        private_key: impl Into<DerFileKeyComponent>,
        private_key_type: Asn1PrivateKeyType,
    ) -> Self {
        Self::new(
            ca_cert.map(|v| v.into()),
            public_cert.into(),
            private_key.into(),
            None,
            private_key_type,
        )
    }
}

impl PkiKeyDef<DerMemoryKeyComponent, DerMemoryKeyComponent, DerMemoryKeyComponent> {
    /// Creates a new key definition using DER-encoded byte sequences in memory as components.
    ///
    /// See the documentation of [`PkiKeyDef::new`] for more information on the parameters, especially
    /// regarding the `ca_cert` field.
    pub fn with_asn1_memory(
        ca_cert: Option<impl Into<DerMemoryKeyComponent>>,
        public_cert: impl Into<DerMemoryKeyComponent>,
        private_key: impl Into<DerMemoryKeyComponent>,
        private_key_type: Asn1PrivateKeyType,
    ) -> Self {
        Self::new(
            ca_cert.map(|v| v.into()),
            public_cert.into(),
            private_key.into(),
            None,
            private_key_type,
        )
    }
}

impl PkiKeyDef<Pkcs11KeyComponent, Pkcs11KeyComponent, Pkcs11KeyComponent> {
    /// Creates a new key definition using PKCS11 URIs as components.
    ///
    /// See the documentation of [`PkiKeyDef::new`] for more information on the parameters, especially
    /// regarding the `ca_cert` field.
    pub fn with_pkcs11(
        ca_cert: Option<impl Into<Pkcs11KeyComponent>>,
        public_cert: impl Into<Pkcs11KeyComponent>,
        private_key: impl Into<Pkcs11KeyComponent>,
        user_pin: Option<CString>,
    ) -> Self {
        Self::new(
            ca_cert.map(|v| v.into()),
            public_cert.into(),
            private_key.into(),
            user_pin,
            Asn1PrivateKeyType::None,
        )
    }
}

impl<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> KeyDefSealed for PkiKeyDef<CA, PK, SK> {
    fn as_raw_dtls_key(&self) -> coap_dtls_key_t {
        let (ca, ca_len) = self.ca_cert.as_ref().map(|v| v.as_raw_key_component()).unwrap_or((
            coap_const_char_ptr_t {
                u_byte: std::ptr::null(),
            },
            0,
        ));
        let (public_cert, public_cert_len) = self.public_cert.as_raw_key_component();
        let (private_key, private_key_len) = self.private_key.as_raw_key_component();

        coap_dtls_key_t {
            key_type: coap_pki_key_t_COAP_PKI_KEY_DEFINE,
            key: coap_dtls_key_t__bindgen_ty_1 {
                define: coap_pki_key_define_t {
                    ca,
                    public_cert,
                    private_key,
                    ca_len,
                    public_cert_len,
                    private_key_len,
                    ca_def: <CA as KeyComponentSealed<Pki>>::DEFINE_TYPE,
                    public_cert_def: <PK as KeyComponentSealed<Pki>>::DEFINE_TYPE,
                    private_key_def: <SK as KeyComponentSealed<Pki>>::DEFINE_TYPE,
                    private_key_type: self.asn1_private_key_type.into(),
                    user_pin: self.user_pin.as_ref().map(|v| v.as_ptr()).unwrap_or(std::ptr::null()),
                },
            },
        }
    }
}

impl<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> KeyDef for PkiKeyDef<CA, PK, SK> {
    type KeyType = Pki;
}

impl KeyComponentSealed<Pki> for PemFileKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t_COAP_PKI_KEY_DEF_PEM;
}

impl KeyComponentSealed<Pki> for PemMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t_COAP_PKI_KEY_DEF_PEM_BUF;
}

impl KeyComponentSealed<Pki> for DerFileKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t_COAP_PKI_KEY_DEF_DER;
}

impl KeyComponentSealed<Pki> for DerMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t_COAP_PKI_KEY_DEF_DER_BUF;
}

impl KeyComponentSealed<Pki> for Pkcs11KeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t_COAP_PKI_KEY_DEF_PKCS11;
}

impl KeyComponentSealed<Pki> for EngineKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t_COAP_PKI_KEY_DEF_ENGINE;
}

use crate::crypto::ClientCryptoContext;
use std::fmt::Debug;
use std::ffi::{c_uint, CStr, CString};
use libcoap_sys::{coap_const_char_ptr_t, coap_dtls_key_t, coap_dtls_key_t__bindgen_ty_1, coap_pki_define_t, coap_pki_key_define_t, coap_pki_key_t};
use crate::crypto::pki_rpk;
use crate::crypto::pki_rpk::{Asn1PrivateKeyType, CertVerificationMode, CertVerifying, CnCallback, DerFileKeyComponent, DerMemoryKeyComponent, EngineKeyComponent, KeyComponent, KeyDef, KeyDefSealed, KeyType, NonCertVerifying, PemFileKeyComponent, PemMemoryKeyComponent, Pkcs11KeyComponent, PkiRpkContext, PkiRpkContextBuilder, ServerPkiRpkCryptoContext};
use crate::crypto::pki_rpk::key::{KeyTypeSealed, KeyComponentSealed};
use crate::session::CoapSession;

impl<'a> From<PkiRpkContext<'a, Pki>> for ServerPkiRpkCryptoContext<'a> {
    fn from(value: PkiRpkContext<'a, Pki>) -> Self {
        ServerPkiRpkCryptoContext::Pki(value)
    }
}

impl<'a> From<PkiRpkContext<'a, Pki>> for ClientCryptoContext<'a> {
    fn from(value: pki_rpk::PkiRpkContext<'a, pki_rpk::Pki>) -> Self {
        ClientCryptoContext::Pki(value)
    }
}

impl<'a> PkiRpkContextBuilder<'a, Pki, NonCertVerifying> {
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
    pub fn cn_validator(mut self, validator: impl PkiCnValidator + 'a) -> Self {
        self.ctx.cn_callback = Some(CnCallback::Pki(Box::new(validator)));
        self.ctx.raw_cfg.validate_cn_call_back = Some(pki_rpk::dtls_pki_cn_callback::<Pki>);
        self
    }
}

pub trait PkiCnValidator: Debug {
    fn validate_cn(
        &self,
        cn: &CStr,
        asn1_public_cert: &[u8],
        session: &CoapSession,
        depth: c_uint,
        validated: bool,
    ) -> bool;
}

#[derive(Debug, Clone, Copy)]
pub struct Pki {}

impl KeyTypeSealed for Pki {}

#[derive(Clone, Debug)]
pub struct PkiKeyDef<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> {
    ca_cert: Option<CA>,
    public_cert: PK,
    private_key: SK,
    user_pin: Option<CString>,
    asn1_private_key_type: Asn1PrivateKeyType,
}

impl<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> PkiKeyDef<CA, PK, SK> {
    pub fn new(ca_cert: Option<CA>, public_cert: PK, private_key: SK, user_pin: Option<CString>, asn1_private_key_type: Asn1PrivateKeyType) -> Self {
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
    pub fn with_pem_files(ca_cert: Option<impl Into<PemFileKeyComponent>>, public_cert: impl Into<PemFileKeyComponent>, private_key: impl Into<PemFileKeyComponent>) -> Self {
        Self::new(ca_cert.map(|v| v.into()), public_cert.into(), private_key.into(), None, Asn1PrivateKeyType::None)
    }
}

impl PkiKeyDef<PemMemoryKeyComponent, PemMemoryKeyComponent, PemMemoryKeyComponent> {
    pub fn with_pem_memory(ca_cert: Option<impl Into<PemMemoryKeyComponent>>, public_cert: impl Into<PemMemoryKeyComponent>, private_key: impl Into<PemMemoryKeyComponent>) -> Self {
        Self::new(ca_cert.map(|v| v.into()), public_cert.into(), private_key.into(), None, Asn1PrivateKeyType::None)
    }
}

impl PkiKeyDef<DerFileKeyComponent, DerFileKeyComponent, DerFileKeyComponent> {
    pub fn with_asn1_files(ca_cert: Option<impl Into<DerFileKeyComponent>>, public_cert: impl Into<DerFileKeyComponent>, private_key: impl Into<DerFileKeyComponent>, private_key_type: Asn1PrivateKeyType) -> Self {
        Self::new(ca_cert.map(|v| v.into()), public_cert.into(), private_key.into(), None, private_key_type)
    }
}

impl PkiKeyDef<DerMemoryKeyComponent, DerMemoryKeyComponent, DerMemoryKeyComponent> {
    pub fn with_asn1_memory(ca_cert: Option<impl Into<DerMemoryKeyComponent>>, public_cert: impl Into<DerMemoryKeyComponent>, private_key: impl Into<DerMemoryKeyComponent>, private_key_type: Asn1PrivateKeyType) -> Self {
        Self::new(ca_cert.map(|v| v.into()), public_cert.into(), private_key.into(), None, private_key_type)
    }
}

impl PkiKeyDef<Pkcs11KeyComponent, Pkcs11KeyComponent, Pkcs11KeyComponent> {
    pub fn with_pkcs11(ca_cert: Option<impl Into<Pkcs11KeyComponent>>, public_cert: impl Into<Pkcs11KeyComponent>, private_key: impl Into<Pkcs11KeyComponent>, user_pin: Option<CString>) -> Self {
        Self::new(ca_cert.map(|v| v.into()), public_cert.into(), private_key.into(), user_pin, Asn1PrivateKeyType::None)
    }
}

impl<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> KeyDefSealed for PkiKeyDef<CA, PK, SK> {

    fn as_raw_dtls_key(&self) -> coap_dtls_key_t {
        let (ca, ca_len) = self.ca_cert.as_ref().map(|v| v.as_raw_key_component()).unwrap_or((coap_const_char_ptr_t {u_byte: std::ptr::null()}, 0));
        let (public_cert, public_cert_len) = self.public_cert.as_raw_key_component();
        let (private_key, private_key_len) = self.private_key.as_raw_key_component();

        coap_dtls_key_t {
            key_type: coap_pki_key_t::COAP_PKI_KEY_DEFINE,
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
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PEM;
}

impl KeyComponentSealed<Pki> for PemMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PEM_BUF;
}

impl KeyComponentSealed<Pki> for DerFileKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_DER;
}

impl KeyComponentSealed<Pki> for DerMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_DER_BUF;
}

impl KeyComponentSealed<Pki> for Pkcs11KeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PKCS11;
}

impl KeyComponentSealed<Pki> for EngineKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_ENGINE;
}

use crate::crypto::ClientCryptoContext;
use std::ffi::CString;
use std::fmt::Debug;
use libcoap_sys::{coap_const_char_ptr_t, coap_dtls_key_t, coap_dtls_key_t__bindgen_ty_1, coap_pki_define_t, coap_pki_key_define_t, coap_pki_key_t};
use crate::crypto::pki_rpk;
use crate::crypto::pki_rpk::key::{KeyComponentSealed, KeyTypeSealed};
use crate::crypto::pki_rpk::{Asn1PrivateKeyType, CnCallback, KeyComponent, KeyDef, KeyDefSealed, NonCertVerifying, PemMemoryKeyComponent, Pkcs11KeyComponent, PkiRpkContext, PkiRpkContextBuilder, ServerPkiRpkCryptoContext};
use crate::session::CoapSession;

#[derive(Debug, Clone, Copy)]
pub struct Rpk {}

impl KeyTypeSealed for Rpk {}

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

pub trait RpkValidator: Debug {
    fn validate_rpk(&self, asn1_public_key: &[u8], session: &CoapSession, validated: bool) -> bool;
}

#[derive(Clone, Debug)]
pub struct RpkKeyDef<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> {
    public_key: PK,
    private_key: SK,
    user_pin: Option<CString>,
    asn1_private_key_type: Asn1PrivateKeyType,
}

impl<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> RpkKeyDef<PK, SK> {
    pub fn new(public_key: PK, private_key: SK, user_pin: Option<CString>, asn1_private_key_type: Asn1PrivateKeyType) -> Self {
        Self {
            public_key,
            private_key,
            user_pin,
            asn1_private_key_type,
        }
    }
}

impl RpkKeyDef<PemMemoryKeyComponent, PemMemoryKeyComponent> {
    pub fn with_pem_memory(public_key: impl Into<PemMemoryKeyComponent>, private_key: impl Into<PemMemoryKeyComponent>) -> Self {
        Self::new(public_key.into(), private_key.into(), None, Asn1PrivateKeyType::None)
    }
}

impl RpkKeyDef<Pkcs11KeyComponent, Pkcs11KeyComponent> {
    pub fn with_pkcs11(public_key: impl Into<Pkcs11KeyComponent>, private_key: impl Into<Pkcs11KeyComponent>, user_pin: Option<CString>) -> Self {
        Self::new(public_key.into(), private_key.into(), user_pin, Asn1PrivateKeyType::None)
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

impl<'a> PkiRpkContextBuilder<'a, Rpk, NonCertVerifying> {
    pub fn rpk_validator(mut self, validator: impl RpkValidator + 'a) -> Self {
        self.ctx.cn_callback = Some(CnCallback::Rpk(Box::new(validator)));
        self.ctx.raw_cfg.validate_cn_call_back = Some(pki_rpk::dtls_pki_cn_callback::<Rpk>);
        self
    }
}

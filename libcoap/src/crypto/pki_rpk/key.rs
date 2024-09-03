use libcoap_sys::{
    coap_asn1_privatekey_type_t, coap_const_char_ptr_t, coap_dtls_key_t, coap_dtls_key_t__bindgen_ty_1,
    coap_pki_define_t, coap_pki_key_define_t, coap_pki_key_t,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::ffi::CString;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy)]
pub struct Pki {}
#[derive(Debug, Clone, Copy)]
pub struct Rpk {}

pub trait KeyType: KeyTypeSealed {}

trait KeyTypeSealed: Debug {}

impl KeyTypeSealed for Pki {}

impl KeyTypeSealed for Rpk {}

impl<T: KeyTypeSealed> KeyType for T {}

#[derive(Clone, Debug)]
pub struct PkiKeyDef<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> {
    ca_cert: Option<CA>,
    public_key: PK,
    private_key: SK,
    user_pin: Option<CString>,
    asn1_private_key_type: Asn1PrivateKeyType,
}

impl<CA: KeyComponent<Pki>, PK: KeyComponent<Pki>, SK: KeyComponent<Pki>> KeyDefSealed for PkiKeyDef<CA, PK, SK> {
    type KeyType = Pki;

    fn as_raw_dtls_key(&self) -> coap_dtls_key_t {
        let (ca, ca_len) = self.ca_cert.as_ref().map(|v| v.as_raw_pki_definition()).unwrap_or((
            coap_const_char_ptr_t {
                s_byte: std::ptr::null(),
            },
            0,
        ));
        let (public_cert, public_cert_len) = self.public_key.as_raw_pki_definition();
        let (private_key, private_key_len) = self.private_key.as_raw_pki_definition();

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

#[derive(Clone, Debug)]
pub struct RpkKeyDef<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> {
    public_key: PK,
    private_key: SK,
    user_pin: Option<CString>,
    asn1_private_key_type: Asn1PrivateKeyType,
}

impl<PK: KeyComponent<Rpk>, SK: KeyComponent<Rpk>> KeyDefSealed for RpkKeyDef<PK, SK> {
    type KeyType = Rpk;

    fn as_raw_dtls_key(&self) -> coap_dtls_key_t {
        let (public_cert, public_cert_len) = self.public_key.as_raw_pki_definition();
        let (private_key, private_key_len) = self.private_key.as_raw_pki_definition();

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

pub(crate) trait KeyDefSealed: Debug {
    type KeyType: KeyType;
    fn as_raw_dtls_key(&self) -> coap_dtls_key_t;
}

pub trait KeyDef: KeyDefSealed {}

impl<T: KeyDefSealed> KeyDef for T {}

pub trait KeyComponentSealed<KTY: KeyType>: Sized + Debug {
    const DEFINE_TYPE: coap_pki_define_t;
    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize);
}

pub trait KeyComponent<KTY: KeyType>: KeyComponentSealed<KTY> {}

impl<KTY: KeyType, T: KeyComponentSealed<KTY>> KeyComponent<KTY> for T {}

#[derive(Clone, Debug)]
pub struct PemFileKeyComponent(CString);

impl KeyComponentSealed<Pki> for PemFileKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PEM;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

#[derive(Clone, Debug)]
pub struct PemMemoryKeyComponent(Box<[u8]>);

impl KeyComponentSealed<Pki> for PemMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PEM_BUF;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                u_byte: self.0.as_ptr(),
            },
            self.0.len(),
        )
    }
}

impl KeyComponentSealed<Rpk> for PemMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_RPK_BUF;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                u_byte: self.0.as_ptr(),
            },
            self.0.len(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct DerFileKeyComponent(CString);

impl KeyComponentSealed<Pki> for DerFileKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_DER;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

#[derive(Clone, Debug)]
pub struct DerMemoryKeyComponent(Box<[u8]>);

impl KeyComponentSealed<Rpk> for DerMemoryKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_DER_BUF;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                u_byte: self.0.as_ptr(),
            },
            self.0.len(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct Pkcs11KeyComponent(CString);

impl KeyComponentSealed<Pki> for Pkcs11KeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PKCS11;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

impl KeyComponentSealed<Rpk> for Pkcs11KeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_PKCS11_RPK;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

#[derive(Clone, Debug)]
pub struct EngineKeyComponent(CString);

impl KeyComponentSealed<Pki> for EngineKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t = coap_pki_define_t::COAP_PKI_KEY_DEF_ENGINE;

    fn as_raw_pki_definition(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

#[repr(C)]
#[derive(Copy, Clone, FromPrimitive, Debug, PartialEq, Eq, Hash)]
pub enum Asn1PrivateKeyType {
    None = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_NONE as isize,
    Rsa = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_RSA as isize,
    Rsa2 = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_RSA2 as isize,
    Dsa = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA as isize,
    Dsa1 = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA1 as isize,
    Dsa2 = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA2 as isize,
    Dsa3 = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA3 as isize,
    Dsa4 = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA4 as isize,
    Dh = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DH as isize,
    Dhx = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DHX as isize,
    Ec = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_EC as isize,
    Hmac = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_HMAC as isize,
    Cmac = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_CMAC as isize,
    Tls1Prf = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_TLS1_PRF as isize,
    Hkdf = coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_HKDF as isize,
}

impl Default for Asn1PrivateKeyType {
    fn default() -> Self {
        Asn1PrivateKeyType::None
    }
}

impl From<Asn1PrivateKeyType> for coap_asn1_privatekey_type_t {
    fn from(value: Asn1PrivateKeyType) -> Self {
        match value {
            Asn1PrivateKeyType::None => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_NONE,
            Asn1PrivateKeyType::Rsa => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_RSA,
            Asn1PrivateKeyType::Rsa2 => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_RSA2,
            Asn1PrivateKeyType::Dsa => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA,
            Asn1PrivateKeyType::Dsa1 => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA1,
            Asn1PrivateKeyType::Dsa2 => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA2,
            Asn1PrivateKeyType::Dsa3 => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA3,
            Asn1PrivateKeyType::Dsa4 => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DSA4,
            Asn1PrivateKeyType::Dh => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DH,
            Asn1PrivateKeyType::Dhx => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_DHX,
            Asn1PrivateKeyType::Ec => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_EC,
            Asn1PrivateKeyType::Hmac => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_HMAC,
            Asn1PrivateKeyType::Cmac => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_CMAC,
            Asn1PrivateKeyType::Tls1Prf => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_TLS1_PRF,
            Asn1PrivateKeyType::Hkdf => coap_asn1_privatekey_type_t::COAP_ASN1_PKEY_HKDF,
        }
    }
}

impl From<coap_asn1_privatekey_type_t> for Asn1PrivateKeyType {
    fn from(value: coap_asn1_privatekey_type_t) -> Self {
        FromPrimitive::from_isize(value as isize).expect("unknown ASN1 private key type")
    }
}

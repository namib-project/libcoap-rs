use libcoap_sys::{
    coap_asn1_privatekey_type_t, coap_const_char_ptr_t, coap_dtls_key_t,
    coap_pki_define_t,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::ffi::CString;
use std::fmt::Debug;
use std::path::Path;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[allow(private_bounds)]
pub trait KeyType: KeyTypeSealed {}

pub(super) trait KeyTypeSealed: Debug {}

impl<T: KeyTypeSealed> KeyType for T {}

pub(crate) trait KeyDefSealed: Debug {
    fn as_raw_dtls_key(&self) -> coap_dtls_key_t;
}

#[allow(private_bounds)]
pub trait KeyDef: KeyDefSealed {
    type KeyType: KeyType;
}

pub(super) trait AsRawKeyComponent: Sized + Debug {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize);
}

pub(super) trait KeyComponentSealed<KTY: KeyType>: AsRawKeyComponent {
    const DEFINE_TYPE: coap_pki_define_t;
}

#[allow(private_bounds)]
pub trait KeyComponent<KTY: KeyType>: KeyComponentSealed<KTY> {}

impl<KTY: KeyType, T: KeyComponentSealed<KTY>> KeyComponent<KTY> for T {}

#[derive(Clone, Debug)]
pub struct PemFileKeyComponent(CString);

impl AsRawKeyComponent for PemFileKeyComponent {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

#[cfg(unix)]
impl<T: AsRef<Path>> From<T> for PemFileKeyComponent {
    fn from(value: T) -> Self {
        // File paths never contain null-bytes on unix, so we can unwrap here.
        PemFileKeyComponent(CString::new(value.as_ref().as_os_str().as_bytes()).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct PemMemoryKeyComponent(Box<[u8]>);

impl<T: Into<Vec<u8>>> From<T> for PemMemoryKeyComponent {
    fn from(value: T) -> Self {
        PemMemoryKeyComponent(value.into().into_boxed_slice())
    }
}

impl AsRawKeyComponent for PemMemoryKeyComponent {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize) {
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

impl AsRawKeyComponent for DerFileKeyComponent {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

#[cfg(unix)]
impl<T: AsRef<Path>> From<T> for DerFileKeyComponent {
    fn from(value: T) -> Self {
        // File paths never contain null-bytes on unix, so we can unwrap here.
        DerFileKeyComponent(CString::new(value.as_ref().as_os_str().as_bytes()).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct DerMemoryKeyComponent(Box<[u8]>);

impl AsRawKeyComponent for DerMemoryKeyComponent {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                u_byte: self.0.as_ptr(),
            },
            self.0.len(),
        )
    }
}

impl<T: Into<Vec<u8>>> From<T> for DerMemoryKeyComponent {
    fn from(value: T) -> Self {
        DerMemoryKeyComponent(value.into().into_boxed_slice())
    }
}

#[derive(Clone, Debug)]
pub struct Pkcs11KeyComponent(CString);

impl AsRawKeyComponent for Pkcs11KeyComponent {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

impl From<CString> for Pkcs11KeyComponent {
    fn from(value: CString) -> Self {
        Pkcs11KeyComponent(value)
    }
}

#[derive(Clone, Debug)]
pub struct EngineKeyComponent(CString);

impl AsRawKeyComponent for EngineKeyComponent {
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize) {
        (
            coap_const_char_ptr_t {
                s_byte: self.0.as_ptr(),
            },
            0,
        )
    }
}

impl From<CString> for EngineKeyComponent {
    fn from(value: CString) -> Self {
        EngineKeyComponent(value)
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

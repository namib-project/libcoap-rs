// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto/pki_rpk/key.rs - Interfaces and types for PKI/RPK keys in libcoap-rs.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use libcoap_sys::{
    coap_asn1_privatekey_type_t, coap_const_char_ptr_t, coap_dtls_key_t, coap_dtls_pki_t, coap_pki_define_t,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::ffi::CString;
use std::fmt::Debug;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Trait for marker structs that describe different types of asymmetric DTLS keys (RPK or PKI).
#[allow(private_bounds)]
pub trait KeyType: KeyTypeSealed {}

/// Sealed trait for key types.
pub(super) trait KeyTypeSealed: Debug {
    /// Applies default settings for this key type to the given encryption context `ctx`.
    fn set_key_type_defaults(ctx: &mut coap_dtls_pki_t);
}

impl<T: KeyTypeSealed> KeyType for T {}

/// Trait for types that can be used as a libcoap DTLS asymmetric key definition (RPK or PKI).
#[allow(private_bounds)]
pub trait KeyDef: KeyDefSealed {
    /// The key type of this key definition.
    type KeyType: KeyType;
}

/// Sealed trait for key definitions.
pub(crate) trait KeyDefSealed: Debug {
    /// Creates a raw key definition based on this key definition.
    ///
    /// **Important:** The returned raw definition refers to memory owned by `self`.
    /// While this function alone can not cause undefined behavior (and is therefore not `unsafe`),
    /// anything that dereferences the pointers stored in the returned [`coap_dtls_key_t`] (which is
    /// itself only possible in `unsafe` code) after `self` has been dropped will cause Undefined
    /// Behavior.
    fn as_raw_dtls_key(&self) -> coap_dtls_key_t;
}

/// Trait for types that can be converted to components of an asymmetric DTLS key.
pub(super) trait AsRawKeyComponent: Sized + Debug {
    /// Returns a raw [`coap_const_char_ptr_t`] pointing to this key component and a `usize`
    /// indicating the length of this key component (or `0` if this key type is supposed to be a
    /// null-terminated string).
    ///
    /// **Important:** The returned raw definition refers to memory owned by `self`.
    /// While this function alone can not cause undefined behavior (and is therefore not `unsafe`),
    /// anything that dereferences the returned [`coap_const_char_ptr_t`] (which is itself only
    /// possible in `unsafe` code) after `self` has been dropped will cause Undefined Behavior.
    fn as_raw_key_component(&self) -> (coap_const_char_ptr_t, usize);
}

/// Sealed trait for components of an asymmetric DTLS key of the given [`KeyType`] `KTY`.
pub(super) trait KeyComponentSealed<KTY: KeyType>: AsRawKeyComponent {
    /// The raw [`coap_pki_define_t`] indicating the type of this key component that should be used
    /// when using it in a key definition of type `KTY`.
    const DEFINE_TYPE: coap_pki_define_t;
}

/// Trait indicating that a type can be used as a DTLS key component of the given [`KeyType`] `KTY`.
#[allow(private_bounds)]
pub trait KeyComponent<KTY: KeyType>: KeyComponentSealed<KTY> {}

impl<KTY: KeyType, T: KeyComponentSealed<KTY>> KeyComponent<KTY> for T {}

/// Key component that is stored in a PEM-encoded file with the given path.
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

/// Key component that is stored in memory as a PEM-encoded sequence of bytes.
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

/// Key component that is stored in a DER-encoded file with the given path.
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

/// Key component that is stored in memory as a DER-encoded sequence of bytes.
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

/// Key component that is stored as a PKCS11 URI.
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

impl<T: Into<CString>> From<T> for Pkcs11KeyComponent {
    fn from(value: T) -> Self {
        Pkcs11KeyComponent(value.into())
    }
}

/// Key component that is passed to the TLS library verbatim (only supported by OpenSSL).
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

impl<T: Into<CString>> From<T> for EngineKeyComponent {
    fn from(value: T) -> Self {
        EngineKeyComponent(value.into())
    }
}

/// Private key type for DER/ASN.1 encoded keys.
#[repr(C)]
#[derive(Copy, Clone, FromPrimitive, Debug, PartialEq, Eq, Hash, Default)]
pub enum Asn1PrivateKeyType {
    #[default]
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

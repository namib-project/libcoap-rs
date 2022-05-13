// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto.rs - CoAP cryptography provider interfaces and types.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::{
    ffi::{c_void, CStr},
    fmt::Debug,
    os::raw::c_char,
};

use libcoap_sys::{coap_bin_const_t, coap_dtls_cpsk_info_t, coap_dtls_spsk_info_t, coap_session_t, coap_str_const_t};

use crate::{context::CoapContext, session::CoapClientSession};

/// Representation of cryptographic information used by a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapCryptoPskInfo {
    /// The identity hint to return to the client.
    pub identity: Box<CoapCryptoPskIdentity>,
    /// The pre-shared-key that belongs to this identity hint.
    pub key: Box<CoapCryptoPskData>,
}

impl CoapCryptoPskInfo {
    /// Apply this key information to a coap_dtls_cpsk_info_t struct for use in libcoap.
    pub fn apply_to_cpsk_info(&self, info: &mut coap_dtls_cpsk_info_t) {
        info.identity.s = self.identity.as_ptr();
        info.identity.length = self.identity.len();
        info.key.s = self.key.as_ptr();
        info.key.length = self.key.len();
    }

    /// Apply this key information to a coap_dtls_spsk_info_t struct for use in libcoap.
    pub fn apply_to_spsk_info(&self, info: &mut coap_dtls_spsk_info_t) {
        info.hint.s = self.identity.as_ptr();
        info.hint.length = self.identity.len();
        info.key.s = self.key.as_ptr();
        info.key.length = self.key.len();
    }
}

pub type CoapCryptoPskIdentity = [u8];
pub type CoapCryptoPskData = [u8];

/// Type representing a possible return value of a cryptographic credential provider.
///
/// Most functions implemented in CoapCryptoProvider can return one of three possible responses,
/// which are represented by this enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoapCryptoProviderResponse<T: Debug> {
    /// The current key (as indicated by a previous callback such as [provide_default_info()]) is
    /// sufficient and should be used for this session.
    UseCurrent,
    /// A new set of cryptographic credentials should be used for this session.
    UseNew(T),
    /// According to the provided information, the cryptographic material of the peer is
    /// unacceptable (=> (D-)TLS Handshake Failure).
    Unacceptable,
}

/// Trait implemented by types that can provide cryptographic information to CoapContexts and
/// associated sessions when needed.
pub trait CoapClientCryptoProvider: Debug {
    /// Provide the appropriate cryptographic information for the given hint supplied by the server.
    ///
    /// Return a CoapCryptoProviderResponse corresponding to the cryptographic information that
    /// should be used.
    fn provide_key_for_hint(
        &mut self,
        hint: &CoapCryptoPskIdentity,
    ) -> CoapCryptoProviderResponse<Box<CoapCryptoPskData>>;

    /// Provide the initial cryptographic information for client-side sessions associated with this
    /// provider.
    fn provide_default_info(&mut self) -> CoapCryptoPskInfo;
}

pub trait CoapServerCryptoProvider: Debug {
    /// Provide the appropiate cryptographic information for the given key identity supplied by the
    /// client.
    ///
    /// Return a CoapCryptoProviderResponse corresponding to the cryptographic information that
    /// should be used.
    #[allow(unused_variables)]
    fn provide_key_for_identity(
        &mut self,
        identity: &CoapCryptoPskIdentity,
    ) -> CoapCryptoProviderResponse<Box<CoapCryptoPskData>> {
        CoapCryptoProviderResponse::UseCurrent
    }

    /// Provide the appropriate key hint and data for the given SNI provided by the client.
    ///
    /// This function will only be called once per SNI hint, libcoap will remember the returned
    /// hint.
    ///
    /// Return None if the provided SNI is unacceptable, i.e. you have no key for this server name.
    #[allow(unused_variables)]
    fn provide_hint_for_sni(&mut self, sni: &str) -> CoapCryptoProviderResponse<CoapCryptoPskInfo> {
        CoapCryptoProviderResponse::UseCurrent
    }

    /// Provide the default PSK identity hint and key data that should be used for new server-side
    /// sessions.
    ///
    /// Return a CoapCryptoProviderResponse corresponding to the cryptographic information that
    /// should be used.
    fn provide_default_info(&mut self) -> CoapCryptoPskInfo;
}

// TODO DTLS PKI/RPK

pub(crate) unsafe extern "C" fn dtls_ih_callback(
    hint: *mut coap_str_const_t,
    session: *mut coap_session_t,
    _userdata: *mut c_void,
) -> *const coap_dtls_cpsk_info_t {
    let mut session = CoapClientSession::from_raw(session);
    let provided_identity = std::slice::from_raw_parts((*hint).s, (*hint).length);
    session
        .provide_raw_key_for_hint(provided_identity)
        .map(|v| v as *const coap_dtls_cpsk_info_t)
        .unwrap_or(std::ptr::null())
}

pub(crate) unsafe extern "C" fn dtls_server_id_callback(
    identity: *mut coap_bin_const_t,
    _session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_bin_const_t {
    let context = (userdata as *mut CoapContext).as_mut().unwrap();
    let provided_identity = std::slice::from_raw_parts((*identity).s, (*identity).length);
    context
        .provide_raw_key_for_identity(provided_identity)
        .map(|v| (v as *const coap_bin_const_t))
        .unwrap_or(std::ptr::null())
}

pub(crate) unsafe extern "C" fn dtls_server_sni_callback(
    sni: *const c_char,
    _session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_dtls_spsk_info_t {
    let context = (userdata as *mut CoapContext).as_mut().unwrap();
    let sni_value = CStr::from_ptr(sni).to_str();
    if let Ok(sni_value) = sni_value {
        context
            .provide_raw_hint_for_sni(sni_value)
            .map(|v| (v as *const coap_dtls_spsk_info_t))
            .unwrap_or(std::ptr::null())
    } else {
        std::ptr::null()
    }
}

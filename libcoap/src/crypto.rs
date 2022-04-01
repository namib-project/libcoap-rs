// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto.rs - CoAP cryptography provider interfaces and types.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::any::Any;
use std::{
    ffi::{c_void, CStr},
    fmt::Debug,
    os::raw::c_char,
};

use libcoap_sys::{
    coap_bin_const_t, coap_dtls_cpsk_info_t, coap_dtls_spsk_info_t, coap_new_bin_const, coap_session_t,
    coap_str_const_t,
};

use crate::{
    context::CoapContext,
    session::{CoapClientSession, CoapServerSession},
};

/// Representation of cryptographic information used by a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapCryptoPskInfo {
    /// The identity hint to return to the client.
    pub identity: Box<CoapCryptoPskIdentity>,
    /// The pre-shared-key that belongs to this identity hint.
    pub key: Box<CoapCryptoPskData>,
}

impl CoapCryptoPskInfo {
    pub fn apply_to_cpsk_info(&self, info: &mut coap_dtls_cpsk_info_t) {
        info.identity.s = self.identity.as_ptr();
        info.identity.length = self.identity.len();
        info.key.s = self.key.as_ptr();
        info.key.length = self.key.len();
    }

    pub fn apply_to_spsk_info(&self, info: &mut coap_dtls_spsk_info_t) {
        info.hint.s = self.identity.as_ptr();
        info.hint.length = self.identity.len();
        info.key.s = self.key.as_ptr();
        info.key.length = self.key.len();
    }
}

pub type CoapCryptoPskIdentity = [u8];
pub type CoapCryptoPskData = [u8];

pub enum CoapCryptoProviderResponse<T> {
    UseCurrent,
    UseNew(T),
    Unacceptable,
}

/// Trait implemented by types that can provide cryptographic information to CoapContexts and
/// associated sessions when needed.
pub trait CoapClientCryptoProvider: Debug {
    /// Provide the appropriate cryptographic information for the given hint supplied by the server.
    ///
    /// The hint can be none either if the server does not provide a hint or if the client has not
    /// started connecting yet and requests the standard key information to use.
    ///
    /// Return None if the provided hint is unacceptable, i.e. you have no key that matches this
    /// hint.
    fn provide_key_for_hint(
        &mut self,
        hint: &CoapCryptoPskIdentity,
    ) -> CoapCryptoProviderResponse<Box<CoapCryptoPskData>>;

    fn provide_default_info(&mut self) -> CoapCryptoPskInfo;
}

pub trait CoapServerCryptoProvider: Debug {
    /// Provide the appropiate cryptographic information for the given key identity supplied by the
    /// client.
    ///
    /// Return None if the provided hint is unacceptable, i.e. you have no key that matches this
    /// identity.
    fn provide_key_for_identity(
        &mut self,
        identity: &CoapCryptoPskIdentity,
    ) -> CoapCryptoProviderResponse<Box<CoapCryptoPskData>> {
        CoapCryptoProviderResponse::UseCurrent
    }

    /// Provide the appropriate key hint for the given SNI provided by the client
    ///
    /// Return None if the provided SNI is unacceptable, i.e. you have no key for this server name.
    fn provide_hint_for_sni(&mut self, sni: &str) -> CoapCryptoProviderResponse<CoapCryptoPskInfo> {
        CoapCryptoProviderResponse::UseCurrent
    }

    fn provide_default_info(&mut self) -> CoapCryptoPskInfo;
}

// TODO DTLS PKI/RPK

pub(crate) unsafe extern "C" fn dtls_ih_callback(
    hint: *mut coap_str_const_t,
    session: *mut coap_session_t,
    _userdata: *mut c_void,
) -> *const coap_dtls_cpsk_info_t {
    let mut session = CoapClientSession::restore_from_raw(session);
    let mut client = session.borrow_mut();
    let provided_identity = std::slice::from_raw_parts((*hint).s, (*hint).length);
    client
        .provide_raw_key_for_hint(provided_identity)
        .map(|v| (v as *const coap_dtls_cpsk_info_t))
        .unwrap_or(std::ptr::null())
}

pub(crate) unsafe extern "C" fn dtls_server_id_callback(
    identity: *mut coap_bin_const_t,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_bin_const_t {
    let mut session = CoapServerSession::restore_from_raw(session);
    let mut server = session.borrow_mut();
    let context = (userdata as *mut CoapContext).as_mut().unwrap();
    let provided_identity = std::slice::from_raw_parts((*identity).s, (*identity).length);
    context
        .provide_raw_key_for_identity(provided_identity)
        .map(|v| (v as *const coap_bin_const_t))
        .unwrap_or(std::ptr::null())
}

pub(crate) unsafe extern "C" fn dtls_server_sni_callback(
    sni: *const c_char,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_dtls_spsk_info_t {
    let mut session = CoapServerSession::restore_from_raw(session);
    let mut server = session.borrow_mut();
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

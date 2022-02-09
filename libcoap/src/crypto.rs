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

use libcoap_sys::{
    coap_bin_const_t, coap_dtls_cpsk_info_t, coap_dtls_spsk_info_t, coap_new_bin_const, coap_session_t,
    coap_str_const_t,
};

use crate::{
    context::CoapContext,
    session::{CoapClientSession, CoapServerSession},
};

/// Representation of cryptographic information used by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapClientCryptoIdentity {
    /// The key identity of the PSK to use.
    pub identity: Box<CoapCryptoPskIdentity>,
    /// The PSK that should be used and has the given identity.
    pub key: Box<CoapCryptoPsk>,
}

/// Representation of cryptographic information used by a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapServerCryptoHint {
    /// The identity hint to return to the client.
    pub hint: Box<CoapCryptoPskIdentity>,
    /// The pre-shared-key that belongs to this identity hint.
    pub key: Box<CoapCryptoPsk>,
}

pub type CoapCryptoPskIdentity = [u8];
pub type CoapCryptoPsk = [u8];

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
    fn provide_info_for_hint(&mut self, hint: Option<&CoapCryptoPskIdentity>) -> Option<CoapClientCryptoIdentity>;
}

pub trait CoapServerCryptoProvider: Debug {
    /// Provide the appropiate cryptographic information for the given key identity supplied by the
    /// client.
    ///
    /// Return None if the provided hint is unacceptable, i.e. you have no key that matches this
    /// identity.
    fn provide_key_for_identity(&mut self, identity: &CoapCryptoPskIdentity) -> Option<Box<CoapCryptoPsk>>;

    /// Provide the appropriate key hint for the given SNI provided by the client
    ///
    /// Return None if the provided SNI is unacceptable, i.e. you have no key for this server name.
    fn provide_hint_for_sni(&mut self, sni: Option<&str>) -> Option<CoapServerCryptoHint>;
}

// TODO DTLS PKI/RPK

pub(crate) unsafe extern "C" fn dtls_ih_callback(
    hint: *mut coap_str_const_t,
    session: *mut coap_session_t,
    _userdata: *mut c_void,
) -> *const coap_dtls_cpsk_info_t {
    let mut session = CoapClientSession::restore_from_raw(session);
    let mut client = session.borrow_mut();
    if let Some(client_crypto) = &mut client.crypto_provider {
        client.crypto_current_data =
            client_crypto.provide_info_for_hint(Some(std::slice::from_raw_parts((*hint).s, (*hint).length)));
        client
            .crypto_current_data
            .as_ref()
            .map(|crypto_data| {
                Box::leak(Box::new(coap_dtls_cpsk_info_t {
                    identity: coap_bin_const_t {
                        s: crypto_data.identity.as_ptr(),
                        length: crypto_data.identity.len(),
                    },
                    key: coap_bin_const_t {
                        s: crypto_data.key.as_ptr(),
                        length: crypto_data.key.len(),
                    },
                })) as *const coap_dtls_cpsk_info_t
            })
            .unwrap_or(std::ptr::null())
    } else {
        std::ptr::null()
    }
}

pub(crate) unsafe extern "C" fn dtls_server_id_callback(
    identity: *mut coap_bin_const_t,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_bin_const_t {
    let mut session = CoapServerSession::restore_from_raw(session);
    let mut server = session.borrow_mut();
    let context = (userdata as *mut CoapContext).as_mut().unwrap();
    if let Some(server_crypto) = context.server_crypto_provider() {
        server.crypto_current_data =
            server_crypto.provide_key_for_identity(std::slice::from_raw_parts((*identity).s, (*identity).length));
        server
            .crypto_current_data
            .as_ref()
            .map(|crypto_data| coap_new_bin_const(crypto_data.as_ptr(), crypto_data.len()))
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

pub(crate) unsafe extern "C" fn dtls_server_sni_callback(
    sni: *const c_char,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_dtls_spsk_info_t {
    let mut session = CoapServerSession::restore_from_raw(session);
    let mut server = session.borrow_mut();
    let context = (userdata as *mut CoapContext).as_mut().unwrap();
    if let Some(server_crypto) = context.server_crypto_provider() {
        let sni_value = CStr::from_ptr(sni).to_str();
        if let Ok(sni_value) = sni_value {
            let new_hint = server_crypto.provide_hint_for_sni(Some(sni_value));

            if let Some(hint) = &new_hint {
                server.crypto_current_data = Some(hint.key.clone());
            }

            new_hint
                .map(|v| {
                    Box::into_raw(Box::new(coap_dtls_spsk_info_t {
                        hint: coap_bin_const_t {
                            length: v.hint.len(),
                            s: v.hint.as_ptr(),
                        },
                        key: coap_bin_const_t {
                            length: v.key.len(),
                            s: v.key.as_ptr(),
                        },
                    }))
                })
                .unwrap_or(std::ptr::null_mut())
        } else {
            std::ptr::null_mut()
        }
    } else {
        std::ptr::null_mut()
    }
}

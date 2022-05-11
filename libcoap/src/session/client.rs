// SPDX-License-Identifier: BSD-2-Clause
/*
 * session/client.rs - Types relating to client-side CoAP sessions.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::borrow::{Borrow, BorrowMut};
use std::cell::{Ref, RefMut};
use std::{
    any::Any,
    collections::{vec_deque::Drain, HashMap, VecDeque},
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    rc::Rc,
};

use rand::Rng;

use libcoap_sys::{
    coap_bin_const_t, coap_context_t, coap_dtls_cpsk_info_t, coap_dtls_cpsk_t, coap_fixed_point_t, coap_mid_t,
    coap_new_client_session, coap_new_client_session_psk2, coap_new_message_id, coap_pdu_get_token, coap_pdu_t,
    coap_proto_t, coap_response_t, coap_send, coap_session_get_ack_random_factor, coap_session_get_ack_timeout,
    coap_session_get_addr_local, coap_session_get_addr_remote, coap_session_get_app_data, coap_session_get_ifindex,
    coap_session_get_max_retransmit, coap_session_get_proto, coap_session_get_psk_hint, coap_session_get_psk_identity,
    coap_session_get_psk_key, coap_session_get_state, coap_session_get_type, coap_session_init_token,
    coap_session_max_pdu_size, coap_session_new_token, coap_session_reference, coap_session_release,
    coap_session_send_ping, coap_session_set_ack_random_factor, coap_session_set_ack_timeout,
    coap_session_set_app_data, coap_session_set_max_retransmit, coap_session_set_mtu, coap_session_set_type_client,
    coap_session_state_t, coap_session_t, coap_session_type_t, COAP_DTLS_SPSK_SETUP_VERSION,
};

use super::{CoapRequestHandle, CoapSessionCommon, CoapSessionInner, CoapSessionInnerProvider};
use crate::context::CoapContextInner;
use crate::crypto::{CoapCryptoProviderResponse, CoapCryptoPskData};
use crate::types::DropInnerExclusively;
use crate::{
    context::CoapContext,
    crypto::{dtls_ih_callback, CoapClientCryptoProvider, CoapCryptoPskIdentity, CoapCryptoPskInfo},
    error::{MessageConversionError, SessionCreationError, SessionGetAppDataError},
    message::{CoapMessage, CoapMessageCommon},
    protocol::CoapToken,
    request::{CoapRequest, CoapResponse},
    types::{CoapAddress, CoapAppDataRef, CoapMessageId, CoapProtocol, IfIndex, MaxRetransmit},
};

/// Representation of a client-side CoAP session.
#[derive(Debug)]
pub struct CoapClientSessionInner<'a> {
    inner: CoapSessionInner<'a>,
    crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>,
    crypto_current_data: Option<CoapCryptoPskInfo>,
    // coap_dtls_cpsk_info_t created upon calling dtls_client_ih_callback().
    // The caller of the callback will make a defensive copy, so this one only has
    // to be valid for a very short time and can always be overridden.
    crypto_last_info_ref: coap_dtls_cpsk_info_t,
}

#[derive(Debug, Clone)]
pub struct CoapClientSession<'a> {
    pub(super) inner: CoapAppDataRef<CoapClientSessionInner<'a>>,
}

impl CoapClientSession<'_> {
    /// Create a new DTLS encrypted session with the given peer.
    ///
    /// To supply cryptographic information (like PSK hints or key data), you have to provide a
    /// struct implementing [CoapClientCryptoProvider].
    pub fn connect_dtls<'a, 'b, P: 'static + CoapClientCryptoProvider>(
        ctx: &'b mut CoapContext<'a>,
        addr: SocketAddr,
        mut crypto_provider: P,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        // Get default identity.
        let id = crypto_provider.provide_default_info();
        let client_setup_data = Box::into_raw(Box::new(coap_dtls_cpsk_t {
            version: COAP_DTLS_SPSK_SETUP_VERSION as u8,
            reserved: [0; 7],
            validate_ih_call_back: Some(dtls_ih_callback),
            ih_call_back_arg: std::ptr::null_mut(),
            client_sni: std::ptr::null_mut(),
            psk_info: coap_dtls_cpsk_info_t {
                identity: coap_bin_const_t {
                    length: id.identity.len(),
                    s: id.identity.as_ptr(),
                },
                key: coap_bin_const_t {
                    length: id.key.len(),
                    s: id.key.as_ptr(),
                },
            },
        }));
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null, constructed
        // coap_dtls_cpsk_t is of valid format and has no out-of-bounds issues.
        let raw_session = unsafe {
            coap_new_client_session_psk2(
                ctx.as_mut_raw_context(),
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                coap_proto_t::COAP_PROTO_DTLS,
                client_setup_data,
            )
        };

        if raw_session.is_null() {
            return Err(SessionCreationError::Unknown);
        }

        Ok(CoapClientSession::new(
            ctx,
            raw_session,
            Some(id),
            Some(Box::new(crypto_provider)),
        ))
    }

    /// Create a new unencrypted session with the given peer over UDP.
    pub fn connect_udp<'a>(
        ctx: &mut CoapContext<'a>,
        addr: SocketAddr,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null.
        let session = unsafe {
            coap_new_client_session(
                ctx.as_mut_raw_context(),
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                coap_proto_t::COAP_PROTO_UDP,
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        Ok(CoapClientSession::new(ctx, session as *mut coap_session_t, None, None))
    }

    fn new<'a>(
        ctx: &mut CoapContext<'a>,
        raw_session: *mut coap_session_t,
        crypto_current_data: Option<CoapCryptoPskInfo>,
        crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>,
    ) -> CoapClientSession<'a> {
        let inner_session = CoapAppDataRef::new(CoapClientSessionInner {
            inner: CoapSessionInner {
                raw_session,
                app_data: None,
                received_responses: Default::default(),
                _context_lifetime_marker: Default::default(),
            },
            crypto_provider,
            crypto_current_data,
            crypto_last_info_ref: coap_dtls_cpsk_info_t {
                identity: coap_bin_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
                key: coap_bin_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
            },
        });

        let client_session = CoapClientSession {
            inner: inner_session.clone(),
        };
        // TODO Safety
        unsafe {
            coap_session_set_app_data(raw_session, inner_session.create_raw_weak());
            // TODO the client sessions are now only deleted if the context goes out of scope, i guess we need to work with weak references or pointers to the raw client sessions here.
            ctx.attach_client_session(client_session.clone());
        }

        client_session
    }

    /// Restores a CoapClientSession from its raw counterpart.
    ///
    /// Note that it is not possible to statically infer the lifetime of the created session from
    /// the raw pointer, i.e., the session will be created with an arbitrary lifetime.
    /// Therefore, callers of this function should ensure that the created session instance does not
    /// outlive the context it is bound to.
    /// Failing to do so will result in a panic/abort in the context destructor as it is unable to
    /// claim exclusive ownership of the client session.
    ///
    /// # Panics
    /// Panics if the given pointer is a null pointer or the raw session is not a client-side
    /// session.
    ///
    /// # Safety
    /// The provided pointer must be valid.
    pub(crate) unsafe fn from_raw<'a>(raw_session: *mut coap_session_t) -> CoapClientSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => {
                let raw_app_data_ptr = coap_session_get_app_data(raw_session);
                assert!(!raw_app_data_ptr.is_null(), "provided raw session has no app data");
                let inner = CoapAppDataRef::clone_raw_rc(raw_app_data_ptr);
                CoapClientSession { inner }
            },
            coap_session_type_t::COAP_SESSION_TYPE_SERVER | coap_session_type_t::COAP_SESSION_TYPE_HELLO => {
                panic!("attempted to create CoapClientSession from raw server session")
            },
            _ => unreachable!("unknown session type"),
        }
    }

    /// Sets the provider for cryptographic information for this session.
    pub fn set_crypto_provider(&mut self, crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>) {
        self.inner.borrow_mut().crypto_provider = crypto_provider;
    }

    pub(crate) fn provide_raw_key_for_hint(
        &mut self,
        hint: &CoapCryptoPskIdentity,
    ) -> Option<*const coap_dtls_cpsk_info_t> {
        let inner_ref = &mut *self.inner.borrow_mut();

        match inner_ref.crypto_provider.as_mut().map(|v| v.provide_key_for_hint(hint)) {
            Some(CoapCryptoProviderResponse::UseNew(new_data)) => {
                inner_ref.crypto_current_data = Some(CoapCryptoPskInfo {
                    identity: Box::from(hint),
                    key: new_data,
                });
                inner_ref
                    .crypto_current_data
                    .as_ref()
                    .unwrap()
                    .apply_to_cpsk_info(&mut inner_ref.crypto_last_info_ref);
                Some(&inner_ref.crypto_last_info_ref as *const coap_dtls_cpsk_info_t)
            },
            Some(CoapCryptoProviderResponse::UseCurrent) => {
                if inner_ref.crypto_current_data.is_some() {
                    inner_ref
                        .crypto_current_data
                        .as_ref()
                        .unwrap()
                        .apply_to_cpsk_info(&mut inner_ref.crypto_last_info_ref);
                    Some(&inner_ref.crypto_last_info_ref as *const coap_dtls_cpsk_info_t)
                } else {
                    None
                }
            },
            None | Some(CoapCryptoProviderResponse::Unacceptable) => None,
        }
    }

    pub(crate) fn provide_default_info(&mut self) -> Option<CoapCryptoPskInfo> {
        self.inner
            .borrow_mut()
            .crypto_provider
            .as_mut()
            .map(|provider| provider.provide_default_info())
    }
}

impl DropInnerExclusively for CoapClientSession<'_> {
    fn drop_exclusively(mut self) {
        self.inner.drop_exclusively();
    }
}

impl Drop for CoapClientSessionInner<'_> {
    fn drop(&mut self) {
        unsafe {
            let app_data = coap_session_get_app_data(self.inner.raw_session);
            assert!(!app_data.is_null());
            CoapAppDataRef::<CoapClientSessionInner>::raw_ptr_to_weak(app_data);
            coap_session_release(self.inner.raw_session);
        }
    }
}

impl<'a> CoapSessionInnerProvider<'a> for CoapClientSession<'a> {
    fn inner_ref<'b>(&'b self) -> Ref<'b, CoapSessionInner<'a>> {
        Ref::map(self.inner.borrow(), |v| &v.inner)
    }
    fn inner_mut<'b>(&'b mut self) -> RefMut<'b, CoapSessionInner<'a>> {
        RefMut::map(self.inner.borrow_mut(), |v| &mut v.inner)
    }
}

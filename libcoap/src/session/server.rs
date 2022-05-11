// SPDX-License-Identifier: BSD-2-Clause
/*
 * session/server.rs - Types relating to client-side CoAP sessions.
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

impl DropInnerExclusively for CoapServerSession<'_> {
    fn drop_exclusively(mut self) {
        self.inner.drop_exclusively();
    }
}

impl Drop for CoapServerSessionInner<'_> {
    fn drop(&mut self) {
        unsafe {
            let app_data = coap_session_get_app_data(self.inner.raw_session);
            assert!(!app_data.is_null());
            CoapAppDataRef::<CoapServerSessionInner>::raw_ptr_to_weak(app_data);
        }
    }
}

/// Representation of a server-side CoAP session.
#[derive(Debug, Clone)]
pub struct CoapServerSession<'a> {
    pub(super) inner: CoapAppDataRef<CoapServerSessionInner<'a>>,
}

#[derive(Debug)]
pub struct CoapServerSessionInner<'a> {
    inner: CoapSessionInner<'a>,
    crypto_current_data: Option<CoapCryptoPskInfo>,
}

impl CoapServerSession<'_> {
    /// Creates a CoapServerSession from a raw session
    ///
    /// # Panics
    /// Panics if the given pointer is a null pointer or the raw session is not a server-side
    /// session.
    ///
    /// # Safety
    /// The provided pointer must be valid.
    /// The existing value in the `app_data` field of the raw session will be overridden.
    /// Make sure that this is actually okay to do so — most importantly, no other [CoapSession] may
    /// already be stored there.
    ///
    /// If you wish to restore an existing [CoapSession] from its raw counterpart, use
    /// [from_raw()](CoapServerSession::from_raw) instead.
    pub(crate) unsafe fn initialize_raw<'a>(raw_session: *mut coap_session_t) -> CoapServerSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        let inner = CoapSessionInner {
            raw_session,
            app_data: None,
            received_responses: Default::default(),
            _context_lifetime_marker: Default::default(),
        };
        let session_inner = match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => {
                panic!("attempted to create server session from raw client session")
            },
            coap_session_type_t::COAP_SESSION_TYPE_SERVER => {
                let psk_identity = coap_session_get_psk_identity(raw_session).as_ref();
                let psk_key = coap_session_get_psk_key(raw_session).as_ref();
                let crypto_info = psk_identity.zip(psk_key).map(|(identity, key)| CoapCryptoPskInfo {
                    identity: Box::from(std::slice::from_raw_parts(identity.s, identity.length)),
                    key: Box::from(std::slice::from_raw_parts(key.s, key.length)),
                });
                CoapServerSessionInner {
                    inner,
                    crypto_current_data: crypto_info,
                }
            },
            coap_session_type_t::COAP_SESSION_TYPE_HELLO => CoapServerSessionInner {
                inner,
                crypto_current_data: None,
            },
            _ => unreachable!("unknown session type"),
        };
        let session_ref = CoapAppDataRef::new(session_inner);
        coap_session_set_app_data(raw_session, session_ref.create_raw_weak());
        CoapServerSession { inner: session_ref }
    }

    /// Restores a CoapServerSession from its raw counterpart.
    ///
    /// # Panics
    /// Panics if the provided raw session pointer or its app_data field is null or the raw session
    /// is not a server-side session.
    ///
    /// # Safety
    /// The provided pointer must be valid.
    pub(crate) unsafe fn from_raw<'a>(raw_session: *mut coap_session_t) -> CoapServerSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_SERVER | coap_session_type_t::COAP_SESSION_TYPE_HELLO => {
                let raw_app_data_ptr = coap_session_get_app_data(raw_session);
                assert!(!raw_app_data_ptr.is_null(), "provided raw session has no app data");
                CoapServerSession {
                    inner: CoapAppDataRef::clone_raw_rc(raw_app_data_ptr),
                }
            },
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => {
                panic!("attempted to create CoapServerSession from raw client session")
            },
            _ => unreachable!("unknown session type"),
        }
    }
}

impl<'a> CoapSessionInnerProvider<'a> for CoapServerSession<'a> {
    fn inner_ref<'b>(&'b self) -> Ref<'b, CoapSessionInner<'a>> {
        Ref::map(self.inner.borrow(), |v| &v.inner)
    }
    fn inner_mut<'b>(&'b mut self) -> RefMut<'b, CoapSessionInner<'a>> {
        RefMut::map(self.inner.borrow_mut(), |v| &mut v.inner)
    }
}

impl<'a, T: CoapSessionCommon<'a>> PartialEq<T> for CoapServerSession<'_> {
    fn eq(&self, other: &T) -> bool {
        // SAFETY: Pointers are only compared, never accessed.
        self.if_index() == other.if_index()
            && unsafe { self.raw_session() == other.raw_session() }
            && self.addr_local() == other.addr_local()
            && self.addr_remote() == other.addr_remote()
    }
}

impl Eq for CoapServerSession<'_> {}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * session/mod.rs - Types relating to generic CoAP sessions.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::borrow::{BorrowMut};
use std::cell::{Ref, RefMut};
use std::{
    any::Any,
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    rc::Rc,
};

use rand::Rng;

use libcoap_sys::{
    coap_context_t, coap_fixed_point_t, coap_mid_t, coap_new_message_id, coap_pdu_get_token, coap_pdu_t, coap_response_t, coap_send, coap_session_get_ack_random_factor, coap_session_get_ack_timeout,
    coap_session_get_addr_local, coap_session_get_addr_remote, coap_session_get_app_data, coap_session_get_ifindex,
    coap_session_get_max_retransmit, coap_session_get_proto, coap_session_get_psk_hint, coap_session_get_psk_identity,
    coap_session_get_psk_key, coap_session_get_state, coap_session_get_type, coap_session_init_token,
    coap_session_max_pdu_size, coap_session_new_token,
    coap_session_send_ping, coap_session_set_ack_random_factor, coap_session_set_ack_timeout, coap_session_set_max_retransmit, coap_session_set_mtu,
    coap_session_state_t, coap_session_t, coap_session_type_t,
};


use crate::crypto::{CoapCryptoPskData};

use crate::{
    crypto::{CoapCryptoPskIdentity},
    error::{MessageConversionError, SessionGetAppDataError},
    message::{CoapMessage, CoapMessageCommon},
    protocol::CoapToken,
    request::{CoapRequest, CoapResponse},
    types::{CoapAddress, CoapMessageId, CoapProtocol, IfIndex, MaxRetransmit},
};

pub use self::client::CoapClientSession;

pub(self) use self::sealed::{CoapSessionCommonInternal, CoapSessionInnerProvider};
pub use self::server::CoapServerSession;


mod client;
mod server;

/// Representation of the states that a session can be in.
#[repr(u32)]
pub enum CoapSessionState {
    None = coap_session_state_t::COAP_SESSION_STATE_NONE as u32,
    Connecting = coap_session_state_t::COAP_SESSION_STATE_CONNECTING as u32,
    Handshake = coap_session_state_t::COAP_SESSION_STATE_HANDSHAKE as u32,
    Csm = coap_session_state_t::COAP_SESSION_STATE_CSM as u32,
    Established = coap_session_state_t::COAP_SESSION_STATE_ESTABLISHED as u32,
}

impl From<coap_session_state_t> for CoapSessionState {
    fn from(raw_state: coap_session_state_t) -> Self {
        match raw_state {
            coap_session_state_t::COAP_SESSION_STATE_NONE => CoapSessionState::None,
            coap_session_state_t::COAP_SESSION_STATE_CONNECTING => CoapSessionState::Connecting,
            coap_session_state_t::COAP_SESSION_STATE_HANDSHAKE => CoapSessionState::Handshake,
            coap_session_state_t::COAP_SESSION_STATE_CSM => CoapSessionState::Csm,
            coap_session_state_t::COAP_SESSION_STATE_ESTABLISHED => CoapSessionState::Established,
            _ => unreachable!("unknown session state added"),
        }
    }
}

mod sealed {
    use super::*;

    pub trait CoapSessionInnerProvider<'a> {
        fn inner_ref<'b>(&'b self) -> Ref<'b, CoapSessionInner<'a>>;

        fn inner_mut<'b>(&'b mut self) -> RefMut<'b, CoapSessionInner<'a>>;
    }

    pub trait CoapSessionCommonInternal<'a>: CoapSessionInnerProvider<'a> {
        fn add_response(&mut self, pdu: CoapResponse) {
            let token = pdu.token();
            if let Some(token) = token {
                if self.inner_ref().received_responses.contains_key(token) {
                    self.inner_mut()
                        .received_responses
                        .get_mut(token)
                        .unwrap()
                        .push_back(pdu);
                }
            }
        }
    }

    impl<'a, T: CoapSessionInnerProvider<'a>> CoapSessionCommonInternal<'a> for T {}
}

impl<'a, T: CoapSessionCommonInternal<'a>> CoapSessionCommon<'a> for T {}

/// Trait for functions that are common between client and server sessions.
pub trait CoapSessionCommon<'a>: CoapSessionCommonInternal<'a> {
    /// Returns the application specific data stored alongside this session.
    fn app_data<T: Any>(&self) -> Result<Option<Rc<T>>, SessionGetAppDataError> {
        self.inner_ref()
            .app_data
            .as_ref()
            .map(|v| v.clone().downcast().map_err(|_v| SessionGetAppDataError::WrongType))
            .transpose()
    }

    /// Sets the application-specific data stored alongside this session.
    fn set_app_data<T: 'static + Any>(&mut self, value: Option<T>) {
        let mut inner = self.inner_mut();
        let new_box: Option<Rc<dyn Any>> = value.map(|v| Rc::new(v) as Rc<dyn Any>);
        inner.app_data = new_box;
    }

    /// Clears the application-specific data stored alongside this session.
    fn clear_app_data(&mut self) {
        let mut inner = self.inner_mut();
        inner.app_data = None;
        let raw_inner_ptr = unsafe { coap_session_get_app_data(inner.raw_session) };
        if !raw_inner_ptr.is_null() {
            std::mem::drop(unsafe { Rc::from_raw(raw_inner_ptr) });
        }
    }

    /// Returns the Ack-Random-Factor used by libcoap.
    ///
    /// The returned value is a tuple consisting of an integer and a fractional part, where the
    /// fractional part is a value from 0-999 and represents the first three digits after the comma.
    fn ack_random_factor(&self) -> (u16, u16) {
        let random_factor = unsafe { coap_session_get_ack_random_factor(self.inner_ref().raw_session) };
        (random_factor.integer_part, random_factor.fractional_part)
    }

    /// Sets the Ack-Random-Factor used by libcoap.
    fn set_ack_random_factor(&mut self, integer_part: u16, fractional_part: u16) {
        unsafe {
            coap_session_set_ack_random_factor(
                self.inner_mut().raw_session,
                coap_fixed_point_t {
                    integer_part,
                    fractional_part,
                },
            )
        };
    }

    /// Returns the current value of the Acknowledgement Timeout for this session (in seconds).
    ///
    /// The returned value is a tuple consisting of an integer and a fractional part, where the
    /// fractional part is a value from 0-999 and represents the first three digits after the comma.
    fn ack_timeout(&self) -> (u16, u16) {
        let random_factor = unsafe { coap_session_get_ack_timeout(self.inner_ref().raw_session) };
        (random_factor.integer_part, random_factor.fractional_part)
    }

    /// Sets the value of the Acknowledgement Timeout for this session.
    fn set_ack_timeout(&mut self, integer_part: u16, fractional_part: u16) {
        unsafe {
            coap_session_set_ack_timeout(
                self.inner_ref().raw_session,
                coap_fixed_point_t {
                    integer_part,
                    fractional_part,
                },
            )
        };
    }

    /// Returns the local address for this session.
    fn addr_local(&self) -> SocketAddr {
        CoapAddress::from(unsafe {
            coap_session_get_addr_local(self.inner_ref().raw_session)
                .as_ref()
                .unwrap()
        })
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
    }

    /// Returns the remote address for this session.
    fn addr_remote(&self) -> SocketAddr {
        CoapAddress::from(unsafe {
            coap_session_get_addr_remote(self.inner_ref().raw_session)
                .as_ref()
                .unwrap()
        })
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
    }

    /// Returns the interface index for this session.
    fn if_index(&self) -> IfIndex {
        unsafe { coap_session_get_ifindex(self.inner_ref().raw_session) }
    }

    /// Sets the maximum number of retransmissions for this session.
    fn max_retransmit(&self) -> MaxRetransmit {
        unsafe { coap_session_get_max_retransmit(self.inner_ref().raw_session) }
    }

    fn set_max_retransmit(&mut self, value: MaxRetransmit) {
        unsafe { coap_session_set_max_retransmit(self.inner_ref().raw_session, value) }
    }

    /// Returns the underlying transport protocol used for this session.
    fn proto(&self) -> CoapProtocol {
        unsafe { coap_session_get_proto(self.inner_ref().raw_session) }.into()
    }

    /// Returns the current PSK hint for this session.
    fn psk_hint(&self) -> Option<Box<CoapCryptoPskIdentity>> {
        unsafe {
            coap_session_get_psk_hint(self.inner_ref().raw_session)
                .as_ref()
                .map(|raw_hint| Box::from(std::slice::from_raw_parts(raw_hint.s, raw_hint.length)))
        }
    }

    /// Returns the current PSK identity for this session.
    fn psk_identity(&self) -> Option<Box<CoapCryptoPskIdentity>> {
        unsafe {
            coap_session_get_psk_identity(self.inner_ref().raw_session)
                .as_ref()
                .map(|raw_hint| Box::from(std::slice::from_raw_parts(raw_hint.s, raw_hint.length)))
        }
    }

    /// Returns the current PSK key for this session.
    fn psk_key(&self) -> Option<Box<CoapCryptoPskData>> {
        unsafe {
            coap_session_get_psk_key(self.inner_ref().raw_session)
                .as_ref()
                .map(|raw_hint| Box::from(std::slice::from_raw_parts(raw_hint.s, raw_hint.length)))
        }
    }

    /// Returns the current state of this session.
    fn state(&self) -> CoapSessionState {
        unsafe { coap_session_get_state(self.inner_ref().raw_session).into() }
    }

    /// Initializes the token value used by libcoap.
    ///
    /// Note that this function does not do anything if you are not setting the token manually using
    /// [new_token()](CoapSessionCommon::new_token), because the wrapper will use a random number
    /// generator to set the tokens instead.
    fn init_token(&mut self, token: &[u8; 8]) {
        unsafe { coap_session_init_token(self.inner_mut().raw_session, token.len(), token.as_ptr()) }
    }

    /// Returns the maximum size of a PDU for this session.
    fn max_pdu_size(&self) -> usize {
        unsafe { coap_session_max_pdu_size(self.inner_ref().raw_session) }
    }

    /// Sets the maximum size of a PDU for this session.
    fn set_mtu(&mut self, mtu: u32) {
        unsafe { coap_session_set_mtu(self.inner_mut().raw_session, mtu) }
    }

    /// Returns the next message ID that should be used for this session.
    fn next_message_id(&mut self) -> CoapMessageId {
        unsafe { coap_new_message_id(self.inner_mut().raw_session) as CoapMessageId }
    }

    /// Returns the next token that should be used for requests.
    fn new_token(&mut self, token: &mut [u8; 8]) -> usize {
        let mut length = 8;
        unsafe { coap_session_new_token(self.inner_mut().raw_session, &mut length, token.as_mut_ptr()) }
        length
    }

    /// Send a ping message to the remote peer.
    fn send_ping(&mut self) -> CoapMessageId {
        unsafe { coap_session_send_ping(self.inner_mut().raw_session) }
    }

    /// Send the given message-like object to the peer.
    ///
    /// Returns a MessageConversionError if the supplied object cannot be converted to a message.
    fn send<P: Into<CoapMessage>>(&mut self, pdu: P) -> Result<CoapMessageId, MessageConversionError> {
        let raw_pdu = pdu.into().into_raw_pdu(self)?;
        let mid = unsafe { coap_send(self.inner_mut().raw_session, raw_pdu) };
        Ok(mid)
    }

    /// Sends the given CoapRequest, returning a CoapRequestHandle that can be used to poll the
    /// request for completion.
    ///
    /// Returns a MessageConversionError if the given Request could not be converted into a raw
    /// message.
    fn send_request(&mut self, mut req: CoapRequest) -> Result<CoapRequestHandle, MessageConversionError> {
        if req.token().is_none() {
            let mut token_tmp: Vec<u8> = vec![0; 8];
            rand::thread_rng().fill(&mut token_tmp[0..8]);
            req.set_token(Some(token_tmp))
        }
        let token: Box<[u8]> = Box::from(req.token().unwrap());
        if req.mid().is_none() {
            req.set_mid(Some(self.next_message_id()))
        }
        self.inner_mut()
            .received_responses
            .insert(token.clone(), VecDeque::new());
        self.send(req.into_message()).map(|v| CoapRequestHandle::new(v, token))
    }

    /// Polls whether the request for the given handle already has pending responses.
    ///
    /// Returns an iterator over all responses associated with the request.
    fn poll_handle(&mut self, handle: &CoapRequestHandle) -> std::collections::vec_deque::IntoIter<CoapResponse> {
        self.inner_mut()
            .received_responses
            .insert(handle.token.clone(), VecDeque::new())
            .expect("Attempted to poll handle that does not refer to a valid token")
            .into_iter()
    }

    fn is_waiting_for_token(&self, token: &CoapToken) -> bool {
        self.inner_ref().received_responses.contains_key(token)
    }

    /// Stops listening for responses to this request handle.
    ///
    /// Any future responses to the request associated with this handle will be responded to with an
    /// RST message.
    fn remove_handle(&mut self, handle: CoapRequestHandle) {
        self.inner_mut().received_responses.remove(&handle.token);
    }

    /// Returns a mutable reference to the underlying raw session.
    ///
    /// # Safety
    /// Do not do anything that would interfere with the functionality of this wrapper.
    /// Most importantly, *do not* free the session yourself.
    unsafe fn raw_session_mut(&mut self) -> *mut coap_session_t {
        self.inner_mut().raw_session
    }

    /// Returns a reference to the underlying raw session.
    ///
    /// # Safety
    /// Do not do anything that would interfere with the functionality of this wrapper.
    /// Most importantly, *do not* free the session yourself.
    unsafe fn raw_session(&self) -> *const coap_session_t {
        self.inner_ref().raw_session
    }
}

#[derive(Debug)]
pub enum CoapSession<'a> {
    Client(CoapClientSession<'a>),
    Server(CoapServerSession<'a>),
}

impl<'a> CoapSessionInnerProvider<'a> for CoapSession<'a> {
    fn inner_ref<'b>(&'b self) -> Ref<'b, CoapSessionInner<'a>> {
        match self {
            CoapSession::Client(sess) => sess.inner_ref(),
            CoapSession::Server(sess) => sess.inner_ref(),
        }
    }

    fn inner_mut<'b>(&'b mut self) -> RefMut<'b, CoapSessionInner<'a>> {
        match self {
            CoapSession::Client(sess) => sess.inner_mut(),
            CoapSession::Server(sess) => sess.inner_mut(),
        }
    }
}

impl<'a> CoapSession<'a> {
    /// Restores a CoapSession from its raw counterpart.
    ///
    /// Note that it is not possible to statically infer the lifetime of the created session from
    /// the raw pointer, i.e., the session will be created with an arbitrary lifetime.
    /// Therefore, callers of this function should ensure that the created session instance does not
    /// outlive the context it is bound to.
    /// Failing to do so will result in a panic/abort in the context destructor as it is unable to
    /// claim exclusive ownership of the session.
    ///
    /// # Panics
    /// Panics if the given pointer is a null pointer.
    ///
    /// # Safety
    /// The provided pointer must be valid.
    pub(crate) unsafe fn from_raw(raw_session: *mut coap_session_t) -> CoapSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => CoapClientSession::from_raw(raw_session).into(),
            coap_session_type_t::COAP_SESSION_TYPE_SERVER | coap_session_type_t::COAP_SESSION_TYPE_HELLO => {
                CoapServerSession::from_raw(raw_session).into()
            },
            _ => unreachable!("unknown session type"),
        }
    }
}

impl<'a> From<CoapClientSession<'a>> for CoapSession<'a> {
    fn from(session: CoapClientSession<'a>) -> Self {
        CoapSession::Client(session)
    }
}

impl<'a> From<CoapServerSession<'a>> for CoapSession<'a> {
    fn from(session: CoapServerSession<'a>) -> Self {
        CoapSession::Server(session)
    }
}

impl PartialEq for CoapSession<'_> {
    fn eq(&self, other: &Self) -> bool {
        match self {
            CoapSession::Client(cli_sess) => cli_sess.eq(other),
            CoapSession::Server(srv_sess) => srv_sess.eq(other),
        }
    }
}

impl Eq for CoapSession<'_> {}

#[derive(Debug)]
pub struct CoapSessionInner<'a> {
    raw_session: *mut coap_session_t,
    app_data: Option<Rc<dyn Any>>,
    received_responses: HashMap<CoapToken, VecDeque<CoapResponse>>,
    _context_lifetime_marker: PhantomData<&'a coap_context_t>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapRequestHandle {
    _mid: CoapMessageId,
    token: CoapToken,
}

impl CoapRequestHandle {
    pub fn new<T: Into<Box<[u8]>>>(mid: CoapMessageId, token: T) -> CoapRequestHandle {
        CoapRequestHandle {
            _mid: mid,
            token: token.into(),
        }
    }
}

// This is fine, we don't read the C-type struct, we return it.
#[allow(improper_ctypes_definitions)]
pub(crate) unsafe extern "C" fn session_response_handler(
    session: *mut coap_session_t,
    _sent: *const coap_pdu_t,
    received: *const coap_pdu_t,
    _id: coap_mid_t,
) -> coap_response_t {
    let mut session = CoapSession::from_raw(session);
    let client = session.borrow_mut();
    // First check if the token is actually one we are currently waiting for.
    let raw_token = coap_pdu_get_token(received);
    let token: CoapToken = CoapToken::from(std::slice::from_raw_parts(raw_token.s, raw_token.length));
    if !client.is_waiting_for_token(&token) {
        return coap_response_t::COAP_RESPONSE_FAIL;
    }
    if let Ok(message) = CoapMessage::from_raw_pdu(received).and_then(CoapResponse::from_message) {
        client.add_response(message);
        coap_response_t::COAP_RESPONSE_OK
    } else {
        coap_response_t::COAP_RESPONSE_FAIL
    }
}

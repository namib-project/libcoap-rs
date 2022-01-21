use std::{
    any::Any,
    borrow::{Borrow, BorrowMut},
    cell::Ref,
    collections::{vec_deque::Drain, HashMap, VecDeque},
    ffi::c_void,
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    rc::Rc,
};

use libcoap_sys::{
    coap_bin_const_t, coap_context_t, coap_dtls_cpsk_info_t, coap_fixed_point_t, coap_mid_t, coap_new_bin_const,
    coap_new_message_id, coap_pdu_get_token, coap_pdu_t, coap_response_t, coap_send,
    coap_session_get_ack_random_factor, coap_session_get_ack_timeout, coap_session_get_addr_local,
    coap_session_get_addr_remote, coap_session_get_app_data, coap_session_get_ifindex, coap_session_get_max_retransmit,
    coap_session_get_proto, coap_session_get_psk_hint, coap_session_get_psk_identity, coap_session_get_psk_key,
    coap_session_get_state, coap_session_get_type, coap_session_init_token, coap_session_max_pdu_size,
    coap_session_new_token, coap_session_reference, coap_session_release, coap_session_send_ping,
    coap_session_set_ack_random_factor, coap_session_set_ack_timeout, coap_session_set_app_data,
    coap_session_set_max_retransmit, coap_session_set_mtu, coap_session_set_type_client, coap_session_state_t,
    coap_session_t, coap_session_type_t, coap_str_const_t,
};
use rand::Rng;

use crate::{
    context::CoapContext,
    crypto::{CoapClientCryptoIdentity, CoapClientCryptoProvider, CoapCryptoPsk, CoapServerCryptoProvider},
    error::{MessageConversionError, SessionGetAppDataError},
    message::{CoapMessage, CoapMessageCommon},
    protocol::{CoapProtocol, CoapToken},
    request::{CoapRequest, CoapResponse},
    types::{CoapAddress, CoapAppDataRef, CoapMessageId, IfIndex, MaxRetransmit},
};

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

pub trait CoapSessionCommon {
    fn app_data<T: Any>(&self) -> Result<Option<Rc<T>>, SessionGetAppDataError>;

    /// Sets the application-specific data stored alongside this session.
    fn set_app_data<T: 'static+Any>(&mut self, value: Option<T>);

    /// Clears the application-specific data stored alongside this session.
    fn clear_app_data(&mut self);

    fn ack_random_factor(&self) -> (u16, u16);

    fn set_ack_random_factor(&mut self, integer_part: u16, fractional_part: u16);

    fn ack_timeout(&self) -> (u16, u16);

    fn set_ack_timeout(&mut self, integer_part: u16, fractional_part: u16);

    fn addr_local(&self) -> SocketAddr;

    fn addr_remote(&self) -> SocketAddr;

    fn if_index(&self) -> IfIndex;

    fn max_retransmit(&self) -> MaxRetransmit;

    fn set_max_retransmit(&mut self, value: MaxRetransmit);

    fn proto(&self) -> CoapProtocol;

    fn psk_hint(&self) -> Option<Box<[u8]>>;

    fn psk_identity(&self) -> Option<Box<[u8]>>;

    fn psk_key(&self) -> Option<Box<[u8]>>;

    fn state(&self) -> CoapSessionState;

    fn init_token(&mut self, token: &[u8; 8]);

    fn max_pdu_size(&self) -> usize;

    fn set_mtu(&mut self, mtu: u32);

    fn next_message_id(&mut self) -> CoapMessageId;

    fn new_token(&mut self, token: &mut [u8; 8]) -> usize;

    fn send_ping(&mut self) -> CoapMessageId;

    fn send<P: Into<CoapMessage>>(&mut self, pdu: P) -> Result<CoapMessageId, MessageConversionError>;

    unsafe fn raw_session_mut(&mut self) -> *mut coap_session_t;

    unsafe fn raw_session(&self) -> *const coap_session_t;
}

impl<S: AsRef<CoapSessionInner>+AsMut<CoapSessionInner>> CoapSessionCommon for S {
    fn app_data<T: Any>(&self) -> Result<Option<Rc<T>>, SessionGetAppDataError> {
        let inner = self.as_ref();
        inner
            .app_data
            .as_ref()
            .map(|v| v.clone().downcast().map_err(|_v| SessionGetAppDataError::WrongType))
            .transpose()
    }

    /// Sets the application-specific data stored alongside this session.
    fn set_app_data<T: 'static+Any>(&mut self, value: Option<T>) {
        let inner = self.as_mut();
        let new_box: Option<Rc<dyn Any>> = value.map(|v| Rc::new(v) as Rc<dyn Any>);
        inner.app_data = new_box;
    }

    /// Clears the application-specific data stored alongside this session.
    fn clear_app_data(&mut self) {
        let inner = self.as_mut();
        inner.app_data = None;
        let raw_inner_ptr = unsafe { coap_session_get_app_data(inner.raw_session) };
        if !raw_inner_ptr.is_null() {
            std::mem::drop(unsafe { Rc::from_raw(raw_inner_ptr) });
        }
    }

    fn ack_random_factor(&self) -> (u16, u16) {
        let random_factor = unsafe { coap_session_get_ack_random_factor(self.as_ref().raw_session) };
        return (random_factor.integer_part, random_factor.fractional_part);
    }

    fn set_ack_random_factor(&mut self, integer_part: u16, fractional_part: u16) {
        unsafe {
            coap_session_set_ack_random_factor(
                self.as_mut().raw_session,
                coap_fixed_point_t {
                    integer_part,
                    fractional_part,
                },
            )
        };
    }

    fn ack_timeout(&self) -> (u16, u16) {
        let random_factor = unsafe { coap_session_get_ack_timeout(self.as_ref().raw_session) };
        return (random_factor.integer_part, random_factor.fractional_part);
    }

    fn set_ack_timeout(&mut self, integer_part: u16, fractional_part: u16) {
        unsafe {
            coap_session_set_ack_timeout(
                self.as_ref().raw_session,
                coap_fixed_point_t {
                    integer_part,
                    fractional_part,
                },
            )
        };
    }

    fn addr_local(&self) -> SocketAddr {
        CoapAddress::from(unsafe { coap_session_get_addr_local(self.as_ref().raw_session).as_ref().unwrap() })
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap()
    }

    fn addr_remote(&self) -> SocketAddr {
        CoapAddress::from(unsafe {
            coap_session_get_addr_remote(self.as_ref().raw_session)
                .as_ref()
                .unwrap()
        })
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
    }

    fn if_index(&self) -> IfIndex {
        unsafe { coap_session_get_ifindex(self.as_ref().raw_session) }
    }

    fn max_retransmit(&self) -> MaxRetransmit {
        unsafe { coap_session_get_max_retransmit(self.as_ref().raw_session) }
    }

    fn set_max_retransmit(&mut self, value: MaxRetransmit) {
        unsafe { coap_session_set_max_retransmit(self.as_ref().raw_session, value) }
    }

    fn proto(&self) -> CoapProtocol {
        unsafe { coap_session_get_proto(self.as_ref().raw_session) }.into()
    }

    fn psk_hint(&self) -> Option<Box<[u8]>> {
        unsafe {
            coap_session_get_psk_hint(self.as_ref().raw_session)
                .as_ref()
                .map(|raw_hint| Box::from(std::slice::from_raw_parts(raw_hint.s, raw_hint.length)))
        }
    }

    fn psk_identity(&self) -> Option<Box<[u8]>> {
        unsafe {
            coap_session_get_psk_identity(self.as_ref().raw_session)
                .as_ref()
                .map(|raw_hint| Box::from(std::slice::from_raw_parts(raw_hint.s, raw_hint.length)))
        }
    }

    fn psk_key(&self) -> Option<Box<[u8]>> {
        unsafe {
            coap_session_get_psk_key(self.as_ref().raw_session)
                .as_ref()
                .map(|raw_hint| Box::from(std::slice::from_raw_parts(raw_hint.s, raw_hint.length)))
        }
    }

    fn state(&self) -> CoapSessionState {
        unsafe { coap_session_get_state(self.as_ref().raw_session).into() }
    }

    fn init_token(&mut self, token: &[u8; 8]) {
        unsafe { coap_session_init_token(self.as_mut().raw_session, token.len(), token.as_ptr()) }
    }

    fn max_pdu_size(&self) -> usize {
        unsafe { coap_session_max_pdu_size(self.as_ref().raw_session) }
    }

    fn set_mtu(&mut self, mtu: u32) {
        unsafe { coap_session_set_mtu(self.as_mut().raw_session, mtu) }
    }

    fn next_message_id(&mut self) -> CoapMessageId {
        unsafe { coap_new_message_id(self.as_mut().raw_session) as CoapMessageId }
    }

    fn new_token(&mut self, token: &mut [u8; 8]) -> usize {
        let mut length = 8;
        unsafe { coap_session_new_token(self.as_mut().raw_session, &mut length, token.as_mut_ptr()) }
        length
    }

    fn send_ping(&mut self) -> CoapMessageId {
        unsafe { coap_session_send_ping(self.as_mut().raw_session) }
    }

    fn send<P: Into<CoapMessage>>(&mut self, pdu: P) -> Result<CoapMessageId, MessageConversionError> {
        Ok(unsafe { coap_send(self.as_mut().raw_session, pdu.into().into_raw_pdu(self)?) })
    }

    unsafe fn raw_session_mut(&mut self) -> *mut coap_session_t {
        self.as_mut().raw_session
    }

    unsafe fn raw_session(&self) -> *const coap_session_t {
        self.as_ref().raw_session
    }
}

pub enum CoapSession {
    Client(CoapClientSession),
    Server(CoapServerSession),
}

impl AsRef<CoapSessionInner> for CoapSession {
    fn as_ref(&self) -> &CoapSessionInner {
        match self {
            CoapSession::Client(client) => client.as_ref(),
            CoapSession::Server(server) => server.as_ref(),
        }
    }
}

impl AsMut<CoapSessionInner> for CoapSession {
    fn as_mut(&mut self) -> &mut CoapSessionInner {
        match self {
            CoapSession::Client(client) => client.as_mut(),
            CoapSession::Server(server) => server.as_mut(),
        }
    }
}

#[derive(Debug)]
pub struct CoapClientSession {
    inner: CoapSessionInner,
    crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>,
    crypto_initial_data: Option<CoapClientCryptoIdentity>,
    crypto_current_data: Option<CoapClientCryptoIdentity>,
    received_responses: HashMap<CoapToken, VecDeque<CoapResponse>>,
}

impl CoapClientSession {
    pub unsafe fn from_raw(raw_session: *mut coap_session_t) -> CoapAppDataRef<CoapClientSession> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        let inner = CoapSessionInner::from_raw(raw_session);
        let psk_id = coap_session_get_psk_identity(raw_session).as_ref();
        let psk_key = coap_session_get_psk_key(raw_session).as_ref();
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => {
                let crypto_info = match (psk_id, psk_key) {
                    (Some(id), Some(key)) => Some(CoapClientCryptoIdentity {
                        identity: Box::from(std::slice::from_raw_parts(id.s, id.length)),
                        key: Box::from(std::slice::from_raw_parts(key.s, key.length)),
                    }),
                    (_, _) => None,
                };
                let client_session = CoapClientSession {
                    inner,
                    crypto_provider: None,
                    crypto_initial_data: None,
                    crypto_current_data: crypto_info,
                    received_responses: HashMap::new(),
                };
                let session_ref = CoapAppDataRef::new(client_session);
                unsafe { coap_session_set_app_data(raw_session, session_ref.create_raw_rc()) }
                session_ref
            },
            coap_session_type_t::COAP_SESSION_TYPE_SERVER => {
                panic!("attempted to create CoapClientSession from raw server session")
            },
            _ => unreachable!("unknown session type"),
        }
    }

    pub unsafe fn restore_from_raw(raw_session: *mut coap_session_t) -> CoapAppDataRef<CoapClientSession> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let session_ptr = coap_session_get_app_data(raw_session);
        if session_ptr.is_null() {
            return CoapClientSession::from_raw(raw_session);
        } else {
            CoapAppDataRef::clone_raw_rc(session_ptr)
        }
    }

    pub fn send_request(&mut self, mut req: CoapRequest) -> Result<CoapRequestHandle, MessageConversionError> {
        if req.token().is_none() {
            let mut token_tmp: Vec<u8> = vec![0; 8];
            rand::thread_rng().fill(&mut token_tmp[0..8]);
            req.set_token(Some(token_tmp.into_boxed_slice()))
        }
        let token = req.token().unwrap().clone();
        if req.mid().is_none() {
            req.set_mid(Some(self.next_message_id()))
        }
        self.received_responses.insert(token.clone(), VecDeque::new());
        self.send(req.into_pdu()?).map(|v| CoapRequestHandle::new(v, token))
    }

    pub fn poll_handle(&mut self, handle: &CoapRequestHandle) -> Drain<CoapResponse> {
        self.received_responses
            .get_mut(&handle.token)
            .expect("Attempted to poll handle that does not refer to a valid token")
            .drain(..)
    }

    fn remove_token_reference(&mut self, token: &CoapToken) {
        self.received_responses.remove(token);
    }

    fn is_waiting_for_token(&mut self, token: &CoapToken) -> bool {
        self.received_responses.contains_key(token)
    }

    pub fn set_crypto_provider(&mut self, crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>) {
        self.crypto_provider = crypto_provider;
    }

    fn add_response(&mut self, pdu: CoapResponse) {
        let token = pdu.token();
        if let Some(token) = token {
            if self.received_responses.contains_key(token) {
                self.received_responses.get_mut(token).unwrap().push_back(pdu);
            }
        }
    }
}

impl AsRef<CoapSessionInner> for CoapClientSession {
    fn as_ref(&self) -> &CoapSessionInner {
        &self.inner
    }
}

impl AsMut<CoapSessionInner> for CoapClientSession {
    fn as_mut(&mut self) -> &mut CoapSessionInner {
        &mut self.inner
    }
}

impl From<CoapServerSession> for CoapClientSession {
    fn from(mut server_session: CoapServerSession) -> Self {
        unsafe {
            coap_session_set_type_client(server_session.as_mut().raw_session);
        }
        CoapClientSession {
            inner: server_session.inner,
            crypto_provider: None,
            crypto_initial_data: None,
            crypto_current_data: server_session.crypto_current_data.map(|v| CoapClientCryptoIdentity {
                identity: Vec::new().into_boxed_slice(),
                key: v,
            }),
            received_responses: HashMap::new(),
        }
    }
}

pub struct CoapServerSession {
    inner: CoapSessionInner,
    crypto_current_data: Option<Box<CoapCryptoPsk>>,
}

impl CoapServerSession {
    pub unsafe fn from_raw(raw_session: *mut coap_session_t) -> CoapAppDataRef<CoapServerSession> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        let inner = CoapSessionInner::from_raw(raw_session);
        let psk_key = coap_session_get_psk_key(raw_session).as_ref();
        let session = match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => {
                panic!("attempted to create server session from raw client session")
            },
            coap_session_type_t::COAP_SESSION_TYPE_SERVER => {
                let crypto_info = match psk_key {
                    Some(key) => Some(Box::from(std::slice::from_raw_parts(key.s, key.length))),
                    _ => None,
                };
                CoapServerSession {
                    inner,
                    crypto_current_data: crypto_info,
                }
            },
            coap_session_type_t::COAP_SESSION_TYPE_HELLO => CoapServerSession {
                inner,
                crypto_current_data: None,
            },
            _ => unreachable!("unknown session type"),
        };
        let session_ref = CoapAppDataRef::new(session);
        unsafe { coap_session_set_app_data(raw_session, session_ref.create_raw_rc()) }
        session_ref
    }

    pub unsafe fn restore_from_raw(raw_session: *mut coap_session_t) -> CoapAppDataRef<CoapServerSession> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let session_ptr = coap_session_get_app_data(raw_session);
        if session_ptr.is_null() {
            return CoapServerSession::from_raw(raw_session);
        } else {
            CoapAppDataRef::clone_raw_rc(session_ptr)
        }
    }
}

impl AsRef<CoapSessionInner> for CoapServerSession {
    fn as_ref(&self) -> &CoapSessionInner {
        &self.inner
    }
}

impl AsMut<CoapSessionInner> for CoapServerSession {
    fn as_mut(&mut self) -> &mut CoapSessionInner {
        &mut self.inner
    }
}

#[derive(Debug)]
pub struct CoapSessionInner {
    raw_session: *mut coap_session_t,
    app_data: Option<Rc<dyn Any>>,
}

impl CoapSessionInner {
    unsafe fn from_raw(raw_session: *mut coap_session_t) -> CoapSessionInner {
        CoapSessionInner {
            raw_session,
            app_data: None,
        }
    }
}

impl Drop for CoapSessionInner {
    fn drop(&mut self) {
        unsafe {
            coap_session_release(self.raw_session);
        }
    }
}

pub struct CoapRequestHandle {
    _mid: CoapMessageId,
    token: CoapToken,
}

impl CoapRequestHandle {
    pub fn new(mid: CoapMessageId, token: CoapToken) -> CoapRequestHandle {
        CoapRequestHandle { _mid: mid, token }
    }
}

pub(crate) unsafe extern "C" fn session_response_handler(
    session: *mut coap_session_t,
    _sent: *const coap_pdu_t,
    received: *const coap_pdu_t,
    _id: coap_mid_t,
) -> coap_response_t {
    let mut session = CoapClientSession::restore_from_raw(session);
    let mut client = session.borrow_mut();
    // First check if the token is actually one we are currently waiting for.
    let raw_token = coap_pdu_get_token(received);
    let token: CoapToken = CoapToken::from(std::slice::from_raw_parts(raw_token.s, raw_token.length));
    if !client.is_waiting_for_token(&token) {
        return coap_response_t::COAP_RESPONSE_FAIL;
    }
    if let Ok(message) = CoapMessage::from_raw_pdu(received).and_then(|v| CoapResponse::from_pdu(v)) {
        client.add_response(message);
        coap_response_t::COAP_RESPONSE_OK
    } else {
        coap_response_t::COAP_RESPONSE_FAIL
    }
}

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

pub struct CoapSessionHandle<'a, S: CoapSessionCommon> {
    session_ref: CoapAppDataRef<S>,
    _context_lifetime_marker: PhantomData<&'a mut coap_context_t>,
}

impl<'a, S: CoapSessionCommon> CoapSessionHandle<'a, S> {
    pub(crate) fn new(mut session_ref: CoapAppDataRef<S>) -> CoapSessionHandle<'a, S> {
        // Increase refcount to prevent the underlying session from being freed.
        unsafe { coap_session_reference(session_ref.borrow_mut().raw_session_mut()) };
        CoapSessionHandle {
            session_ref,
            _context_lifetime_marker: Default::default(),
        }
    }
}

impl<S: CoapSessionCommon> Drop for CoapSessionHandle<'_, S> {
    fn drop(&mut self) {
        unsafe { coap_session_release(self.session_ref.borrow_mut().raw_session_mut()) }
    }
}

impl<S: CoapSessionCommon> CoapSessionCommon for CoapSessionHandle<'_, S> {
    fn app_data<T: Any>(&self) -> Result<Option<Rc<T>>, SessionGetAppDataError> {
        self.session_ref.borrow().app_data()
    }

    fn set_app_data<T: 'static+Any>(&mut self, value: Option<T>) {
        self.session_ref.borrow_mut().set_app_data(value)
    }

    fn clear_app_data(&mut self) {
        self.session_ref.borrow_mut().clear_app_data()
    }

    fn ack_random_factor(&self) -> (u16, u16) {
        self.session_ref.borrow().ack_random_factor()
    }

    fn set_ack_random_factor(&mut self, integer_part: u16, fractional_part: u16) {
        self.session_ref
            .borrow_mut()
            .set_ack_random_factor(integer_part, fractional_part)
    }

    fn ack_timeout(&self) -> (u16, u16) {
        self.session_ref.borrow().ack_timeout()
    }

    fn set_ack_timeout(&mut self, integer_part: u16, fractional_part: u16) {
        self.session_ref
            .borrow_mut()
            .set_ack_timeout(integer_part, fractional_part)
    }

    fn addr_local(&self) -> SocketAddr {
        self.session_ref.borrow().addr_local()
    }

    fn addr_remote(&self) -> SocketAddr {
        self.session_ref.borrow().addr_remote()
    }

    fn if_index(&self) -> IfIndex {
        self.session_ref.borrow().if_index()
    }

    fn max_retransmit(&self) -> MaxRetransmit {
        self.session_ref.borrow().max_retransmit()
    }

    fn set_max_retransmit(&mut self, value: MaxRetransmit) {
        self.session_ref.borrow_mut().set_max_retransmit(value)
    }

    fn proto(&self) -> CoapProtocol {
        self.session_ref.borrow().proto()
    }

    fn psk_hint(&self) -> Option<Box<[u8]>> {
        self.session_ref.borrow().psk_key()
    }

    fn psk_identity(&self) -> Option<Box<[u8]>> {
        self.session_ref.borrow().psk_identity()
    }

    fn psk_key(&self) -> Option<Box<[u8]>> {
        self.session_ref.borrow().psk_key()
    }

    fn state(&self) -> CoapSessionState {
        self.session_ref.borrow().state()
    }

    fn init_token(&mut self, token: &[u8; 8]) {
        self.session_ref.borrow_mut().init_token(token)
    }

    fn max_pdu_size(&self) -> usize {
        self.session_ref.borrow().max_pdu_size()
    }

    fn set_mtu(&mut self, mtu: u32) {
        self.session_ref.borrow_mut().set_mtu(mtu)
    }

    fn next_message_id(&mut self) -> CoapMessageId {
        self.session_ref.borrow_mut().next_message_id()
    }

    fn new_token(&mut self, token: &mut [u8; 8]) -> usize {
        self.session_ref.borrow_mut().new_token(token)
    }

    fn send_ping(&mut self) -> CoapMessageId {
        self.session_ref.borrow_mut().send_ping()
    }

    fn send<P: Into<CoapMessage>>(&mut self, pdu: P) -> Result<CoapMessageId, MessageConversionError> {
        self.session_ref.borrow_mut().send(pdu)
    }

    unsafe fn raw_session_mut(&mut self) -> *mut coap_session_t {
        self.session_ref.borrow_mut().raw_session_mut()
    }

    unsafe fn raw_session(&self) -> *const coap_session_t {
        self.session_ref.borrow().raw_session()
    }
}

impl<'a> CoapSessionHandle<'a, CoapClientSession> {
    pub fn send_request(&mut self, mut req: CoapRequest) -> Result<CoapRequestHandle, MessageConversionError> {
        CoapAppDataRef::borrow_mut(&mut self.session_ref).send_request(req)
    }

    pub fn poll_handle(&mut self, handle: &CoapRequestHandle) -> Vec<CoapResponse> {
        CoapAppDataRef::borrow_mut(&mut self.session_ref)
            .poll_handle(handle)
            .collect()
    }

    pub fn set_crypto_provider(&mut self, crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>) {
        CoapAppDataRef::borrow_mut(&mut self.session_ref).set_crypto_provider(crypto_provider)
    }
}

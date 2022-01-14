use std::{
    any::{Any, TypeId},
    borrow::Borrow,
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    ffi::c_void,
    iter::Map,
    net::{SocketAddr, ToSocketAddrs},
    ops::Deref,
    rc::{Rc, Weak},
    slice::Iter,
    vec::IntoIter,
};

use libc::c_int;
use libcoap_sys::{
    coap_fixed_point_t, coap_mid_t, coap_new_message_id, coap_pdu_t, coap_response_t, coap_send,
    coap_session_get_ack_random_factor, coap_session_get_ack_timeout, coap_session_get_addr_local,
    coap_session_get_addr_remote, coap_session_get_app_data, coap_session_get_ifindex, coap_session_get_max_retransmit,
    coap_session_get_proto, coap_session_get_psk_hint, coap_session_get_psk_identity, coap_session_get_psk_key,
    coap_session_get_state, coap_session_get_type, coap_session_init_token, coap_session_max_pdu_size,
    coap_session_new_token, coap_session_reference, coap_session_release, coap_session_send_ping,
    coap_session_set_ack_random_factor, coap_session_set_ack_timeout, coap_session_set_app_data,
    coap_session_set_max_retransmit, coap_session_set_mtu, coap_session_set_type_client, coap_session_state_t,
    coap_session_t, coap_session_type_t,
};

use crate::{
    error::{MessageConversionError, SessionGetAppDataError},
    message::CoapMessage,
    protocol::{CoapProtocol, CoapToken},
    request::{CoapRequest, CoapResponse},
    types::{CoapAddress, CoapMessageId, IfIndex, MaxRetransmit},
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

pub enum CoapSession {
    Client(CoapClientSession),
    Server(CoapServerSession),
}

pub struct CoapClientSession {
    inner: Rc<RefCell<CoapSessionInner>>,
}

pub struct CoapServerSession {
    inner: Rc<RefCell<CoapSessionInner>>,
}

pub struct CoapSessionInner {
    raw_session: *mut coap_session_t,
    app_data: Option<Rc<dyn Any>>,
    received_responses: HashMap<CoapToken, Vec<CoapMessage>>,
}

impl CoapSession {
    pub(crate) unsafe fn from_raw(raw_session: *mut coap_session_t) -> CoapSession {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        let inner = Rc::new(RefCell::new(CoapSessionInner {
            raw_session,
            app_data: None,
            received_responses: HashMap::new(),
        }));
        unsafe { coap_session_set_app_data(raw_session, Rc::into_raw(Rc::clone(&inner)) as *mut c_void) }
        // Increase refcount to prevent the underlying session from being freed.
        coap_session_reference(raw_session);
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => CoapSession::Client(CoapClientSession { inner }),
            coap_session_type_t::COAP_SESSION_TYPE_SERVER => CoapSession::Server(CoapServerSession { inner }),
            coap_session_type_t::COAP_SESSION_TYPE_HELLO => CoapSession::Server(CoapServerSession { inner }),
            _ => unreachable!("unknown session type"),
        }
    }

    pub(crate) unsafe fn restore_from_raw(raw_session: *mut coap_session_t) -> CoapSession {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let session_ptr = coap_session_get_app_data(raw_session) as *const RefCell<CoapSessionInner>;
        if session_ptr.is_null() {
            return CoapSession::from_raw(raw_session);
        } else {
            let session_container = Rc::from_raw(session_ptr);
            let session = CoapSession::from(session_container.clone());
            coap_session_set_app_data(raw_session, Rc::into_raw(session_container) as *mut c_void);
            session
        }
    }

    pub fn app_data<T: Any>(&self) -> Result<Option<Rc<T>>, SessionGetAppDataError> {
        let inner = self.borrow_inner();
        inner
            .app_data
            .as_ref()
            .map(|v| v.clone().downcast().map_err(|v| SessionGetAppDataError::WrongType))
            .transpose()
    }

    /// Sets the application-specific data stored alongside this session.
    pub fn set_app_data<T: 'static+Any>(&self, value: Option<T>) {
        let mut inner = self.borrow_inner_mut();
        let new_box: Option<Rc<dyn Any>> = value.map(|v| Rc::new(v) as Rc<dyn Any>);
        inner.app_data = new_box;
    }

    /// Clears the application-specific data stored alongside this session.
    pub fn clear_app_data(&self) {
        let mut inner = self.borrow_inner_mut();
        inner.app_data = None;
        let raw_inner_ptr = unsafe { coap_session_get_app_data(inner.raw_session) };
        if !raw_inner_ptr.is_null() {
            std::mem::drop(unsafe { Rc::from_raw(raw_inner_ptr) });
        }
    }

    pub fn ack_random_factor(&self) -> (u16, u16) {
        let random_factor = unsafe { coap_session_get_ack_random_factor(self.borrow_inner().raw_session) };
        return (random_factor.integer_part, random_factor.fractional_part);
    }

    pub fn set_ack_random_factor(&self, integer_part: u16, fractional_part: u16) {
        unsafe {
            coap_session_set_ack_random_factor(
                self.borrow_inner().raw_session,
                coap_fixed_point_t {
                    integer_part,
                    fractional_part,
                },
            )
        };
    }

    pub fn ack_timeout(&self) -> (u16, u16) {
        let random_factor = unsafe { coap_session_get_ack_timeout(self.borrow_inner().raw_session) };
        return (random_factor.integer_part, random_factor.fractional_part);
    }

    pub fn set_ack_timeout(&self, integer_part: u16, fractional_part: u16) {
        unsafe {
            coap_session_set_ack_timeout(
                self.borrow_inner().raw_session,
                coap_fixed_point_t {
                    integer_part,
                    fractional_part,
                },
            )
        };
    }

    pub fn addr_local(&self) -> SocketAddr {
        CoapAddress::from(unsafe {
            coap_session_get_addr_local(self.borrow_inner().raw_session)
                .as_ref()
                .unwrap()
        })
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
    }

    pub fn addr_remote(&self) -> SocketAddr {
        CoapAddress::from(unsafe {
            coap_session_get_addr_remote(self.borrow_inner().raw_session)
                .as_ref()
                .unwrap()
        })
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap()
    }

    pub fn ifindex(&self) -> IfIndex {
        unsafe { coap_session_get_ifindex(self.borrow_inner().raw_session) }
    }

    pub fn max_retransmit(&self) -> MaxRetransmit {
        unsafe { coap_session_get_max_retransmit(self.borrow_inner().raw_session) }
    }

    pub fn set_max_retransmit(&self, value: MaxRetransmit) {
        unsafe { coap_session_set_max_retransmit(self.borrow_inner().raw_session, value) }
    }

    pub fn proto(&self) -> CoapProtocol {
        unsafe { coap_session_get_proto(self.borrow_inner().raw_session) }.into()
    }

    pub fn psk_hint(&self) -> Option<&[u8]> {
        unsafe {
            coap_session_get_psk_hint(self.borrow_inner().raw_session)
                .as_ref()
                .map(|raw_hint| std::slice::from_raw_parts(raw_hint.s, raw_hint.length))
        }
    }

    pub fn psk_identity(&self) -> Option<&[u8]> {
        unsafe {
            coap_session_get_psk_identity(self.borrow_inner().raw_session)
                .as_ref()
                .map(|raw_hint| std::slice::from_raw_parts(raw_hint.s, raw_hint.length))
        }
    }

    pub fn psk_key(&self) -> Option<&[u8]> {
        unsafe {
            coap_session_get_psk_key(self.borrow_inner().raw_session)
                .as_ref()
                .map(|raw_hint| std::slice::from_raw_parts(raw_hint.s, raw_hint.length))
        }
    }

    pub fn state(&self) -> CoapSessionState {
        unsafe { coap_session_get_state(self.borrow_inner().raw_session).into() }
    }

    pub fn init_token(&self, token: &[u8; 8]) {
        unsafe { coap_session_init_token(self.borrow_inner_mut().raw_session, token.len(), token.as_ptr()) }
    }

    pub fn max_pdu_size(&self) -> usize {
        unsafe { coap_session_max_pdu_size(self.borrow_inner().raw_session) }
    }

    pub fn set_mtu(&self, mtu: u32) {
        unsafe { coap_session_set_mtu(self.borrow_inner_mut().raw_session, mtu) }
    }

    pub fn next_message_id(&self) -> CoapMessageId {
        unsafe { coap_new_message_id(self.borrow_inner_mut().raw_session) as CoapMessageId }
    }

    pub fn new_token(&self, token: &mut [u8; 8]) -> usize {
        let mut length = 8;
        unsafe { coap_session_new_token(self.borrow_inner_mut().raw_session, &mut length, token.as_mut_ptr()) }
        length
    }

    pub fn send_ping(&self) -> CoapMessageId {
        unsafe { coap_session_send_ping(self.borrow_inner_mut().raw_session) }
    }

    pub fn send<P: Into<CoapMessage>>(&self, pdu: P) -> Result<CoapMessageId, MessageConversionError> {
        Ok(unsafe { coap_send(self.borrow_inner_mut().raw_session, pdu.into().into_raw_pdu()?) })
    }

    pub fn send_request(&mut self, req: CoapRequest) -> Result<CoapRequestHandle, MessageConversionError> {
        let token = req.token().clone();
        match self {
            CoapSession::Client(_) => self.send(req.into_pdu()?).map(|v| CoapRequestHandle { mid: v, token }),
            CoapSession::Server(_) => {
                panic!("attempted to make request from server session (call CoapClientSession::from() first)")
            },
        }
    }

    pub fn poll_handle(
        &self,
        handle: &CoapRequestHandle,
    ) -> Option<IntoIter<Result<CoapResponse, MessageConversionError>>> {
        let response_pdus: Option<Vec<Result<CoapResponse, MessageConversionError>>> = self
            .borrow_inner_mut()
            .received_responses
            .remove(&handle.token)
            .map(|v| v.into_iter().map(|msg| CoapResponse::from_pdu(msg)).collect());
        response_pdus.map(|v| v.into_iter())
    }

    fn add_received_pdu(&mut self, pdu: CoapMessage) {
        let token = pdu.token();
        let mut inner = self.borrow_inner_mut();
        if !inner.received_responses.contains_key(token) {
            inner.received_responses.insert(token.clone(), Vec::new());
        }
        inner.received_responses.get_mut(token).unwrap().push(pdu);
    }

    pub(crate) unsafe fn raw_session(&self) -> *mut coap_session_t {
        self.borrow_inner_mut().raw_session
    }

    fn borrow_inner(&self) -> Ref<CoapSessionInner> {
        match self {
            CoapSession::Client(CoapClientSession { inner }) => RefCell::borrow(inner),
            CoapSession::Server(CoapServerSession { inner }) => RefCell::borrow(inner),
        }
    }

    fn borrow_inner_mut(&self) -> RefMut<CoapSessionInner> {
        match self {
            CoapSession::Client(CoapClientSession { inner }) => inner.borrow_mut(),
            CoapSession::Server(CoapServerSession { inner }) => inner.borrow_mut(),
        }
    }

    fn inner(&self) -> &Rc<RefCell<CoapSessionInner>> {
        match self {
            CoapSession::Client(CoapClientSession { inner }) => inner,
            CoapSession::Server(CoapServerSession { inner }) => inner,
        }
    }

    fn inner_mut(&mut self) -> &mut Rc<RefCell<CoapSessionInner>> {
        match self {
            CoapSession::Client(CoapClientSession { inner }) => inner,
            CoapSession::Server(CoapServerSession { inner }) => inner,
        }
    }
}

impl From<CoapServerSession> for CoapClientSession {
    fn from(server_session: CoapServerSession) -> Self {
        unsafe {
            coap_session_set_type_client(server_session.inner.borrow_mut().raw_session);
        }
        CoapClientSession {
            inner: server_session.inner,
        }
    }
}

impl Drop for CoapSession {
    fn drop(&mut self) {
        unsafe {
            coap_session_release(self.borrow_inner_mut().raw_session);
        }
    }
}

impl From<Rc<RefCell<CoapSessionInner>>> for CoapSession {
    fn from(refcell: Rc<RefCell<CoapSessionInner>>) -> Self {
        let raw_session_type = unsafe { coap_session_get_type(RefCell::borrow(refcell.borrow()).raw_session) };
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => CoapSession::Client(CoapClientSession { inner: refcell }),
            coap_session_type_t::COAP_SESSION_TYPE_SERVER => CoapSession::Server(CoapServerSession { inner: refcell }),
            coap_session_type_t::COAP_SESSION_TYPE_HELLO => CoapSession::Server(CoapServerSession { inner: refcell }),
            _ => unreachable!("unknown session type"),
        }
    }
}

pub struct CoapRequestHandle {
    mid: CoapMessageId,
    token: CoapToken,
}

impl CoapRequestHandle {
    pub fn new(mid: CoapMessageId, token: CoapToken) -> CoapRequestHandle {
        CoapRequestHandle { mid, token }
    }
}

pub(crate) unsafe extern "C" fn session_response_handler(
    session: *mut coap_session_t,
    sent: *const coap_pdu_t,
    received: *const coap_pdu_t,
    id: coap_mid_t,
) -> coap_response_t {
    let mut session = CoapSession::restore_from_raw(session);
    if let Ok(message) = CoapMessage::from_raw_pdu(&session, received) {
        session.add_received_pdu(message);
        return coap_response_t::COAP_RESPONSE_OK;
    } else {
        return coap_response_t::COAP_RESPONSE_FAIL;
    }
}

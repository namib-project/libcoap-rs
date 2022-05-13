// SPDX-License-Identifier: BSD-2-Clause
/*
 * context.rs - CoAP context related code.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::{any::Any, ffi::c_void, fmt::Debug, marker::PhantomData, net::SocketAddr, ops::Sub, time::Duration};

use libc::c_uint;

use libcoap_sys::{
    coap_add_resource, coap_bin_const_t, coap_can_exit, coap_context_get_csm_max_message_size,
    coap_context_get_csm_timeout, coap_context_get_max_handshake_sessions, coap_context_get_max_idle_sessions,
    coap_context_get_session_timeout, coap_context_set_block_mode, coap_context_set_csm_max_message_size,
    coap_context_set_csm_timeout, coap_context_set_keepalive, coap_context_set_max_handshake_sessions,
    coap_context_set_max_idle_sessions, coap_context_set_psk2, coap_context_set_session_timeout, coap_context_t,
    coap_dtls_spsk_info_t, coap_dtls_spsk_t, coap_event_t, coap_free_context, coap_get_app_data, coap_io_process,
    coap_new_context, coap_register_response_handler, coap_set_app_data, coap_set_event_handler,
    COAP_BLOCK_SINGLE_BODY, COAP_BLOCK_USE_LIBCOAP, COAP_DTLS_SPSK_SETUP_VERSION, COAP_IO_WAIT,
};

use crate::event::{event_handler_callback, CoapEventHandler};
use crate::mem::{DropInnerExclusively, FfiPassthroughRefContainer, FfiPassthroughWeakContainer};
use crate::session::{CoapClientSession, CoapServerSession, CoapSession};
use crate::{
    crypto::{
        dtls_server_id_callback, dtls_server_sni_callback, CoapCryptoProviderResponse, CoapCryptoPskIdentity,
        CoapCryptoPskInfo, CoapServerCryptoProvider,
    },
    error::{ContextCreationError, EndpointCreationError, IoProcessError},
    resource::{CoapResource, UntypedCoapResource},
    session::session_response_handler,
    transport::{dtls::CoapDtlsEndpoint, udp::CoapUdpEndpoint, CoapEndpoint},
};

#[derive(Debug)]
pub struct CoapContextInner<'a> {
    /// Reference to the raw context this context wraps around.
    raw_context: *mut coap_context_t,
    /// A list of endpoints that this context is currently associated with.
    endpoints: Vec<CoapEndpoint>,
    /// A list of resources associated with this context.
    resources: Vec<Box<dyn UntypedCoapResource>>,
    /// A list of client-side sessions that were created using the `connect_*` methods
    ///
    /// Note that these are not necessarily all sessions there are. Most notably, server sessions are
    /// automatically created and managed by the underlying C library and are not stored here.
    client_sessions: Vec<CoapClientSession<'a>>,
    server_sessions: Vec<CoapServerSession<'a>>,
    event_handler: Option<Box<dyn CoapEventHandler>>,
    /// The provider for cryptography information for server-side sessions.
    crypto_provider: Option<Box<dyn CoapServerCryptoProvider>>,
    crypto_default_info: Option<CoapCryptoPskInfo>,
    crypto_sni_info_container: Vec<CoapCryptoPskInfo>,
    crypto_current_data: Option<CoapCryptoPskInfo>,
    // coap_dtls_spsk_info_t created upon calling dtls_server_sni_callback() as the SNI validation callback.
    // The caller of the validate_sni_call_back will make a defensive copy, so this one only has
    // to be valid for a very short time and can always be overridden by dtls_server_sni_callback().
    crypto_last_info_ref: coap_dtls_spsk_info_t,
    _context_lifetime_marker: PhantomData<&'a coap_context_t>,
}

/// A CoAP Context – container for general state and configuration information relating to CoAP
///
/// The equivalent to the [coap_context_t] type in libcoap.
#[derive(Debug)]
pub struct CoapContext<'a> {
    inner: FfiPassthroughRefContainer<CoapContextInner<'a>>,
}

impl<'a> CoapContext<'a> {
    /// Creates a new context
    pub fn new() -> Result<CoapContext<'a>, ContextCreationError> {
        let raw_context = unsafe { coap_new_context(std::ptr::null()) };
        if raw_context.is_null() {
            return Err(ContextCreationError::Unknown);
        }
        // SAFETY: We checked that raw_context is not null.
        unsafe {
            coap_context_set_block_mode(raw_context, (COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY) as u8);
            coap_register_response_handler(raw_context, Some(session_response_handler));
        }
        let inner = FfiPassthroughRefContainer::new(CoapContextInner {
            raw_context,
            endpoints: Vec::new(),
            resources: Vec::new(),
            client_sessions: Vec::new(),
            server_sessions: Vec::new(),
            event_handler: None,
            crypto_provider: None,
            crypto_default_info: None,
            crypto_sni_info_container: Vec::new(),
            crypto_current_data: None,
            crypto_last_info_ref: coap_dtls_spsk_info_t {
                hint: coap_bin_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
                key: coap_bin_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
            },
            _context_lifetime_marker: Default::default(),
        });

        unsafe {
            coap_set_app_data(raw_context, inner.create_raw_weak() as *mut c_void);
            coap_set_event_handler(raw_context, Some(event_handler_callback));
        }

        Ok(CoapContext { inner })
    }

    pub(crate) unsafe fn attach_client_session(&mut self, session: CoapClientSession<'a>) {
        self.inner.borrow_mut().client_sessions.push(session);
    }

    pub(crate) unsafe fn from_raw(raw_context: *mut coap_context_t) -> CoapContext<'a> {
        assert!(!raw_context.is_null());
        let inner = FfiPassthroughRefContainer::clone_raw_weak(
            coap_get_app_data(raw_context) as *mut FfiPassthroughWeakContainer<CoapContextInner>
        );

        CoapContext { inner }
    }

    pub(crate) fn handle_event(&self, mut session: CoapSession<'a>, event: coap_event_t) {
        let inner_ref = &mut *self.inner.borrow_mut();
        // Call event handler for event.
        if let Some(handler) = &mut inner_ref.event_handler {
            match event {
                coap_event_t::COAP_EVENT_DTLS_CLOSED => handler.handle_dtls_closed(&mut session),
                coap_event_t::COAP_EVENT_DTLS_CONNECTED => handler.handle_dtls_connected(&mut session),
                coap_event_t::COAP_EVENT_DTLS_RENEGOTIATE => handler.handle_dtls_renegotiate(&mut session),
                coap_event_t::COAP_EVENT_DTLS_ERROR => handler.handle_dtls_error(&mut session),
                coap_event_t::COAP_EVENT_TCP_CONNECTED => handler.handle_tcp_connected(&mut session),
                coap_event_t::COAP_EVENT_TCP_CLOSED => handler.handle_tcp_closed(&mut session),
                coap_event_t::COAP_EVENT_TCP_FAILED => handler.handle_tcp_failed(&mut session),
                coap_event_t::COAP_EVENT_SESSION_CONNECTED => handler.handle_session_connected(&mut session),
                coap_event_t::COAP_EVENT_SESSION_CLOSED => handler.handle_session_closed(&mut session),
                coap_event_t::COAP_EVENT_SESSION_FAILED => handler.handle_session_failed(&mut session),
                coap_event_t::COAP_EVENT_PARTIAL_BLOCK => handler.handle_partial_block(&mut session),
                coap_event_t::COAP_EVENT_SERVER_SESSION_NEW => {
                    if let CoapSession::Server(server_session) = &mut session {
                        handler.handle_server_session_new(server_session)
                    } else {
                        panic!("server-side session event fired for non-server-side session");
                    }
                },
                coap_event_t::COAP_EVENT_SERVER_SESSION_DEL => {
                    if let CoapSession::Server(server_session) = &mut session {
                        handler.handle_server_session_del(server_session)
                    } else {
                        panic!("server-side session event fired for non-server-side session");
                    }
                },
                _ => {
                    // TODO probably a log message is justified here.
                },
            }
        }
        // For server-side sessions: Ensure that server-side session wrappers are either kept in memory or dropped when needed.
        if let CoapSession::Server(serv_sess) = session {
            match event {
                coap_event_t::COAP_EVENT_SERVER_SESSION_NEW => inner_ref.server_sessions.push(serv_sess),
                coap_event_t::COAP_EVENT_SERVER_SESSION_DEL => {
                    std::mem::drop(inner_ref.server_sessions.remove(
                        inner_ref.server_sessions.iter().position(|v| v.eq(&serv_sess)).expect(
                            "attempted to remove session wrapper from context that was never associated with it",
                        ),
                    ));
                    serv_sess.drop_exclusively();
                },
                _ => {},
            }
        }
    }
}

impl CoapContext<'_> {
    /// Performs a controlled shutdown of the CoAP context.
    ///
    /// This will perform all still outstanding IO operations until [coap_can_exit()] confirms that
    /// the context has no more outstanding IO and can be dropped without interrupting sessions.
    pub fn shutdown(mut self, exit_wait_timeout: Option<Duration>) -> Result<(), IoProcessError> {
        let mut remaining_time = exit_wait_timeout;
        // Send remaining packets until we can cleanly shutdown.
        while unsafe { coap_can_exit(self.inner.borrow_mut().raw_context) } == 0 {
            let spent_time = self.do_io(remaining_time)?;
            remaining_time = remaining_time.map(|v| v.sub(spent_time));
        }
        Ok(())
    }

    /// Creates a new UDP endpoint that is bound to the given address.
    pub fn add_endpoint_udp(&mut self, addr: SocketAddr) -> Result<(), EndpointCreationError> {
        // SAFETY: Because we never return an owned reference to the endpoint, it cannot outlive the
        // context it is bound to (i.e. this one).
        let endpoint = unsafe { CoapUdpEndpoint::new(self, addr)? }.into();
        let mut inner_ref = self.inner.borrow_mut();
        inner_ref.endpoints.push(endpoint);
        // Cannot fail, we just pushed to the Vec.
        Ok(())
    }

    /// TODO
    pub fn add_endpoint_tcp(&mut self, _addr: SocketAddr) -> Result<(), EndpointCreationError> {
        todo!()
    }

    /// Creates a new DTLS endpoint that is bound to the given address.
    ///
    /// Note that in order to actually connect to DTLS clients, you need to set a crypto provider
    /// using [set_server_crypto_provider()](CoapContext::set_server_crypto_provider())
    pub fn add_endpoint_dtls(&mut self, addr: SocketAddr) -> Result<(), EndpointCreationError> {
        let endpoint = unsafe { CoapDtlsEndpoint::new(self, addr)? }.into();
        let mut inner_ref = self.inner.borrow_mut();
        inner_ref.endpoints.push(endpoint);
        // Cannot fail, we just pushed to the Vec.
        Ok(())
    }

    /// TODO
    pub fn add_endpoint_tls(&mut self, _addr: SocketAddr) -> Result<(), EndpointCreationError> {
        todo!()
    }

    /// Adds the given resource to the resource pool of this context.
    pub fn add_resource<D: Any + ?Sized + Debug>(&mut self, res: CoapResource<D>) {
        let mut inner_ref = self.inner.borrow_mut();
        inner_ref.resources.push(Box::new(res));
        // SAFETY: raw context is valid, raw resource is also guaranteed to be valid as long as
        // contract of CoapResource is upheld (most importantly,
        // UntypedCoapResource::drop_inner_exclusive() must not have been called).
        unsafe {
            coap_add_resource(
                inner_ref.raw_context,
                inner_ref.resources.last_mut().unwrap().raw_resource(),
            );
        };
    }

    /// Sets the server-side cryptography information provider.
    pub fn set_server_crypto_provider(&mut self, provider: Option<Box<dyn CoapServerCryptoProvider>>) {
        let mut inner_ref = self.inner.borrow_mut();
        // TODO replace Option<Box<Something>> with Option<Borrow<Something>> in libcoap-rs to simplify API.
        inner_ref.crypto_provider = provider;
        if let Some(provider) = &mut inner_ref.crypto_provider {
            inner_ref.crypto_default_info = Some(provider.provide_default_info());
            let initial_data = coap_dtls_spsk_info_t {
                hint: coap_bin_const_t {
                    length: inner_ref.crypto_default_info.as_ref().unwrap().key.len(),
                    s: inner_ref.crypto_default_info.as_ref().unwrap().key.as_ptr(),
                },
                key: coap_bin_const_t {
                    length: inner_ref.crypto_default_info.as_ref().unwrap().key.len(),
                    s: inner_ref.crypto_default_info.as_ref().unwrap().key.as_ptr(),
                },
            };
            // SAFETY: raw context is valid, setup_data is of the right type and contains
            // only valid information.
            unsafe {
                coap_context_set_psk2(
                    inner_ref.raw_context,
                    Box::into_raw(Box::new(coap_dtls_spsk_t {
                        version: COAP_DTLS_SPSK_SETUP_VERSION as u8,
                        reserved: [0; 7],
                        validate_id_call_back: Some(dtls_server_id_callback),
                        id_call_back_arg: inner_ref.raw_context as *mut c_void,
                        validate_sni_call_back: Some(dtls_server_sni_callback),
                        sni_call_back_arg: inner_ref.raw_context as *mut c_void,
                        psk_info: initial_data,
                    })),
                )
            };
        }
    }

    /// Performs currently outstanding IO operations, waiting for a maximum duration of `timeout`.
    ///
    /// This is the function where most of the IO operations made using this library are actually
    /// executed. It is recommended to call this function in a loop for as long as the CoAP context
    /// is used.
    pub fn do_io(&mut self, timeout: Option<Duration>) -> Result<Duration, IoProcessError> {
        let mut inner_ref = self.inner.borrow_mut();
        // Round up the duration if it is not a clean number of seconds.
        let timeout = if let Some(timeout) = timeout {
            let mut temp_timeout = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            if timeout.subsec_micros() > 0 || timeout.subsec_nanos() > 0 {
                temp_timeout = temp_timeout.saturating_add(1);
            }
            temp_timeout
        } else {
            // If no timeout is set, wait indefinitely.
            COAP_IO_WAIT
        };
        let raw_ctx_ptr = inner_ref.raw_context;
        // Lend the current mutable reference to potential callers of CoapContext functions on the
        // other side of the FFI barrier.
        let lend_handle = self.inner.lend_ref_mut(&mut inner_ref);
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        let spent_time = unsafe { coap_io_process(raw_ctx_ptr, timeout) };
        // Demand the returnal of the lent handle, ensuring that the mutable reference is no longer
        // used anywhere.
        lend_handle.unlend();
        // Check for errors.
        if spent_time < 0 {
            return Err(IoProcessError::Unknown);
        }
        // Return with duration of call.
        Ok(Duration::from_millis(spent_time.unsigned_abs() as u64))
    }

    pub fn session_timeout(&self) -> Duration {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        let timeout = unsafe { coap_context_get_session_timeout(self.inner.borrow().raw_context) };
        Duration::from_secs(timeout as u64)
    }

    pub fn set_session_timeout(&self, timeout: Duration) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe {
            coap_context_set_session_timeout(
                self.inner.borrow_mut().raw_context,
                timeout
                    .as_secs()
                    .try_into()
                    .expect("provided session timeout is too large for libcoap (> u32::MAX)"),
            )
        }
    }

    pub fn max_handshake_sessions(&self) -> c_uint {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_get_max_handshake_sessions(self.inner.borrow().raw_context) }
    }

    pub fn set_max_handshake_sessions(&self, max_handshake_sessions: c_uint) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_max_handshake_sessions(self.inner.borrow().raw_context, max_handshake_sessions) };
    }

    pub fn max_idle_sessions(&self) -> c_uint {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_get_max_idle_sessions(self.inner.borrow().raw_context) }
    }

    pub fn set_max_idle_sessions(&self, max_idle_sessions: c_uint) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_max_idle_sessions(self.inner.borrow().raw_context, max_idle_sessions) };
    }

    pub fn csm_max_message_size(&self) -> u32 {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_get_csm_max_message_size(self.inner.borrow().raw_context) }
    }

    pub fn set_csm_max_message_size(&self, csm_max_message_size: u32) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_csm_max_message_size(self.inner.borrow().raw_context, csm_max_message_size) };
    }

    pub fn csm_timeout(&self) -> Duration {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        let timeout = unsafe { coap_context_get_csm_timeout(self.inner.borrow().raw_context) };
        Duration::from_secs(timeout as u64)
    }

    pub fn set_csm_timeout(&self, csm_timeout: Duration) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe {
            coap_context_set_csm_timeout(
                self.inner.borrow().raw_context,
                csm_timeout
                    .as_secs()
                    .try_into()
                    .expect("provided session timeout is too large for libcoap (> u32::MAX)"),
            )
        };
    }

    pub fn set_keepalive(&self, seconds: c_uint) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_keepalive(self.inner.borrow().raw_context, seconds) };
    }

    /// Provide a raw key for a given identity using the CoapContext's set server crypto provider.
    ///
    /// # Safety
    /// Returned pointer should only be used if the context is borrowed.
    /// Calling this function may override previous returned values of this function.
    pub(crate) unsafe fn provide_raw_key_for_identity(
        &self,
        identity: &CoapCryptoPskIdentity,
    ) -> Option<*const coap_bin_const_t> {
        let inner_ref = &mut *self.inner.borrow_mut();
        match inner_ref
            .crypto_provider
            .as_mut()
            .map(|v| v.provide_key_for_identity(identity))
        {
            Some(CoapCryptoProviderResponse::UseNew(new_data)) => {
                inner_ref.crypto_current_data = Some(CoapCryptoPskInfo {
                    identity: Box::from(identity),
                    key: new_data,
                });
                let curr_data = inner_ref.crypto_current_data.as_ref().unwrap();
                curr_data.apply_to_spsk_info(&mut inner_ref.crypto_last_info_ref);
                Some(&inner_ref.crypto_last_info_ref.key as *const coap_bin_const_t)
            },
            Some(CoapCryptoProviderResponse::UseCurrent) => inner_ref.crypto_current_data.as_ref().map(|v| {
                v.apply_to_spsk_info(&mut inner_ref.crypto_last_info_ref);
                &inner_ref.crypto_last_info_ref.key as *const coap_bin_const_t
            }),
            None | Some(CoapCryptoProviderResponse::Unacceptable) => None,
        }
    }

    /// Provide a hint for a given SNI name using the CoapContext's set server crypto provider.
    ///
    /// # Safety
    /// Returned pointer should only be used if the context is borrowed.
    /// Calling this function may override previous returned values of this function.
    pub(crate) unsafe fn provide_raw_hint_for_sni(&self, sni: &str) -> Option<*const coap_dtls_spsk_info_t> {
        let inner_ref = &mut *self.inner.borrow_mut();
        match inner_ref.crypto_provider.as_mut().map(|v| v.provide_hint_for_sni(sni)) {
            Some(CoapCryptoProviderResponse::UseNew(new_info)) => {
                inner_ref.crypto_sni_info_container.push(new_info);
                inner_ref
                    .crypto_sni_info_container
                    .last()
                    .unwrap()
                    .apply_to_spsk_info(&mut inner_ref.crypto_last_info_ref);
                Some(&inner_ref.crypto_last_info_ref as *const coap_dtls_spsk_info_t)
            },
            Some(CoapCryptoProviderResponse::UseCurrent) => {
                if inner_ref.crypto_default_info.is_some() {
                    inner_ref
                        .crypto_default_info
                        .as_ref()
                        .unwrap()
                        .apply_to_spsk_info(&mut inner_ref.crypto_last_info_ref);
                    Some(&inner_ref.crypto_last_info_ref as *const coap_dtls_spsk_info_t)
                } else {
                    None
                }
            },
            None | Some(CoapCryptoProviderResponse::Unacceptable) => None,
        }
    }

    /// Returns a reference to the raw context contained in this struct.
    ///
    /// # Safety
    /// In general, you should not do anything that would interfere with the safe functions of this
    /// struct.
    /// Most notably, this includes the following:
    /// - Associating raw resources with the context and not removing them before the context is
    ///   dropped (may cause segfaults on drop).
    /// - Associating raw sessions that have a reference count != 0 when the CoapContext is dropped
    ///   (will cause an abort on drop)
    /// - Calling `coap_free_context()` on this context (for obvious reasons, this will probably
    ///   cause a segfault if you don't immediately [std::mem::forget()] the CoapContext and never
    ///   use anything related to the context again, but why would you do that?)  
    // Kept here for consistency, even though it is unused.
    #[allow(unused)]
    pub(crate) unsafe fn as_raw_context(&self) -> &coap_context_t {
        // SAFETY: raw_context is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &*self.inner.borrow().raw_context
    }

    /// Returns a mutable reference to the raw context contained in this struct.
    ///
    /// # Safety
    /// In general, you should not do anything that would interfere with the safe functions of this
    /// struct.
    /// Most notably, this includes the following:
    /// - Associating raw resources with the context and not removing them before the context is
    ///   dropped (may cause segfaults on drop).
    /// - Associating raw sessions that have a reference count != 0 when the CoapContext is dropped
    ///   (will cause an abort on drop)
    /// - Calling `coap_free_context()` on this context (for obvious reasons, this will probably
    ///   cause a segfault if you don't immediately [std::mem::forget()] the CoapContext and never
    ///   use anything related to the context again, but why would you do that?)  
    pub(crate) unsafe fn as_mut_raw_context(&mut self) -> &mut coap_context_t {
        // SAFETY: raw_context is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &mut *self.inner.borrow_mut().raw_context
    }

    // TODO coap_session_get_by_peer
}

impl Drop for CoapContextInner<'_> {
    fn drop(&mut self) {
        // Clean up sessions while the remainder of the context is still available.
        for session in std::mem::take(&mut self.client_sessions).into_iter() {
            session.drop_exclusively();
        }
        for session in std::mem::take(&mut self.server_sessions).into_iter() {
            session.drop_exclusively();
        }
        // Clear endpoints because coap_free_context() would free their underlying raw structs.
        self.endpoints.clear();
        // Extract reference to CoapContextInner from raw context and drop it.
        // SAFETY: Value is set upon construction of the inner context and never deleted.
        unsafe {
            std::mem::drop(FfiPassthroughWeakContainer::<CoapContextInner>::from_raw_box(
                coap_get_app_data(self.raw_context) as *mut FfiPassthroughWeakContainer<CoapContextInner>,
            ))
        }
        // Attempt to regain sole ownership over all resources.
        // As long as [CoapResource::into_inner] isn't used and we haven't given out owned
        // CoapResource instances whose raw resource is attached to the raw context, this should
        // never fail.
        std::mem::take(&mut self.resources)
            .into_iter()
            .for_each(UntypedCoapResource::drop_inner_exclusive);
        // SAFETY: We have already dropped all endpoints and contexts which could be freed alongside
        // the actual context, and our raw context reference is valid (as long as the contracts of
        // [as_mut_raw_context()] and [as_mut_context()] are fulfilled).
        unsafe {
            coap_free_context(self.raw_context);
        }
    }
}

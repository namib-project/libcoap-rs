// SPDX-License-Identifier: BSD-2-Clause
/*
 * context.rs - CoAP context related code.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Module containing context-internal types and traits.

use std::{any::Any, ffi::c_void, fmt::Debug, marker::PhantomData, net::SocketAddr, ops::Sub, time::Duration};
use std::sync::Once;

use libc::c_uint;

use libcoap_sys::{
    coap_add_resource, coap_bin_const_t, coap_can_exit, coap_context_get_csm_max_message_size,
    coap_context_get_csm_timeout, coap_context_get_max_handshake_sessions, coap_context_get_max_idle_sessions,
    coap_context_get_session_timeout, coap_context_set_block_mode, coap_context_set_csm_max_message_size,
    coap_context_set_csm_timeout, coap_context_set_keepalive, coap_context_set_max_handshake_sessions,
    coap_context_set_max_idle_sessions, coap_context_set_psk2, coap_context_set_session_timeout, coap_context_t,
    coap_dtls_spsk_info_t, coap_dtls_spsk_t, coap_event_t, coap_free_context, coap_get_app_data, coap_io_process,
    coap_new_context, coap_proto_t, coap_register_event_handler, coap_register_response_handler, coap_set_app_data,
    COAP_BLOCK_SINGLE_BODY, COAP_BLOCK_USE_LIBCOAP, COAP_DTLS_SPSK_SETUP_VERSION, COAP_IO_WAIT,
    coap_startup
};

static COAP_STARTUP_ONCE: Once = Once::new();

#[cfg(feature = "dtls")]
use crate::crypto::{dtls_server_id_callback, dtls_server_sni_callback, CoapServerCryptoProvider};
#[cfg(feature = "dtls")]
use crate::crypto::{CoapCryptoProviderResponse, CoapCryptoPskIdentity, CoapCryptoPskInfo};
use crate::event::{event_handler_callback, CoapEventHandler};
use crate::mem::{CoapLendableFfiRcCell, CoapLendableFfiWeakCell, DropInnerExclusively};

use crate::session::CoapSessionCommon;

use crate::session::CoapServerSession;
use crate::session::CoapSession;
#[cfg(feature = "dtls")]
use crate::{
    error::{ContextCreationError, EndpointCreationError, IoProcessError},
    resource::{CoapResource, UntypedCoapResource},
    session::session_response_handler,
};

use crate::transport::CoapEndpoint;

#[derive(Debug)]
struct CoapContextInner<'a> {
    /// Reference to the raw context this context wraps around.
    raw_context: *mut coap_context_t,
    /// A list of endpoints that this context is currently associated with.
    endpoints: Vec<CoapEndpoint>,
    /// A list of resources associated with this context.
    resources: Vec<Box<dyn UntypedCoapResource>>,
    /// A list of server-side sessions that are currently active.
    server_sessions: Vec<CoapServerSession<'a>>,
    /// The event handler responsible for library-user side handling of events.
    event_handler: Option<Box<dyn CoapEventHandler>>,
    /// The provider for cryptography information for server-side sessions.
    #[cfg(feature = "dtls")]
    crypto_provider: Option<Box<dyn CoapServerCryptoProvider>>,
    /// Last default cryptography info provided to libcoap.
    #[cfg(feature = "dtls")]
    crypto_default_info: Option<CoapCryptoPskInfo>,
    /// Container for SNI information so that the libcoap C library can keep referring to the memory
    /// locations.
    #[cfg(feature = "dtls")]
    crypto_sni_info_container: Vec<CoapCryptoPskInfo>,
    /// Last provided cryptography information for server-side sessions (temporary storage as
    /// libcoap makes defensive copies).
    #[cfg(feature = "dtls")]
    crypto_current_data: Option<CoapCryptoPskInfo>,
    /// Structure referring to the last provided cryptography information for server-side sessions.
    /// coap_dtls_spsk_info_t created upon calling dtls_server_sni_callback() as the SNI validation callback.
    /// The caller of the validate_sni_call_back will make a defensive copy, so this one only has
    /// to be valid for a very short time and can always be overridden by dtls_server_sni_callback().
    #[cfg(feature = "dtls")]
    crypto_last_info_ref: coap_dtls_spsk_info_t,
    _context_lifetime_marker: PhantomData<&'a coap_context_t>,
}

/// A CoAP Context — container for general state and configuration information relating to CoAP
///
/// The equivalent to the [coap_context_t] type in libcoap.
#[derive(Debug)]
pub struct CoapContext<'a> {
    inner: CoapLendableFfiRcCell<CoapContextInner<'a>>,
}

impl<'a> CoapContext<'a> {
    /// Creates a new context.
    ///
    /// # Errors
    /// Returns an error if the underlying libcoap library was unable to create a new context
    /// (probably an allocation error?).
    pub fn new() -> Result<CoapContext<'a>, ContextCreationError> {
        // TODO this should actually be done before calling _any_ libcoap function, not just the
        //      context initialization. Maybe we need to make sure to call this in other places too
        //      (e.g. if a resource is initialized before a context is created).
        COAP_STARTUP_ONCE.call_once(|| unsafe { coap_startup(); });
        // SAFETY: Providing null here is fine, the context will just not be bound to an endpoint
        // yet.
        let raw_context = unsafe { coap_new_context(std::ptr::null()) };
        if raw_context.is_null() {
            return Err(ContextCreationError::Unknown);
        }
        // SAFETY: We checked that raw_context is not null.
        unsafe {
            coap_context_set_block_mode(raw_context, (COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY) as u32);
            coap_register_response_handler(raw_context, Some(session_response_handler));
        }
        let inner = CoapLendableFfiRcCell::new(CoapContextInner {
            raw_context,
            endpoints: Vec::new(),
            resources: Vec::new(),
            server_sessions: Vec::new(),
            event_handler: None,
            #[cfg(feature = "dtls")]
            crypto_provider: None,
            #[cfg(feature = "dtls")]
            crypto_default_info: None,
            #[cfg(feature = "dtls")]
            crypto_sni_info_container: Vec::new(),
            #[cfg(feature = "dtls")]
            crypto_current_data: None,
            #[cfg(feature = "dtls")]
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

        // SAFETY: We checked that the raw context is not null, the provided function is valid and
        // the app data pointer provided must be valid as we just created it using
        // `create_raw_weak_box()`.
        unsafe {
            coap_set_app_data(raw_context, inner.create_raw_weak_box() as *mut c_void);
            coap_register_event_handler(raw_context, Some(event_handler_callback));
        }

        Ok(CoapContext { inner })
    }

    /// Restores a CoapContext from its raw counterpart.
    ///
    /// # Safety
    /// Provided pointer must point to as valid instance of a raw context whose application data
    /// points to a `*mut CoapLendableFfiWeakCell<CoapContextInner>`.
    pub(crate) unsafe fn from_raw(raw_context: *mut coap_context_t) -> CoapContext<'a> {
        assert!(!raw_context.is_null());
        let inner = CoapLendableFfiRcCell::clone_raw_weak_box(
            coap_get_app_data(raw_context) as *mut CoapLendableFfiWeakCell<CoapContextInner>
        );

        CoapContext { inner }
    }

    /// Handle an incoming event provided by libcoap.
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
        // SAFETY: Provided context is always valid as an invariant of this struct.
        while unsafe { coap_can_exit(self.inner.borrow_mut().raw_context) } == 0 {
            let spent_time = self.do_io(remaining_time)?;
            remaining_time = remaining_time.map(|v| v.sub(spent_time));
        }
        Ok(())
    }

    /// Store reference to the endpoint
    fn add_endpoint(&mut self, addr: SocketAddr, proto: coap_proto_t) -> Result<(), EndpointCreationError> {
        let endpoint = CoapEndpoint::new_endpoint(self, addr, proto)?;

        let mut inner_ref = self.inner.borrow_mut();
        inner_ref.endpoints.push(endpoint);
        Ok(())
    }

    /// Creates a new UDP endpoint that is bound to the given address.
    pub fn add_endpoint_udp(&mut self, addr: SocketAddr) -> Result<(), EndpointCreationError> {
        self.add_endpoint(addr, coap_proto_t::COAP_PROTO_UDP)
    }

    /// Creates a new TCP endpoint that is bound to the given address.
    #[cfg(feature = "tcp")]
    pub fn add_endpoint_tcp(&mut self, addr: SocketAddr) -> Result<(), EndpointCreationError> {
        self.add_endpoint(addr, coap_proto_t::COAP_PROTO_TCP)
    }

    /// Creates a new DTLS endpoint that is bound to the given address.
    ///
    /// Note that in order to actually connect to DTLS clients, you need to set a crypto provider
    /// using [set_server_crypto_provider()](CoapContext::set_server_crypto_provider())
    #[cfg(feature = "dtls")]
    pub fn add_endpoint_dtls(&mut self, addr: SocketAddr) -> Result<(), EndpointCreationError> {
        self.add_endpoint(addr, coap_proto_t::COAP_PROTO_DTLS)
    }

    /// TODO
    #[cfg(all(feature = "tcp", feature = "dtls"))]
    pub fn add_endpoint_tls(&mut self, _addr: SocketAddr) -> Result<(), EndpointCreationError> {
        todo!()
        // TODO: self.add_endpoint(addr, coap_proto_t::COAP_PROTO_TLS)
    }

    /// Adds the given resource to the resource pool of this context.
    pub fn add_resource<D: Any + ?Sized + Debug>(&mut self, res: CoapResource<D>) {
        let mut inner_ref = self.inner.borrow_mut();
        inner_ref.resources.push(Box::new(res));
        // SAFETY: raw context is valid, raw resource is also guaranteed to be valid as long as
        // contract of CoapResource is upheld.
        unsafe {
            coap_add_resource(
                inner_ref.raw_context,
                inner_ref.resources.last_mut().unwrap().raw_resource(),
            );
        };
    }

    /// Sets the server-side cryptography information provider.
    #[cfg(feature = "dtls")]
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
                        validate_sni_call_back: {
                            // Unsupported by TinyDTLS
                            #[cfg(not(feature = "dtls_tinydtls"))]
                            {
                                Some(dtls_server_sni_callback)
                            }
                            #[cfg(feature = "dtls_tinydtls")]
                            {
                                None
                            }
                        },
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
        // Other raw structs used by libcoap are encapsulated in a way that they cannot be in use
        // while in this function (considering that they are all !Send).
        let spent_time = unsafe { coap_io_process(raw_ctx_ptr, timeout) };
        // Demand the return of the lent handle, ensuring that the mutable reference is no longer
        // used anywhere.
        lend_handle.unlend();
        // Check for errors.
        if spent_time < 0 {
            return Err(IoProcessError::Unknown);
        }
        // Return with duration of call.
        Ok(Duration::from_millis(spent_time.unsigned_abs() as u64))
    }

    /// Return the duration that idle server-side sessions are kept alive if they are not referenced
    /// or used anywhere else.
    pub fn session_timeout(&self) -> Duration {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        let timeout = unsafe { coap_context_get_session_timeout(self.inner.borrow().raw_context) };
        Duration::from_secs(timeout as u64)
    }

    /// Set the duration that idle server-side sessions are kept alive if they are not referenced or
    /// used anywhere else.
    ///
    /// # Panics
    /// Panics if the provided duration is too large to be provided to libcoap (larger than a
    /// [libc::c_uint]).
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

    /// Returns the maximum number of server-side sessions that can concurrently be in a handshake
    /// state.
    ///
    /// If this number is exceeded, no new handshakes will be accepted.
    pub fn max_handshake_sessions(&self) -> c_uint {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_get_max_handshake_sessions(self.inner.borrow().raw_context) }
    }

    /// Sets the maximum number of server-side sessions that can concurrently be in a handshake
    /// state.
    ///
    /// If this number is exceeded, no new handshakes will be accepted.

    pub fn set_max_handshake_sessions(&self, max_handshake_sessions: c_uint) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_max_handshake_sessions(self.inner.borrow().raw_context, max_handshake_sessions) };
    }

    /// Returns the maximum number of idle server-side sessions for this context.
    ///
    /// If this number is exceeded, the oldest unreferenced session will be freed.
    pub fn max_idle_sessions(&self) -> c_uint {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_get_max_idle_sessions(self.inner.borrow().raw_context) }
    }

    /// Sets the maximum number of idle server-side sessions for this context.
    ///
    /// If this number is exceeded, the oldest unreferenced session will be freed.
    pub fn set_max_idle_sessions(&self, max_idle_sessions: c_uint) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_max_idle_sessions(self.inner.borrow().raw_context, max_idle_sessions) };
    }

    /// Returns the maximum size for Capabilities and Settings Messages
    ///
    /// CSMs are used in CoAP over TCP as specified in
    /// [RFC 8323, Section 5.3](https://datatracker.ietf.org/doc/html/rfc8323#section-5.3).
    pub fn csm_max_message_size(&self) -> u32 {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_get_csm_max_message_size(self.inner.borrow().raw_context) }
    }

    /// Sets the maximum size for Capabilities and Settings Messages
    ///
    /// CSMs are used in CoAP over TCP as specified in
    /// [RFC 8323, Section 5.3](https://datatracker.ietf.org/doc/html/rfc8323#section-5.3).
    pub fn set_csm_max_message_size(&self, csm_max_message_size: u32) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe { coap_context_set_csm_max_message_size(self.inner.borrow().raw_context, csm_max_message_size) };
    }

    /// Returns the timeout for Capabilities and Settings Messages
    ///
    /// CSMs are used in CoAP over TCP as specified in
    /// [RFC 8323, Section 5.3](https://datatracker.ietf.org/doc/html/rfc8323#section-5.3).
    pub fn csm_timeout(&self) -> Duration {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        let timeout = unsafe { coap_context_get_csm_timeout(self.inner.borrow().raw_context) };
        Duration::from_secs(timeout as u64)
    }

    /// Sets the timeout for Capabilities and Settings Messages
    ///
    /// CSMs are used in CoAP over TCP as specified in
    /// [RFC 8323, Section 5.3](https://datatracker.ietf.org/doc/html/rfc8323#section-5.3).
    ///
    /// # Panics
    /// Panics if the provided timeout is too large for libcoap (> [u32::MAX]).
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

    /// Sets the number of seconds to wait before sending a CoAP keepalive message for idle
    /// sessions.
    ///
    /// If the provided value is None, CoAP-level keepalive messages will be disabled.
    ///
    /// # Panics
    /// Panics if the provided duration is too large to be provided to libcoap (larger than a
    /// [libc::c_uint]).
    pub fn set_keepalive(&self, timeout: Option<Duration>) {
        // SAFETY: Properly initialized CoapContext always has a valid raw_context that is not
        // deleted until the CoapContextInner is dropped.
        unsafe {
            coap_context_set_keepalive(
                self.inner.borrow().raw_context,
                timeout.map_or(0, |v| {
                    v.as_secs()
                        .try_into()
                        .expect("provided keepalive time is too large for libcoap (> c_uint)")
                }),
            )
        };
    }

    /// Provide a raw key for a given identity using the CoapContext's set server crypto provider.
    ///
    /// # Safety
    /// Returned pointer should only be used if the context is borrowed.
    /// Calling this function may override previous returned values of this function.
    #[cfg(feature = "dtls")]
    pub(crate) unsafe fn provide_raw_key_for_identity(
        &self,
        identity: &CoapCryptoPskIdentity,
        session: &CoapServerSession,
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
            Some(CoapCryptoProviderResponse::UseCurrent) => {
                if let Some(key) = session.psk_key() {
                    inner_ref.crypto_current_data = Some(CoapCryptoPskInfo {
                        identity: Box::new([]),
                        key,
                    });
                    inner_ref
                        .crypto_current_data
                        .as_ref()
                        .unwrap()
                        .apply_to_spsk_info(&mut inner_ref.crypto_last_info_ref);
                    Some(&inner_ref.crypto_last_info_ref.key)
                } else if inner_ref.crypto_default_info.is_some() {
                    inner_ref
                        .crypto_default_info
                        .as_ref()
                        .unwrap()
                        .apply_to_spsk_info(&mut inner_ref.crypto_last_info_ref);
                    Some(&inner_ref.crypto_last_info_ref.key)
                } else {
                    None
                }
            },
            None | Some(CoapCryptoProviderResponse::Unacceptable) => None,
        }
    }

    /// Provide a hint for a given SNI name using the CoapContext's set server crypto provider.
    ///
    /// # Safety
    /// Returned pointer should only be used if the context is borrowed.
    /// Calling this function may override previous returned values of this function.
    #[cfg(all(feature = "dtls"))]
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
        // Disable event handler before dropping, as we would otherwise need to lend our reference
        // and because calling event handlers is probably undesired when we are already dropping
        // the context.
        // SAFETY: Validity of our raw context is always given for the lifetime of CoapContextInner
        // unless coap_free_context() is called during a violation of the [as_mut_raw_context()] and
        // [as_mut_context()] contracts (we check validity of the pointer on construction).
        // Passing a NULL handler/None to coap_register_event_handler() is allowed as per the
        // documentation.
        unsafe {
            coap_register_event_handler(self.raw_context, None);
        }
        for session in std::mem::take(&mut self.server_sessions).into_iter() {
            session.drop_exclusively();
        }
        // Clear endpoints because coap_free_context() would free their underlying raw structs.
        self.endpoints.clear();
        // Extract reference to CoapContextInner from raw context and drop it.
        // SAFETY: Value is set upon construction of the inner context and never deleted.
        unsafe {
            std::mem::drop(CoapLendableFfiWeakCell::<CoapContextInner>::from_raw_box(
                coap_get_app_data(self.raw_context) as *mut CoapLendableFfiWeakCell<CoapContextInner>,
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

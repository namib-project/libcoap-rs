use std::{
    any::Any,
    cell::RefCell,
    collections::HashMap,
    ffi::c_void,
    fmt::Debug,
    marker::PhantomData,
    net::SocketAddr,
    ops::Sub,
    rc::Rc,
    slice::{Iter, IterMut},
    time::Duration,
};

use libcoap_sys::{
    coap_add_resource, coap_bin_const_t, coap_can_exit, coap_context_set_block_mode, coap_context_set_psk2,
    coap_context_t, coap_dtls_cpsk_info_t, coap_dtls_cpsk_t, coap_dtls_spsk_info_t, coap_dtls_spsk_t,
    coap_free_context, coap_io_process, coap_new_client_session, coap_new_client_session_psk2, coap_new_context,
    coap_proto_t::{COAP_PROTO_DTLS, COAP_PROTO_UDP},
    coap_register_response_handler, coap_session_get_app_data, coap_session_release, COAP_BLOCK_SINGLE_BODY,
    COAP_BLOCK_USE_LIBCOAP, COAP_DTLS_SPSK_SETUP_VERSION, COAP_IO_WAIT,
};

use crate::{
    crypto::{
        dtls_ih_callback, dtls_server_id_callback, dtls_server_sni_callback, CoapClientCryptoProvider,
        CoapServerCryptoProvider,
    },
    error::{ContextCreationError, EndpointCreationError, IoProcessError, SessionCreationError},
    resource::{CoapResource, UntypedCoapResource},
    session::{session_response_handler, CoapClientSession, CoapSessionCommon, CoapSessionHandle},
    transport::{dtls::CoapDtlsEndpoint, udp::CoapUdpEndpoint, CoapEndpoint},
    types::{CoapAddress, CoapAppDataRef},
};

/// A CoAP Context – container for general state and configuration information relating to CoAP
///
/// The equivalent to the [coap_context_t] type in libcoap.
#[derive(Debug)]
pub struct CoapContext<'a> {
    /// Reference to the raw context this context wraps around.
    raw_context: *mut coap_context_t,
    /// A list of endpoints that this context is currently associated with.
    endpoints: Vec<CoapEndpoint>,
    /// A list of resources associated with this context.
    resources: Vec<Box<dyn UntypedCoapResource>>,
    /// A list of client-side sessions that were created using the `connect_*` methods
    ///
    /// Note that these are not necessarily all session there are. Most notably, server sessions are
    /// automatically created and managed by the underlying C library and are not stored here.
    client_sessions: HashMap<SocketAddr, CoapAppDataRef<CoapClientSession>>,
    /// The provider for cryptography information for server-side sessions.
    crypto_provider: Option<Box<dyn CoapServerCryptoProvider>>,
    _context_lifetime_marker: PhantomData<&'a coap_context_t>,
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
        Ok(CoapContext {
            raw_context,
            endpoints: Vec::new(),
            resources: Vec::new(),
            client_sessions: HashMap::new(),
            crypto_provider: None,
            _context_lifetime_marker: Default::default(),
        })
    }

    /// Create a new DTLS encrypted session with the given peer.
    ///
    /// To supply cryptographic information (like PSK hints or key data), you have to provide a
    /// struct implementing [CoapClientCryptoProvider].
    pub fn connect_dtls<P: 'static+CoapClientCryptoProvider>(
        &mut self,
        addr: SocketAddr,
        mut crypto_provider: P,
    ) -> Result<CoapSessionHandle<'a, CoapClientSession>, SessionCreationError> {
        // Get default identity.
        let id = crypto_provider
            .provide_info_for_hint(None)
            .expect("crypto provider did not provide default credentials");
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null, constructed
        // coap_dtls_cpsk_t is of valid format and has no out-of-bounds issues.
        let session = unsafe {
            coap_new_client_session_psk2(
                self.raw_context,
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                COAP_PROTO_DTLS,
                Box::leak(Box::new(coap_dtls_cpsk_t {
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
                })),
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // SAFETY: We just checked that the raw session is valid.
        let mut session = unsafe { CoapClientSession::from_raw(session) };
        session
            .borrow_mut()
            .set_crypto_provider(Some(Box::new(crypto_provider)));
        session.borrow_mut().crypto_initial_data = Some(id);
        self.client_sessions.insert(addr, (&session).clone());
        let handle = CoapSessionHandle::new(session);
        Ok(handle)
    }

    /// Create a new unencrypted session with the given peer over UDP.
    pub fn connect_udp(
        &mut self,
        addr: SocketAddr,
    ) -> Result<CoapSessionHandle<'a, CoapClientSession>, SessionCreationError> {
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null.
        let session = unsafe {
            coap_new_client_session(
                self.raw_context,
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                COAP_PROTO_UDP,
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // SAFETY: We just checked that the raw session is valid.
        let session = unsafe { CoapClientSession::from_raw(session) };
        self.client_sessions.insert(addr, session.clone());
        return Ok(CoapSessionHandle::new(session));
    }
}

impl CoapContext<'_> {
    /// Creates a new UDP endpoint that is bound to the given address.
    pub fn add_endpoint_udp(&mut self, addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        // SAFETY: Because we never return an owned reference to the endpoint, it cannot outlive the
        // context it is bound to (i.e. this one).
        let endpoint = unsafe { CoapUdpEndpoint::new(self, addr)? }.into();
        self.endpoints.push(endpoint);
        // Cannot fail, we just pushed to the Vec.
        Ok(self.endpoints.last_mut().unwrap())
    }

    /// TODO
    pub fn add_endpoint_tcp(&mut self, _addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        todo!()
    }

    /// Creates a new DTLS endpoint that is bound to the given address.
    ///
    /// Note that in order to actually connect to DTLS clients, you need to set a crypto provider
    /// using [set_server_crypto_provider()](CoapContext::set_server_crypto_provider())
    pub fn add_endpoint_dtls(&mut self, addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        let endpoint = unsafe { CoapDtlsEndpoint::new(self, addr)? }.into();
        self.endpoints.push(endpoint);
        // Cannot fail, we just pushed to the Vec.
        Ok(self.endpoints.last_mut().unwrap())
    }

    /// TODO
    pub fn add_endpoint_tls(&mut self, _addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        todo!()
    }

    /// Adds the given resource to the resource pool of this context.
    pub fn add_resource<D: Any+?Sized+Debug>(&mut self, res: CoapResource<D>) {
        self.resources.push(Box::new(res));
        // SAFETY: raw context is valid, raw resource is also guaranteed to be valid as long as
        // contract of CoapResource is upheld (most importantly,
        // UntypedCoapResource::drop_inner_exclusive() must not have been called).
        unsafe {
            coap_add_resource(self.raw_context, self.resources.last().unwrap().raw_resource());
        };
    }

    /// Returns a reference to the server-side cryptography information provider.
    pub(crate) fn server_crypto_provider(&mut self) -> Option<&mut Box<dyn CoapServerCryptoProvider>> {
        self.crypto_provider.as_mut()
    }

    /// Sets the server-side cryptography information provider.
    pub fn set_server_crypto_provider(&mut self, provider: Option<Box<dyn CoapServerCryptoProvider>>) {
        self.crypto_provider = provider;
        if let Some(provider) = &mut self.crypto_provider {
            let initial_data = provider.provide_hint_for_sni(None).map(|v| coap_dtls_spsk_info_t {
                hint: coap_bin_const_t {
                    length: v.hint.len(),
                    s: v.hint.as_ptr(),
                },
                key: coap_bin_const_t {
                    length: v.key.len(),
                    s: v.key.as_ptr(),
                },
            });
            if let Some(initial_data) = initial_data {
                // SAFETY: raw context is valid, setup_data is of the right type and contains
                // only valid information.
                unsafe {
                    coap_context_set_psk2(
                        self.raw_context,
                        Box::leak(Box::new(coap_dtls_spsk_t {
                            version: COAP_DTLS_SPSK_SETUP_VERSION as u8,
                            reserved: [0; 7],
                            validate_id_call_back: Some(dtls_server_id_callback),
                            id_call_back_arg: (self) as *mut CoapContext as *mut c_void,
                            // TODO
                            validate_sni_call_back: Some(dtls_server_sni_callback),
                            sni_call_back_arg: (self) as *const CoapContext as *mut c_void,
                            psk_info: initial_data,
                        })),
                    )
                };
            }
        }
    }

    /// Returns a reference to the resource with the provided `uri_path`.
    ///
    /// Note that because the type of the user data inside of the resource is unknown, the returned
    /// value is a trait object of the [UntypedCoapResource] trait.
    /// To interact with the user data, use [UntypedCoapResource::as_any()] and downcast as
    /// necessary or use trait upcasting if you are on unstable rust (`resource as Any`).
    pub fn resource_by_uri_path(&self, uri_path: &str) -> Option<&dyn UntypedCoapResource> {
        for resource in &self.resources {
            if resource.uri_path() == uri_path {
                return Some(resource.as_ref());
            }
        }
        None
    }

    /// Performs currently outstanding IO operations, waiting for a maximum duration of `timeout`.
    ///
    /// This is the function where most of the IO operations made using this library are actually
    /// executed. It is recommended to call this function in a loop for as long as the CoAP context
    /// is used.
    pub fn do_io(&mut self, timeout: Option<Duration>) -> Result<Duration, IoProcessError> {
        let timeout = if let Some(timeout) = timeout {
            let mut temp_timeout = u32::try_from(timeout.as_millis().saturating_add(1)).unwrap_or(u32::MAX);
            if timeout.subsec_micros() > 0 || timeout.subsec_nanos() > 0 {
                temp_timeout = temp_timeout.saturating_add(1);
            }
            temp_timeout
        } else {
            COAP_IO_WAIT
        };
        let spent_time = unsafe { coap_io_process(self.raw_context, timeout) };
        if spent_time < 0 {
            return Err(IoProcessError::Unknown);
        }
        Ok(Duration::from_millis(spent_time.unsigned_abs() as u64))
    }

    /// Returns an iterator over all endpoints associated with this context.
    pub fn endpoints(&self) -> Iter<'_, CoapEndpoint> {
        self.endpoints.iter()
    }

    /// Returns a mutable iterator over all endpoints associated with this context.
    pub fn endpoints_mut(&mut self) -> IterMut<'_, CoapEndpoint> {
        self.endpoints.iter_mut()
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
    pub unsafe fn as_raw_context(&self) -> &coap_context_t {
        // SAFETY: raw_context is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &*self.raw_context
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
    pub unsafe fn as_mut_raw_context(&mut self) -> &mut coap_context_t {
        // SAFETY: raw_context is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &mut *self.raw_context
    }

    /// Performs a controlled shutdown of the CoAP context.
    ///
    /// This will perform all still outstanding IO operations until [coap_can_exit()] confirms that
    /// the context has no more outstanding IO and can be dropped without interrupting sessions.
    pub fn shutdown(mut self, exit_wait_timeout: Option<Duration>) -> Result<(), IoProcessError> {
        let mut remaining_time = exit_wait_timeout;
        // Send remaining packets until we can cleanly shutdown.
        while unsafe { coap_can_exit(self.raw_context) } == 0 {
            let spent_time = self.do_io(remaining_time)?;
            remaining_time = remaining_time.map(|v| v.sub(spent_time));
        }
        Ok(())
    }

    // TODO coap_session_get_by_peer
}

impl<'a> Drop for CoapContext<'a> {
    fn drop(&mut self) {
        // Clear endpoints because coap_free_context() would free their underlying raw structs.
        self.endpoints.clear();
        for (_addr, mut session) in std::mem::take(&mut self.client_sessions).into_iter() {
            // SAFETY: The sessions here should have valid raw references whose userdata should
            // point to the reference counter, because we didn't provide methods that would allow
            // modifying this user data.
            unsafe {
                let raw_session = session.borrow_mut().raw_session_mut();
                // Client sessions get their reference count set to 1 when calling coap_new_client_session_*
                let extracted_ref: Rc<RefCell<CoapClientSession>> =
                    CoapAppDataRef::raw_ptr_to_rc(coap_session_get_app_data(raw_session));
                std::mem::drop(session);
                let inner_session_rc =
                    Rc::try_unwrap(extracted_ref).expect("session of context being dropped is still in use");
                coap_session_release(raw_session);
                std::mem::drop(inner_session_rc);
            };
        }
        // Attempt to regain sole ownership over all resources.
        // As long as [CoapResource::into_inner] isn't used and we haven't given out owned
        // CoapResource instances whose raw resource is attached to the raw context, this should
        // never fail.
        // TODO Somehow we don't have exclusive ownership here, causing a panic.
        //let resources = std::mem::take(&mut self.resources);
        //resources
        //    .into_iter()
        //    .for_each(|mut res| unsafe { res.drop_inner_exclusive() });
        // SAFETY: We have already dropped all endpoints and contexts which could be freed alongside
        // the actual context, and our raw context reference is valid (as long as the contracts of
        // [as_mut_raw_context()] and [as_mut_context()] are fulfilled).
        unsafe {
            coap_free_context(self.raw_context);
        }
    }
}

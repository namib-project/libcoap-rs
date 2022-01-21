use std::{
    any::Any,
    borrow::{Borrow, BorrowMut},
    cell::RefCell,
    collections::HashMap,
    ffi::c_void,
    net::SocketAddr,
    ops::Sub,
    rc::Rc,
    time::Duration,
};

use libcoap_sys::{
    coap_add_resource, coap_bin_const_t, coap_can_exit, coap_context_set_block_mode, coap_context_set_psk2,
    coap_context_t, coap_dtls_cpsk_info_t, coap_dtls_cpsk_t, coap_dtls_id_callback_t, coap_dtls_spsk_info_t,
    coap_dtls_spsk_t, coap_free_context, coap_io_process, coap_mid_t, coap_new_client_session,
    coap_new_client_session_psk2, coap_new_context, coap_pdu_t,
    coap_proto_t::{COAP_PROTO_DTLS, COAP_PROTO_UDP},
    coap_register_response_handler, coap_resource_t, coap_session_t, COAP_BLOCK_SINGLE_BODY, COAP_BLOCK_USE_LIBCOAP,
    COAP_DTLS_SPSK_SETUP_VERSION, COAP_IO_WAIT,
};

use crate::{
    crypto::{CoapClientCryptoProvider, CoapServerCryptoProvider},
    error::{ContextCreationError, EndpointCreationError, IoProcessError, SessionCreationError},
    resource::{CoapResource, UntypedCoapResource},
    session::{
        dtls_ih_callback, dtls_server_id_callback, session_response_handler, CoapClientSession, CoapSession,
        CoapSessionHandle,
    },
    transport::{udp::CoapUdpEndpoint, CoapEndpoint},
    types::{CoapAddress, CoapAppDataRef},
};

pub struct CoapContext {
    raw_context: *mut coap_context_t,
    endpoints: Vec<CoapEndpoint>,
    resources: Vec<Box<dyn UntypedCoapResource>>,
    sessions: HashMap<SocketAddr, CoapAppDataRef<CoapSession>>,
    crypto_provider: Option<Box<dyn CoapServerCryptoProvider>>,
}

impl CoapContext {
    pub fn new() -> Result<CoapContext, ContextCreationError> {
        let raw_context = unsafe { coap_new_context(std::ptr::null()) };
        if raw_context.is_null() {
            return Err(ContextCreationError::Unknown);
        }
        unsafe {
            coap_context_set_block_mode(raw_context, (COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY) as u8);
            coap_register_response_handler(raw_context, Some(session_response_handler));
        }
        Ok(CoapContext {
            raw_context,
            endpoints: Vec::new(),
            resources: Vec::new(),
            sessions: HashMap::new(),
            crypto_provider: None,
        })
    }

    pub fn add_endpoint_udp(&mut self, addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        let endpoint = unsafe { CoapUdpEndpoint::new(self, addr)? }.into();
        self.endpoints.push(endpoint);
        // Cannot fail, we just pushed to the Vec.
        Ok(self.endpoints.last_mut().unwrap())
    }

    pub fn add_endpoint_tcp(&mut self, addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        todo!()
    }

    pub fn add_endpoint_dtls(&mut self, addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        todo!()
    }

    pub fn add_endpoint_tls(&mut self, addr: SocketAddr) -> Result<&mut CoapEndpoint, EndpointCreationError> {
        todo!()
    }

    pub fn add_resource<D: Any+?Sized>(&mut self, res: CoapResource<D>) {
        self.resources.push(Box::new(res));
        unsafe {
            coap_add_resource(self.raw_context, self.resources.last().unwrap().raw_resource());
        };
    }

    pub(crate) fn server_crypto_provider(&mut self) -> Option<&mut Box<dyn CoapServerCryptoProvider>> {
        self.crypto_provider.as_mut()
    }

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
                unsafe {
                    coap_context_set_psk2(
                        self.raw_context,
                        Box::leak(Box::new(coap_dtls_spsk_t {
                            version: COAP_DTLS_SPSK_SETUP_VERSION as u8,
                            reserved: [0; 7],
                            validate_id_call_back: Some(dtls_server_id_callback),
                            id_call_back_arg: Box::into_raw(Box::from(self)) as *mut c_void,
                            validate_sni_call_back: None,
                            sni_call_back_arg: std::ptr::null_mut::<c_void>(),
                            psk_info: initial_data,
                        })),
                    )
                };
            }
        }
    }

    pub fn resource_by_uri_path<D: Any+?Sized>(&self, uri_path: &str) -> Option<&dyn UntypedCoapResource> {
        for resource in &self.resources {
            if resource.uri_path() == uri_path {
                return Some(resource.as_ref());
            }
        }
        None
    }

    pub fn connect_dtls<P: 'static+CoapClientCryptoProvider>(
        &mut self,
        addr: SocketAddr,
        mut crypto_provider: P,
    ) -> Result<CoapSessionHandle, SessionCreationError> {
        unsafe {
            let id = crypto_provider
                .provide_info_for_hint(None)
                .expect("crypto provider did not provide default credentials");
            let session = coap_new_client_session_psk2(
                self.raw_context,
                std::ptr::null(),
                CoapAddress::from(addr.clone()).as_raw_address(),
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
            );
            if session.is_null() {
                return Err(SessionCreationError::Unknown);
            }
            let mut session = CoapSession::from_raw(session);
            match session.borrow_mut() {
                CoapSession::Client(client_session) => {
                    client_session.set_crypto_provider(Some(Box::new(crypto_provider)));
                    self.sessions.insert(addr.clone(), session);
                    Ok(CoapSessionHandle::new(addr))
                },
                CoapSession::Server(_) => unreachable!(),
            }
        }
    }

    pub fn connect_udp(&mut self, addr: SocketAddr) -> Result<CoapSessionHandle, SessionCreationError> {
        unsafe {
            let session = coap_new_client_session(
                self.raw_context,
                std::ptr::null(),
                CoapAddress::from(addr.clone()).as_raw_address(),
                COAP_PROTO_UDP,
            );
            if session.is_null() {
                return Err(SessionCreationError::Unknown);
            }
            self.sessions.insert(addr.clone(), CoapSession::from_raw(session));
            return Ok(CoapSessionHandle::new(addr));
        }
    }

    pub fn session_by_handle(&self, handle: &CoapSessionHandle) -> Option<&CoapSession> {
        unsafe { self.sessions.get(handle.addr()).map(|v| v.borrow()) }
    }

    pub fn session_by_handle_mut(&mut self, handle: &CoapSessionHandle) -> Option<&mut CoapSession> {
        unsafe { self.sessions.get_mut(handle.addr()).map(|v| v.borrow_mut()) }
    }

    pub fn do_io(&mut self, timeout: Option<Duration>) -> Result<Duration, IoProcessError> {
        let timeout = if let Some(timeout) = timeout {
            let temp_timeout = u32::try_from(timeout.as_millis().saturating_add(1)).unwrap_or(u32::MAX);
            if timeout.subsec_micros() > 0 || timeout.subsec_nanos() > 0 {
                temp_timeout.saturating_add(1);
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

    pub fn endpoints(&self) -> &Vec<CoapEndpoint> {
        &self.endpoints
    }

    pub unsafe fn as_raw_context(&self) -> &coap_context_t {
        // SAFETY: raw_context is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &*self.raw_context
    }

    pub unsafe fn as_mut_raw_context(&self) -> &mut coap_context_t {
        // SAFETY: raw_context is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &mut *self.raw_context
    }

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

impl Drop for CoapContext {
    fn drop(&mut self) {
        // Clear endpoints because coap_free_context() would free their underlying raw structs.
        self.endpoints.clear();
        // Attempt to regain sole ownership over all resources.
        // As long as [CoapResource::into_inner] isn't used and we haven't given out owned
        // CoapResource instances whose raw resource is attached to the raw context, this should
        // never fail.
        let resources = std::mem::take(&mut self.resources);
        // TODO, somehow, it seems that we are not the only ones owning the Rc here.
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

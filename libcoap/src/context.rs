use std::{any::Any, borrow::BorrowMut, cell::RefCell, net::SocketAddr, ops::Sub, rc::Rc, time::Duration};

use libcoap_sys::{
    coap_add_resource, coap_can_exit, coap_context_set_block_mode, coap_context_t, coap_free_context, coap_io_process,
    coap_mid_t, coap_new_client_session, coap_new_context, coap_pdu_t, coap_proto_t::COAP_PROTO_UDP,
    coap_register_response_handler, coap_resource_t, coap_session_t, COAP_BLOCK_SINGLE_BODY, COAP_BLOCK_USE_LIBCOAP,
    COAP_IO_WAIT,
};

#[cfg(feature = "nightly")]
use crate::error::ResourceTypecastingError;
use crate::{
    error::{ContextCreationError, EndpointCreationError, IoProcessError, SessionCreationError},
    resource::CoapResource,
    session::{session_response_handler, CoapClientSession, CoapSession},
    transport::{udp::CoapUdpEndpoint, CoapEndpoint},
    types::CoapAddress,
};

pub struct CoapContext {
    raw_context: *mut coap_context_t,
    endpoints: Vec<CoapEndpoint>,
    resources: Vec<Box<dyn CoapResourceListContent>>,
    sessions: Vec<CoapSession>,
}

pub(crate) trait CoapResourceListContent: Any {
    fn uri_path(&self) -> &str;
    unsafe fn drop_inner_exclusive(&mut self);
    unsafe fn raw_resource(&self) -> *mut coap_resource_t;
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
            sessions: Vec::new(),
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

    #[cfg(feature = "nightly")]
    pub fn resource_by_uri_path_typed<D: Any+?Sized>(
        &self,
        uri_path: &str,
    ) -> Result<Option<&CoapResource<D>>, ResourceTypecastingError> {
        for resource in self.resources {
            if resource.uri_path() == uri_path {
                return (resource as Box<dyn Any>)
                    .downcast_ref::<CoapResource<D>>()
                    .map(|v| Some(v))
                    .ok_or(ResourceTypecastingError::WrongUserDataType);
            }
        }
        Ok(None)
    }

    pub fn connect_udp(&mut self, addr: SocketAddr) -> Result<CoapSession, SessionCreationError> {
        Ok(unsafe {
            CoapSession::from_raw(coap_new_client_session(
                self.raw_context,
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                COAP_PROTO_UDP,
            ))
        })
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

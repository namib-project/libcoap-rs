// SPDX-License-Identifier: BSD-2-Clause
/*
 * transport/dtls.rs - transport-specific code for DTLS.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::net::SocketAddr;

use libcoap_sys::{coap_endpoint_t, coap_free_endpoint, coap_new_endpoint, coap_proto_t::COAP_PROTO_DTLS};

use crate::{context::CoapContext, error::EndpointCreationError, transport::EndpointCommon, types::CoapAddress};

#[derive(Debug)]
pub struct CoapDtlsEndpoint {
    raw_endpoint: *mut coap_endpoint_t,
}

impl CoapDtlsEndpoint {
    /// Creates a new CoapUdpEndpoint and binds it to the supplied SocketAddr.
    ///
    /// This is an unsafe function (see #Safety for an explanation of why) used internally by
    /// libcoap-rs to instantiate new endpoints. You should most likely not use this function, and
    /// use one of the following alternatives instead:
    /// - If you just want to add an endpoint to the coap context, use [CoapContext::add_endpoint_dtls()].
    /// - If you need to (unsafely) modify the underlying [coap_endpoint_t] directly, use
    ///   [CoapContext::add_endpoint_dtls()] to instantiate the endpoint and then [as_mut_raw_endpoint()]
    ///   to access the underlying struct.
    ///
    /// # Safety
    /// All endpoint types defined in this crate contain a [coap_endpoint_t] instance,
    /// which is the representation of endpoints used by the underlying libcoap C library.
    ///
    /// On instantiation, these [coap_endpoint_t] instances are bound to a context, which includes
    /// adding them to a list maintained by the [CoapContext] (or — to be more specific — the
    /// underlying [libcoap_sys::coap_context_t].
    ///
    /// When the context that this endpoint is bound to is dropped, the context calls [libcoap_sys::coap_free_context()],
    /// which will not only free the context, but also all [coap_endpoint_t] instances associated
    /// with it, including the one this struct points to.
    ///
    /// Therefore, if you decide to use this function anyway, you have to ensure that the
    /// CoapContext lives at least as long as this struct does.
    /// Also note that unlike [CoapContext::add_endpoint_dtls()], this function does not add the
    /// endpoint to the [CoapContext::endpoints] vector, while the underlying [coap_endpoint_t] is
    /// added to the underlying [libcoap_sys::coap_context_t]
    pub(crate) unsafe fn new(
        context: &mut CoapContext,
        addr: SocketAddr,
    ) -> Result<CoapDtlsEndpoint, EndpointCreationError> {
        let endpoint = coap_new_endpoint(
            context.as_mut_raw_context(),
            CoapAddress::from(addr).as_raw_address(),
            COAP_PROTO_DTLS,
        );
        if endpoint.is_null() {
            return Err(EndpointCreationError::Unknown);
        }
        Ok(CoapDtlsEndpoint { raw_endpoint: endpoint })
    }
}

impl EndpointCommon for CoapDtlsEndpoint {
    unsafe fn as_raw_endpoint(&self) -> &coap_endpoint_t {
        // SAFETY: raw_endpoint is checked to be a valid pointer on struct instantiation, cannot be
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &*self.raw_endpoint
    }

    unsafe fn as_mut_raw_endpoint(&mut self) -> &mut coap_endpoint_t {
        // SAFETY: raw_endpoint is checked to be a valid pointer on struct instantiation, is not
        // freed by anything outside of here (assuming the contract of this function is kept), and
        // the default (elided) lifetimes are correct (the pointer is valid as long as the endpoint
        // is).
        &mut *self.raw_endpoint
    }
}

impl Drop for CoapDtlsEndpoint {
    fn drop(&mut self) {
        // SAFETY: Raw endpoint is guaranteed to exist for as long as the container exists.
        unsafe { coap_free_endpoint(self.raw_endpoint) }
    }
}

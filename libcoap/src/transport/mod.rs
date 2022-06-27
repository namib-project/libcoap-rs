// SPDX-License-Identifier: BSD-2-Clause
/*
 * transport/mod.rs - Module file for CoAP transports.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::os::raw::c_uint;

use libcoap_sys::{coap_endpoint_set_default_mtu, coap_endpoint_t};

#[cfg(feature = "dtls")]
pub use dtls::CoapDtlsEndpoint;
pub use udp::CoapUdpEndpoint;

#[cfg(feature = "dtls")]
mod dtls;
#[cfg(feature = "tcp")]
mod tcp;
#[cfg(all(feature = "dtls", feature = "tcp"))]
mod tls;
mod udp;

pub type EndpointMtu = c_uint;

/// Trait for functions common between all types of endpoints.
pub trait EndpointCommon {
    /// Provides an immutable reference to the supplied endpoint.
    ///
    /// # Safety
    /// Note that the endpoint expects the reference to be valid for as long as the endpoint
    /// itself exists. Therefore, you should never call [coap_free_endpoint()](libcoap_sys::coap_free_endpoint())
    /// or attach the raw endpoint to a context that does not live for as long as the endpoint
    /// itself ([coap_free_context()](libcoap_sys::coap_free_context()) is called when the
    /// context goes out of scope and then also calls [coap_free_endpoint()](libcoap_sys::coap_free_endpoint())).
    unsafe fn as_raw_endpoint(&self) -> &coap_endpoint_t;

    /// Provides a mutable reference to the supplied endpoint.
    ///
    /// # Safety
    /// Note that the endpoint expects the reference to be valid for as long as the endpoint
    /// itself exists. Therefore, you should never call [coap_free_endpoint()](libcoap_sys::coap_free_endpoint())
    /// or attach the raw endpoint to a context that does not live for as long as the endpoint
    /// itself ([coap_free_context()](libcoap_sys::coap_free_context()) is called when the context
    /// goes out of scope and then also calls [coap_free_endpoint()](libcoap_sys::coap_free_endpoint())).
    unsafe fn as_mut_raw_endpoint(&mut self) -> &mut coap_endpoint_t;

    /// Sets the default MTU value of the endpoint.
    fn set_default_mtu(&mut self, mtu: EndpointMtu) {
        // SAFETY: as_mut_raw_endpoint cannot fail and will always return a valid reference.
        // Modifying the state of the endpoint is also fine, because we have a mutable reference
        // of the whole endpoint.
        unsafe {
            let raw_endpoint = self.as_mut_raw_endpoint();
            coap_endpoint_set_default_mtu(raw_endpoint, mtu);
        }
    }
}

/// Enum representing CoAP endpoints of various types.
#[derive(Debug)]
pub enum CoapEndpoint {
    Udp(CoapUdpEndpoint),
    #[cfg(feature = "dtls")]
    Dtls(CoapDtlsEndpoint),
}

impl From<CoapUdpEndpoint> for CoapEndpoint {
    fn from(ep: CoapUdpEndpoint) -> Self {
        CoapEndpoint::Udp(ep)
    }
}

#[cfg(feature = "dtls")]
impl From<CoapDtlsEndpoint> for CoapEndpoint {
    fn from(ep: CoapDtlsEndpoint) -> Self {
        CoapEndpoint::Dtls(ep)
    }
}

impl EndpointCommon for CoapEndpoint {
    unsafe fn as_raw_endpoint(&self) -> &coap_endpoint_t {
        match self {
            CoapEndpoint::Udp(ep) => ep.as_raw_endpoint(),
            #[cfg(feature = "dtls")]
            CoapEndpoint::Dtls(ep) => ep.as_raw_endpoint(),
        }
    }

    unsafe fn as_mut_raw_endpoint(&mut self) -> &mut coap_endpoint_t {
        match self {
            CoapEndpoint::Udp(ep) => ep.as_mut_raw_endpoint(),
            #[cfg(feature = "dtls")]
            CoapEndpoint::Dtls(ep) => ep.as_mut_raw_endpoint(),
        }
    }
}

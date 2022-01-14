use crate::transport::udp::CoapUdpEndpoint;
use libcoap_sys::{coap_endpoint_set_default_mtu, coap_endpoint_t};
use std::os::raw::c_uint;

#[cfg(feature = "dtls")]
pub mod dtls;
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(all(feature = "dtls", feature = "tcp"))]
pub mod tls;
pub mod udp;

pub trait EndpointCommon {
    unsafe fn as_raw_endpoint(&self) -> &coap_endpoint_t;

    unsafe fn as_mut_raw_endpoint(&mut self) -> &mut coap_endpoint_t;

    fn set_default_mtu(&mut self, mtu: c_uint) {
        // SAFETY: as_mut_raw_endpoint cannot fail and will always return a valid reference.
        // Modifying the state of the endpoint is also fine, because we have a mutable reference
        // of the whole endpoint.
        unsafe {
            let raw_endpoint = self.as_mut_raw_endpoint();
            coap_endpoint_set_default_mtu(raw_endpoint, mtu);
        }
    }
}

pub enum CoapEndpoint {
    Udp(CoapUdpEndpoint),
}

impl From<CoapUdpEndpoint> for CoapEndpoint {
    fn from(ep: CoapUdpEndpoint) -> Self {
        CoapEndpoint::Udp(ep)
    }
}

impl EndpointCommon for CoapEndpoint {
    unsafe fn as_raw_endpoint(&self) -> &coap_endpoint_t {
        match self {
            CoapEndpoint::Udp(ep) => ep.as_raw_endpoint(),
        }
    }

    unsafe fn as_mut_raw_endpoint(&mut self) -> &mut coap_endpoint_t {
        match self {
            CoapEndpoint::Udp(ep) => ep.as_mut_raw_endpoint(),
        }
    }
}

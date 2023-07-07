// SPDX-License-Identifier: BSD-2-Clause
/*
 * transport/mod.rs - Module file for CoAP transports.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::{net::SocketAddr, os::raw::c_uint};

use libcoap_sys::{
    coap_endpoint_set_default_mtu, coap_endpoint_t, coap_free_endpoint, coap_new_endpoint,
    coap_proto_t::COAP_PROTO_DTLS, coap_proto_t::COAP_PROTO_TCP, coap_proto_t::COAP_PROTO_UDP,
};

use crate::{error::EndpointCreationError, types::CoapAddress, CoapContext};

pub type EndpointMtu = c_uint;

#[derive(Debug)]
pub struct CoapEndpoint {
    raw_endpoint: *mut coap_endpoint_t,
}

/// Trait for functions common between all types of endpoints.
impl CoapEndpoint {
    /// Sets the default MTU value of the endpoint.
    pub fn set_default_mtu(&mut self, mtu: EndpointMtu) {
        // SAFETY: as_mut_raw_endpoint cannot fail and will always return a valid reference.
        // Modifying the state of the endpoint is also fine, because we have a mutable reference
        // of the whole endpoint.
        unsafe {
            coap_endpoint_set_default_mtu(&mut *self.raw_endpoint, mtu);
        }
    }

    pub(crate) unsafe fn new_tcp_endpoint(
        context: &mut CoapContext,
        addr: SocketAddr,
    ) -> Result<Self, EndpointCreationError> {
        let endpoint = coap_new_endpoint(
            context.as_mut_raw_context(),
            CoapAddress::from(addr).as_raw_address(),
            COAP_PROTO_TCP,
        );
        if endpoint.is_null() {
            return Err(EndpointCreationError::Unknown);
        }
        Ok(Self { raw_endpoint: endpoint })
    }

    pub(crate) unsafe fn new_dtls_endpoint(
        context: &mut CoapContext,
        addr: SocketAddr,
    ) -> Result<Self, EndpointCreationError> {
        let endpoint = coap_new_endpoint(
            context.as_mut_raw_context(),
            CoapAddress::from(addr).as_raw_address(),
            COAP_PROTO_DTLS,
        );
        if endpoint.is_null() {
            return Err(EndpointCreationError::Unknown);
        }
        Ok(Self { raw_endpoint: endpoint })
    }

    pub(crate) unsafe fn new_udp_endpoint(
        context: &mut CoapContext,
        addr: SocketAddr,
    ) -> Result<Self, EndpointCreationError> {
        let endpoint = coap_new_endpoint(
            context.as_mut_raw_context(),
            CoapAddress::from(addr).as_raw_address(),
            COAP_PROTO_UDP,
        );
        if endpoint.is_null() {
            return Err(EndpointCreationError::Unknown);
        }
        Ok(Self { raw_endpoint: endpoint })
    }
}

impl Drop for CoapEndpoint {
    fn drop(&mut self) {
        // SAFETY: Raw endpoint is guaranteed to exist for as long as the container exists.
        unsafe { coap_free_endpoint(self.raw_endpoint) }
    }
}

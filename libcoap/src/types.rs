// SPDX-License-Identifier: BSD-2-Clause
/*
 * resource.rs - Types for converting between libcoap and Rust data structures.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
//! Types required for conversion between libcoap C library abstractions and Rust types.

use std::{
    cell::{Ref, RefCell, RefMut},
    convert::Infallible,
    ffi::c_void,
    fmt::{Debug, Formatter},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    os::raw::{c_int, c_uint},
    rc::{Rc, Weak},
    slice::Iter,
    str::FromStr,
    vec::Drain,
};

use std::ops::Deref;
use std::ops::DerefMut;

use libc::{in6_addr, in_addr, sa_family_t, sockaddr_in, sockaddr_in6, socklen_t, AF_INET, AF_INET6};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use url::{Host, Url};

use libcoap_sys::{
    coap_address_t, coap_mid_t, coap_proto_t,
    coap_proto_t::{COAP_PROTO_DTLS, COAP_PROTO_NONE, COAP_PROTO_TCP, COAP_PROTO_TLS, COAP_PROTO_UDP},
    coap_uri_scheme_t,
    coap_uri_scheme_t::{
        COAP_URI_SCHEME_COAP, COAP_URI_SCHEME_COAPS, COAP_URI_SCHEME_COAPS_TCP, COAP_URI_SCHEME_COAP_TCP,
        COAP_URI_SCHEME_HTTP, COAP_URI_SCHEME_HTTPS,
    },
    COAP_URI_SCHEME_SECURE_MASK,
};

use crate::error::UriParsingError;

pub type IfIndex = c_int;
pub type MaxRetransmit = c_uint;
pub type CoapMessageId = coap_mid_t;

/// Internal wrapper for the raw coap_address_t type, mainly used for conversion between types.
pub struct CoapAddress(coap_address_t);

impl CoapAddress {
    pub fn as_raw_address(&self) -> &coap_address_t {
        &self.0
    }

    /// Returns a mutable reference to the underlying [coap_address_t].
    ///
    /// Because there are some invariants that must be kept with regards to the underlying
    /// [coap_address_t], this function is unsafe.
    /// If you want to get the coap_address_t safely, use [into_raw_address()](CoapAddress::into_raw_address()).
    ///
    /// # Safety
    /// The underlying [coap_address_t] must always refer to a valid instance of sockaddr_in or
    /// sockaddr_in6, and [coap_address_t::size] must always be the correct size of the sockaddr
    /// in the [coap_address_t::addr] field.
    pub unsafe fn as_mut_raw_address(&mut self) -> &mut coap_address_t {
        &mut self.0
    }

    /// Converts this address into the corresponding raw [coap_address_t](libcoap_sys::coap_address_t)
    pub fn into_raw_address(self) -> coap_address_t {
        self.0
    }
}

impl ToSocketAddrs for CoapAddress {
    type Iter = std::option::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        // SAFETY: That the underlying value of addr is a valid sockaddr is an invariant, the only
        // way the value could be invalid is if as_mut_coap_address_t() (an unsafe function) is used
        // incorrectly.
        let socketaddr = match unsafe { self.0.addr.sa.as_ref().sa_family } as i32 {
            AF_INET => {
                // SAFETY: Validity of addr is an invariant, and we checked that the type of the
                // underlying sockaddr is actually sockaddr_in.
                let raw_addr = unsafe { self.0.addr.sin.as_ref() };
                SocketAddrV4::new(
                    Ipv4Addr::from(raw_addr.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(raw_addr.sin_port),
                )
                .into()
            },
            AF_INET6 => {
                // SAFETY: Validity of addr is an invariant, and we checked that the type of the
                // underlying sockaddr is actually sockaddr_in6.
                let raw_addr = unsafe { self.0.addr.sin6.as_ref() };
                SocketAddrV6::new(
                    Ipv6Addr::from(raw_addr.sin6_addr.s6_addr),
                    u16::from_be(raw_addr.sin6_port),
                    raw_addr.sin6_flowinfo,
                    raw_addr.sin6_scope_id,
                )
                .into()
            },
            // This should not happen as long as the invariants are kept.
            _ => panic!("sa_family_t of underlying coap_address_t is invalid!"),
        };
        Ok(Some(socketaddr).into_iter())
    }
}

impl From<SocketAddr> for CoapAddress {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => {
                // addr is a bindgen-type union wrapper, so we can't assign to it directly and have
                // to use a pointer instead.
                // SAFETY: addr is not read before it is assigned properly, assignment cannot fail.
                unsafe {
                    let mut coap_addr = coap_address_t {
                        size: std::mem::size_of::<sockaddr_in>() as socklen_t,
                        addr: std::mem::zeroed(),
                    };
                    *coap_addr.addr.sin.as_mut() = sockaddr_in {
                        sin_family: AF_INET as sa_family_t,
                        sin_port: addr.port().to_be(),
                        sin_addr: in_addr {
                            s_addr: u32::from_ne_bytes(addr.ip().octets()),
                        },
                        sin_zero: Default::default(),
                    };
                    CoapAddress(coap_addr)
                }
            },
            SocketAddr::V6(addr) => {
                // addr is a bindgen-type union wrapper, so we can't assign to it directly and have
                // to use a pointer instead.
                // SAFETY: addr is not read before it is assigned properly, assignment cannot fail.
                unsafe {
                    let mut coap_addr = coap_address_t {
                        size: std::mem::size_of::<sockaddr_in6>() as socklen_t,
                        addr: std::mem::zeroed(),
                    };
                    *coap_addr.addr.sin6.as_mut() = sockaddr_in6 {
                        sin6_family: AF_INET6 as sa_family_t,
                        sin6_port: addr.port().to_be(),
                        sin6_addr: in6_addr {
                            s6_addr: addr.ip().octets(),
                        },
                        sin6_flowinfo: addr.flowinfo(),
                        sin6_scope_id: addr.scope_id(),
                    };
                    CoapAddress(coap_addr)
                }
            },
        }
    }
}

impl From<coap_address_t> for CoapAddress {
    fn from(raw_addr: coap_address_t) -> Self {
        CoapAddress(raw_addr)
    }
}

impl From<&coap_address_t> for CoapAddress {
    fn from(raw_addr: &coap_address_t) -> Self {
        let mut new_addr = MaybeUninit::zeroed();
        unsafe {
            std::ptr::copy_nonoverlapping(raw_addr, new_addr.as_mut_ptr(), 1);
            CoapAddress(new_addr.assume_init())
        }
    }
}

/// Representation for a URI scheme that can be used in CoAP (proxy) requests.
#[repr(u32)]
#[derive(Copy, Clone, FromPrimitive, Debug, PartialEq, Eq, Hash)]
pub enum CoapUriScheme {
    Coap = COAP_URI_SCHEME_COAP as u32,
    Coaps = COAP_URI_SCHEME_COAPS as u32,
    CoapTcp = COAP_URI_SCHEME_COAP_TCP as u32,
    CoapsTcp = COAP_URI_SCHEME_COAPS_TCP as u32,
    Http = COAP_URI_SCHEME_HTTP as u32,
    Https = COAP_URI_SCHEME_HTTPS as u32,
}

impl CoapUriScheme {
    pub fn is_secure(self) -> bool {
        COAP_URI_SCHEME_SECURE_MASK & (self as u32) > 0
    }

    pub fn from_raw_scheme(scheme: coap_uri_scheme_t) -> CoapUriScheme {
        num_traits::FromPrimitive::from_u32(scheme as u32).expect("unknown scheme")
    }
}

impl FromStr for CoapUriScheme {
    type Err = UriParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "coap" => Ok(CoapUriScheme::Coap),
            "coaps" => Ok(CoapUriScheme::Coaps),
            "coap+tcp" => Ok(CoapUriScheme::CoapTcp),
            "coaps+tcp" => Ok(CoapUriScheme::CoapsTcp),
            "http" => Ok(CoapUriScheme::Http),
            "https" => Ok(CoapUriScheme::Https),
            _ => Err(UriParsingError::NotACoapScheme),
        }
    }
}

impl ToString for CoapUriScheme {
    fn to_string(&self) -> String {
        match self {
            CoapUriScheme::Coap => "coap".to_string(),
            CoapUriScheme::Coaps => "coaps".to_string(),
            CoapUriScheme::CoapTcp => "coap+tcp".to_string(),
            CoapUriScheme::CoapsTcp => "coaps+tcp".to_string(),
            CoapUriScheme::Http => "http".to_string(),
            CoapUriScheme::Https => "https".to_string(),
        }
    }
}

/// Representation of the host part of a CoAP request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CoapUriHost {
    IpLiteral(IpAddr),
    Name(String),
}

impl<T: ToString> From<url::Host<T>> for CoapUriHost {
    fn from(host: Host<T>) -> Self {
        match host {
            Host::Domain(d) => CoapUriHost::Name(d.to_string()),
            Host::Ipv4(addr) => CoapUriHost::IpLiteral(IpAddr::V4(addr)),
            Host::Ipv6(addr) => CoapUriHost::IpLiteral(IpAddr::V6(addr)),
        }
    }
}

impl FromStr for CoapUriHost {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpAddr::from_str(s).map_or_else(|_| CoapUriHost::Name(s.to_string()), CoapUriHost::IpLiteral))
    }
}

impl From<coap_uri_scheme_t> for CoapUriScheme {
    fn from(scheme: coap_uri_scheme_t) -> Self {
        CoapUriScheme::from_raw_scheme(scheme)
    }
}

impl ToString for CoapUriHost {
    fn to_string(&self) -> String {
        match self {
            CoapUriHost::IpLiteral(addr) => addr.to_string(),
            CoapUriHost::Name(host) => host.clone(),
        }
    }
}

/// Representation of an URI for CoAP requests or responses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoapUri {
    scheme: Option<CoapUriScheme>,
    host: Option<CoapUriHost>,
    port: Option<u16>,
    path: Option<Vec<String>>,
    query: Option<Vec<String>>,
}

impl CoapUri {
    pub fn new(
        scheme: Option<CoapUriScheme>,
        host: Option<CoapUriHost>,
        port: Option<u16>,
        path: Option<Vec<String>>,
        query: Option<Vec<String>>,
    ) -> CoapUri {
        CoapUri {
            scheme,
            host,
            port,
            path,
            query,
        }
    }

    pub fn try_from_url(url: Url) -> Result<CoapUri, UriParsingError> {
        let path: Vec<String> = url
            .path()
            .split('/')
            .map(String::from)
            .filter(|v| !v.is_empty())
            .collect();
        let path = if path.is_empty() { None } else { Some(path) };

        let query: Vec<String> = url.query_pairs().map(|(k, v)| format!("{}={}", k, v)).collect();
        let query = if query.is_empty() { None } else { Some(query) };
        Ok(CoapUri {
            scheme: Some(CoapUriScheme::from_str(url.scheme())?),
            host: url.host().map(|h| h.into()),
            port: url.port(),
            path,
            query,
        })
    }

    pub fn scheme(&self) -> Option<&CoapUriScheme> {
        self.scheme.as_ref()
    }

    pub fn host(&self) -> Option<&CoapUriHost> {
        self.host.as_ref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn drain_path_iter(&mut self) -> Option<Drain<String>> {
        self.path.as_mut().map(|p| p.drain(..))
    }

    pub fn path_iter(&self) -> Option<Iter<'_, String>> {
        self.path.as_ref().map(|p| p.iter())
    }

    pub fn drain_query_iter(&mut self) -> Option<Drain<String>> {
        self.query.as_mut().map(|p| p.drain(..))
    }

    pub fn query_iter(&self) -> Option<Iter<String>> {
        self.query.as_ref().map(|p| p.iter())
    }
}

impl TryFrom<Url> for CoapUri {
    type Error = UriParsingError;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        CoapUri::try_from_url(value)
    }
}

/// Transport protocols that can be used with libcoap.
#[repr(u32)]
#[non_exhaustive]
#[derive(Copy, Clone, FromPrimitive, PartialEq, Eq, Hash)]
pub enum CoapProtocol {
    None = COAP_PROTO_NONE as u32,
    Udp = COAP_PROTO_UDP as u32,
    Dtls = COAP_PROTO_DTLS as u32,
    Tcp = COAP_PROTO_TCP as u32,
    Tls = COAP_PROTO_TLS as u32,
}

impl From<coap_proto_t> for CoapProtocol {
    fn from(raw_proto: coap_proto_t) -> Self {
        <CoapProtocol as FromPrimitive>::from_u32(raw_proto as u32).expect("unknown protocol")
    }
}

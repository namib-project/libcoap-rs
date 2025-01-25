// SPDX-License-Identifier: BSD-2-Clause
/*
 * resource.rs - Types for converting between libcoap and Rust data structures.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Types required for conversion between libcoap C library abstractions and Rust types.

use core::ffi::c_ushort;
use std::{
    ffi::{CStr, CString},
    fmt::{Debug, Display, Formatter},
    marker::PhantomPinned,
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    os::raw::c_int,
    pin::Pin,
    str::FromStr,
};

use libcoap_sys::{
    c_stdlib::{in6_addr, in_addr, sa_family_t, sockaddr_in, sockaddr_in6, socklen_t, AF_INET, AF_INET6},
    coap_address_t, coap_delete_optlist, coap_mid_t, coap_proto_t, coap_proto_t_COAP_PROTO_DTLS,
    coap_proto_t_COAP_PROTO_NONE, coap_proto_t_COAP_PROTO_TCP, coap_proto_t_COAP_PROTO_TLS,
    coap_proto_t_COAP_PROTO_UDP, coap_split_proxy_uri, coap_split_uri, coap_str_const_t, coap_string_equal,
    coap_uri_into_optlist, coap_uri_scheme_t, coap_uri_scheme_t_COAP_URI_SCHEME_COAP,
    coap_uri_scheme_t_COAP_URI_SCHEME_COAPS, coap_uri_scheme_t_COAP_URI_SCHEME_COAPS_TCP,
    coap_uri_scheme_t_COAP_URI_SCHEME_COAPS_WS, coap_uri_scheme_t_COAP_URI_SCHEME_COAP_TCP,
    coap_uri_scheme_t_COAP_URI_SCHEME_COAP_WS, coap_uri_scheme_t_COAP_URI_SCHEME_HTTP,
    coap_uri_scheme_t_COAP_URI_SCHEME_HTTPS, coap_uri_t, COAP_URI_SCHEME_SECURE_MASK,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
#[cfg(feature = "url")]
use url::Url;

use crate::{context::ensure_coap_started, error::UriParsingError, message::CoapOption, protocol::UriPort};

/// Interface index used internally by libcoap to refer to an endpoint.
pub type IfIndex = c_int;
/// Value for maximum retransmits.
pub type MaxRetransmit = c_ushort;
/// Identifier for a CoAP message.
pub type CoapMessageId = coap_mid_t;

/// Internal wrapper for the raw coap_address_t type, mainly used for conversion between types.
pub(crate) struct CoapAddress(coap_address_t);

impl CoapAddress {
    /// Returns a reference to the underlying raw [coap_address_t].
    pub(crate) fn as_raw_address(&self) -> &coap_address_t {
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
    // Kept for consistency
    #[allow(dead_code)]
    pub(crate) unsafe fn as_mut_raw_address(&mut self) -> &mut coap_address_t {
        &mut self.0
    }

    /// Converts this address into the corresponding raw [coap_address_t](libcoap_sys::coap_address_t)
    // Kept for consistency
    #[allow(dead_code)]
    pub(crate) fn into_raw_address(self) -> coap_address_t {
        self.0
    }
}

impl ToSocketAddrs for CoapAddress {
    type Iter = std::option::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        // SAFETY: That the underlying value of addr is a valid sockaddr is an invariant, the only
        // way the value could be invalid is if as_mut_coap_address_t() (an unsafe function) is used
        // incorrectly.
        let socketaddr = match unsafe { self.0.addr.sa.sa_family as _ } {
            AF_INET => {
                // SAFETY: Validity of addr is an invariant, and we checked that the type of the
                // underlying sockaddr is actually sockaddr_in.
                let raw_addr = unsafe { self.0.addr.sin };
                SocketAddrV4::new(
                    Ipv4Addr::from(raw_addr.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(raw_addr.sin_port),
                )
                .into()
            },
            AF_INET6 => {
                // SAFETY: Validity of addr is an invariant, and we checked that the type of the
                // underlying sockaddr is actually sockaddr_in6.
                let raw_addr = unsafe { self.0.addr.sin6 };

                // The esp_idf_sys definition of sockaddr_in6 differs slightly.
                #[cfg(not(target_os = "espidf"))]
                let raw_addr_bytes = raw_addr.sin6_addr.s6_addr;
                #[cfg(target_os = "espidf")]
                // SAFETY: Both representations are valid.
                let raw_addr_bytes = unsafe { raw_addr.sin6_addr.un.u8_addr };

                SocketAddrV6::new(
                    Ipv6Addr::from(raw_addr_bytes),
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

                    coap_addr.addr.sin = sockaddr_in {
                        #[cfg(any(
                            target_os = "freebsd",
                            target_os = "dragonfly",
                            target_os = "openbsd",
                            target_os = "netbsd",
                            target_os = "aix",
                            target_os = "haiku",
                            target_os = "hurd",
                            target_os = "espidf",
                        ))]
                        sin_len: (std::mem::size_of::<sockaddr_in>() as u8),
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

                    // Representation of sockaddr_in6 differs depending on the used OS, therefore
                    // some fields are a bit different.
                    coap_addr.addr.sin6 = sockaddr_in6 {
                        #[cfg(any(
                            target_os = "freebsd",
                            target_os = "dragonfly",
                            target_os = "openbsd",
                            target_os = "netbsd",
                            target_os = "aix",
                            target_os = "haiku",
                            target_os = "hurd",
                            target_os = "espidf",
                        ))]
                        sin6_len: (std::mem::size_of::<sockaddr_in6>() as u8),
                        sin6_family: AF_INET6 as sa_family_t,
                        sin6_port: addr.port().to_be(),
                        sin6_addr: in6_addr {
                            #[cfg(not(target_os = "espidf"))]
                            s6_addr: addr.ip().octets(),
                            #[cfg(target_os = "espidf")]
                            un: libcoap_sys::c_stdlib::in6_addr__bindgen_ty_1 {
                                u8_addr: addr.ip().octets(),
                            },
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

#[doc(hidden)]
impl From<coap_address_t> for CoapAddress {
    fn from(raw_addr: coap_address_t) -> Self {
        CoapAddress(raw_addr)
    }
}

#[doc(hidden)]
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
    Coap = coap_uri_scheme_t_COAP_URI_SCHEME_COAP as u32,
    Coaps = coap_uri_scheme_t_COAP_URI_SCHEME_COAPS as u32,
    CoapTcp = coap_uri_scheme_t_COAP_URI_SCHEME_COAP_TCP as u32,
    CoapsTcp = coap_uri_scheme_t_COAP_URI_SCHEME_COAPS_TCP as u32,
    Http = coap_uri_scheme_t_COAP_URI_SCHEME_HTTP as u32,
    Https = coap_uri_scheme_t_COAP_URI_SCHEME_HTTPS as u32,
    CoapWs = coap_uri_scheme_t_COAP_URI_SCHEME_COAP_WS as u32,
    CoapsWs = coap_uri_scheme_t_COAP_URI_SCHEME_COAPS_WS as u32,
}

impl CoapUriScheme {
    pub fn is_secure(self) -> bool {
        COAP_URI_SCHEME_SECURE_MASK & (self as u32) > 0
    }

    pub fn from_raw_scheme(scheme: coap_uri_scheme_t) -> CoapUriScheme {
        FromPrimitive::from_u32(scheme as u32).expect("unknown scheme")
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
            "coap+ws" => Ok(CoapUriScheme::CoapWs),
            "coaps+ws" => Ok(CoapUriScheme::CoapsWs),
            _ => Err(UriParsingError::NotACoapScheme(s.to_string())),
        }
    }
}

impl Display for CoapUriScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CoapUriScheme::Coap => "coap",
            CoapUriScheme::Coaps => "coaps",
            CoapUriScheme::CoapTcp => "coap+tcp",
            CoapUriScheme::CoapsTcp => "coaps+tcp",
            CoapUriScheme::Http => "http",
            CoapUriScheme::Https => "https",
            CoapUriScheme::CoapWs => "coap+ws",
            CoapUriScheme::CoapsWs => "coaps+ws",
        })
    }
}

impl From<coap_uri_scheme_t> for CoapUriScheme {
    fn from(scheme: coap_uri_scheme_t) -> Self {
        CoapUriScheme::from_raw_scheme(scheme)
    }
}

impl From<CoapProtocol> for CoapUriScheme {
    fn from(value: CoapProtocol) -> Self {
        match value {
            CoapProtocol::None | CoapProtocol::Udp => CoapUriScheme::Coap,
            CoapProtocol::Dtls => CoapUriScheme::Coaps,
            CoapProtocol::Tcp => CoapUriScheme::CoapTcp,
            CoapProtocol::Tls => CoapUriScheme::CoapsTcp,
        }
    }
}

/// Representation of a URI for CoAP requests, responses or proxy URIs.
///
/// See https://datatracker.ietf.org/doc/html/rfc7252#section-6 for a description of how a URI
/// should look like.
///
/// # Examples
/// The easiest way to instantiate a request or location CoAP URI is by parsing a string (either
/// using the [FromStr] implementation or using [CoapUri::try_from_str]):
/// ```
/// use libcoap_rs::error::UriParsingError;
/// use libcoap_rs::types::{CoapUri, CoapUriScheme};
///
/// let uri: CoapUri = "coap://example.com:4711/foo/bar?answer=42".parse()?;
///
/// assert_eq!(uri.scheme(), Some(CoapUriScheme::Coap));
/// assert_eq!(uri.host(), Some("example.com".as_bytes()));
/// assert_eq!(uri.port(), Some(4711));
/// assert_eq!(uri.path(), Some("foo/bar".as_bytes()));
/// assert_eq!(uri.query(), Some("answer=42".as_bytes()));
/// assert!(!uri.is_proxy());
///
/// # Result::<(), UriParsingError>::Ok(())
/// ```
///
/// Alternatively, a [CoapUri] may be constructed from its parts using [CoapUri::new] or
/// [CoapUri::new_relative] or from a [Url] (requires the `url` feature), refer to the method level
/// documentation for more information.
///
/// If you want to create a proxy URI, refer to the method-level documentation [CoapUri::new_proxy],
/// [CoapUri::try_from_str_proxy] or [CoapUri::try_from_url_proxy].
///
/// # Note on URI Length Limits
///
/// Due to [the specified limits](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10)
/// of CoAP option lengths, the URI path components, query components, and hostnames for a URI must not
/// exceed 255 bytes each, i.e. a full path with more than 255 bytes is fine, but each individual
/// path segment must be smaller than 255 bytes.
///
/// For proxy URIs, there is a length limit of 255 bytes for the scheme.
/// As we use the Uri-* options for encoding proxy URIs instead of the Proxy-Uri option (as
/// specified in [RFC 7252, section 5.10.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.2)),
/// the above limits regarding path and query components also apply here.
#[derive(Debug)]
pub struct CoapUri {
    is_proxy: bool,
    raw_uri: coap_uri_t,
    uri_str: Pin<Box<CoapUriInner>>,
}

#[derive(Debug)]
struct CoapUriInner(CString, PhantomPinned);

impl CoapUri {
    /// Creates a new [CoapUri] for use as a request or location URI from its constituent parts.
    ///
    /// # Errors
    /// May fail if the provided fields do not represent a valid relative URI or if the arguments
    /// exceed maximum lengths (see the struct level documentation).
    ///
    /// # Examples
    /// ```
    /// use libcoap_rs::error::UriParsingError;
    /// use libcoap_rs::types::{CoapUri, CoapUriScheme};
    ///
    /// let uri: CoapUri = CoapUri::new(
    ///     CoapUriScheme::Coap,
    ///     "example.com".as_bytes(),
    ///     4711,
    ///     Some("/foo/bar".as_bytes()),
    ///     Some("?answer=42".as_bytes())
    /// )?;
    ///
    /// assert_eq!(uri.scheme(), Some(CoapUriScheme::Coap));
    /// assert_eq!(uri.host(), Some("example.com".as_bytes()));
    /// assert_eq!(uri.port(), Some(4711));
    /// assert_eq!(uri.path(), Some("foo/bar".as_bytes()));
    /// assert_eq!(uri.query(), Some("answer=42".as_bytes()));
    /// assert!(!uri.is_proxy());
    ///
    /// # Result::<(), UriParsingError>::Ok(())
    /// ```
    pub fn new(
        scheme: CoapUriScheme,
        host: &[u8],
        port: u16,
        path: Option<&[u8]>,
        query: Option<&[u8]>,
    ) -> Result<CoapUri, UriParsingError> {
        let (uri_str, _, _, _) =
            Self::construct_uri_string_from_parts(scheme, host, port, path.unwrap_or(&[b'/']), query.unwrap_or(&[]))?;
        // SAFETY: coap_split_uri is one of the allowed functions.
        unsafe { CoapUri::create_parsed_uri(uri_str, coap_split_uri, false) }
    }

    /// Creates a new [CoapUri] for use as a proxy URI from its constituent parts.
    ///
    /// # Errors
    /// May fail if the provided fields do not represent a valid relative URI or if the arguments
    /// exceed maximum lengths (see the struct level documentation).
    /// # Examples
    /// ```
    /// use libcoap_rs::error::UriParsingError;
    /// use libcoap_rs::types::{CoapUri, CoapUriScheme};
    ///
    /// let uri: CoapUri = CoapUri::new_proxy(
    ///     CoapUriScheme::Coap,
    ///     "example.com".as_bytes(),
    ///     4711,
    ///     Some("/foo/bar".as_bytes()),
    ///     Some("?answer=42".as_bytes())
    /// )?;
    ///
    /// assert_eq!(uri.scheme(), Some(CoapUriScheme::Coap));
    /// assert_eq!(uri.host(), Some("example.com".as_bytes()));
    /// assert_eq!(uri.port(), Some(4711));
    /// assert_eq!(uri.path(), Some("foo/bar".as_bytes()));
    /// assert_eq!(uri.query(), Some("answer=42".as_bytes()));
    /// assert!(uri.is_proxy());
    ///
    /// # Result::<(), UriParsingError>::Ok(())
    /// ```
    pub fn new_proxy(
        scheme: CoapUriScheme,
        host: &[u8],
        port: u16,
        path: Option<&[u8]>,
        query: Option<&[u8]>,
    ) -> Result<CoapUri, UriParsingError> {
        let (uri_str, _, _, _) =
            Self::construct_uri_string_from_parts(scheme, host, port, path.unwrap_or(&[b'/']), query.unwrap_or(&[]))?;
        // SAFETY: coap_split_proxy_uri is one of the allowed functions.
        unsafe { CoapUri::create_parsed_uri(uri_str, coap_split_proxy_uri, true) }
    }

    /// Attempts to convert the provided `path` and `query` into a relative [CoapUri] suitable as a
    /// request/location URI.
    ///
    /// # Errors
    /// May fail if the provided `path` and `query` do not represent a valid relative URI or if the
    /// arguments exceed maximum lengths (see the struct level documentation).
    ///
    /// # Examples
    /// ```
    /// use libcoap_rs::error::UriParsingError;
    /// use libcoap_rs::types::{CoapUri, CoapUriScheme};
    ///
    /// let uri: CoapUri = CoapUri::new_relative(
    ///     Some("/foo/bar".as_bytes()),
    ///     Some("?answer=42".as_bytes())
    /// )?;
    ///
    /// assert_eq!(uri.scheme(), None);
    /// assert_eq!(uri.host(), None);
    /// assert_eq!(uri.port(), Some(5683));
    /// assert_eq!(uri.path(), Some("foo/bar".as_bytes()));
    /// assert_eq!(uri.query(), Some("answer=42".as_bytes()));
    /// assert!(!uri.is_proxy());
    ///
    /// # Result::<(), UriParsingError>::Ok(())
    /// ```
    pub fn new_relative(path: Option<&[u8]>, query: Option<&[u8]>) -> Result<CoapUri, UriParsingError> {
        CoapUri::new(CoapUriScheme::Coap, &[], 0, path, query)
    }

    /// Attempts to convert the provided `uri_str` into a [CoapUri] suitable as a request/location
    /// URI.
    ///
    /// # Errors
    /// May fail if the provided `uri_str` is not a valid URI or if the URI components exceed
    /// maximum lengths (see the struct level documentation).
    ///
    /// # Examples
    /// ```
    /// use libcoap_rs::error::UriParsingError;
    /// use libcoap_rs::types::{CoapUri, CoapUriScheme};
    ///
    /// let uri: CoapUri = CoapUri::try_from_str("coap://example.com:4711/foo/bar?answer=42")?;
    ///
    /// assert_eq!(uri.scheme(), Some(CoapUriScheme::Coap));
    /// assert_eq!(uri.host(), Some("example.com".as_bytes()));
    /// assert_eq!(uri.port(), Some(4711));
    /// assert_eq!(uri.path(), Some("foo/bar".as_bytes()));
    /// assert_eq!(uri.query(), Some("answer=42".as_bytes()));
    /// assert!(!uri.is_proxy());
    ///
    /// # Result::<(), UriParsingError>::Ok(())
    /// ```
    pub fn try_from_str(uri_str: &str) -> Result<CoapUri, UriParsingError> {
        // SAFETY: coap_split_uri is one of the allowed functions.
        unsafe { CoapUri::create_parsed_uri(CString::new(uri_str)?, coap_split_uri, false) }
    }

    /// Attempts to convert the provided `uri_str` into a [CoapUri] suitable as a proxy URI.
    ///
    /// # Errors
    /// May fail if the provided `uri_str` is not a valid proxy URI or if the URI components exceed
    /// maximum lengths (see the struct level documentation).
    ///
    /// # Examples
    /// ```
    /// use libcoap_rs::error::UriParsingError;
    /// use libcoap_rs::types::{CoapUri, CoapUriScheme};
    ///
    /// let uri: CoapUri = CoapUri::try_from_str_proxy("coap://example.com:4711/foo/bar?answer=42")?;
    ///
    /// assert_eq!(uri.scheme(), Some(CoapUriScheme::Coap));
    /// assert_eq!(uri.host(), Some("example.com".as_bytes()));
    /// assert_eq!(uri.port(), Some(4711));
    /// assert_eq!(uri.path(), Some("foo/bar".as_bytes()));
    /// assert_eq!(uri.query(), Some("answer=42".as_bytes()));
    /// assert!(uri.is_proxy());
    ///
    /// # Result::<(), UriParsingError>::Ok(())
    /// ```
    pub fn try_from_str_proxy(uri_str: &str) -> Result<CoapUri, UriParsingError> {
        // SAFETY: coap_split_proxy_uri is one of the allowed functions.
        unsafe { CoapUri::create_parsed_uri(CString::new(uri_str)?, coap_split_proxy_uri, true) }
    }

    /// Attempts to convert a [Url] into a [CoapUri].
    ///
    /// # Errors
    /// May fail if the provided Url is not a valid URI supported by libcoap or if the URI
    /// components exceed maximum lengths (see the struct level documentation).
    #[cfg(feature = "url")]
    pub fn try_from_url(url: &Url) -> Result<CoapUri, UriParsingError> {
        Self::try_from_str(url.as_str())
    }

    /// Attempts to convert a [Url] into a proxy [CoapUri].
    ///
    /// # Errors
    /// May fail if the provided Url is not a valid proxy URI supported by libcoap or if the URI
    /// components exceed maximum lengths (see the struct level documentation).
    #[cfg(feature = "url")]
    pub fn try_from_url_proxy(url: &Url) -> Result<CoapUri, UriParsingError> {
        Self::try_from_str_proxy(url.as_str())
    }

    /// Returns the scheme part of this URI.
    pub fn scheme(&self) -> Option<CoapUriScheme> {
        // URIs can either be absolute or relative. If they are relative, the scheme is also not
        // set (but defaults to CoAP as the default enum value is 0).
        self.host()?;
        Some(CoapUriScheme::from_raw_scheme(self.raw_uri.scheme))
    }

    /// Returns the host part of this URI.
    pub fn host(&self) -> Option<&[u8]> {
        let raw_str = self.raw_uri.host;
        if raw_str.length == 0 {
            return None;
        }
        // SAFETY: After construction the fields of self.raw_uri always reference the corresponding
        //         parts of the underlying string, which is pinned. Therefore, the pointer and
        //         length are valid for the lifetime of this struct.
        Some(unsafe { std::slice::from_raw_parts(raw_str.s, raw_str.length) })
    }

    /// Returns the port of this URI (if provided).
    pub fn port(&self) -> Option<UriPort> {
        match self.raw_uri.port {
            0 => None,
            v => Some(v),
        }
    }

    /// Returns the URI path part of this URI.
    pub fn path(&self) -> Option<&[u8]> {
        let raw_str = self.raw_uri.path;
        if raw_str.s.is_null() {
            return None;
        }
        // SAFETY: After construction the fields of self.raw_uri always reference the corresponding
        //         parts of the underlying string, which is pinned. Therefore, the pointer and
        //         length are valid for the lifetime of this struct.
        Some(unsafe { std::slice::from_raw_parts(raw_str.s, raw_str.length) })
    }

    /// Returns the host part of this URI.
    pub fn query(&self) -> Option<&[u8]> {
        let raw_str = self.raw_uri.query;
        if raw_str.s.is_null() {
            return None;
        }
        // SAFETY: After construction the fields of self.raw_uri always reference the corresponding
        //         parts of the underlying string, which is pinned. Therefore, the pointer and
        //         length are valid for the lifetime of this struct.
        Some(unsafe { std::slice::from_raw_parts(raw_str.s, raw_str.length) })
    }

    /// Returns whether this URI is a proxy URI.
    pub fn is_proxy(&self) -> bool {
        self.is_proxy
    }

    /// Converts the given URI into a `Vec` of [CoapOption]s that can be added to a
    /// [crate::message::CoapMessage].
    pub fn into_options(self) -> Vec<CoapOption> {
        // TODO this is a lot of copying around, however, fixing that would require an entire
        //      rewrite of the option handling code, so it's better kept for a separate PR.

        let mut optlist = std::ptr::null_mut();
        // SAFETY: self.raw_uri is always valid after construction. The destination may be a null
        //         pointer, optlist may be a null pointer at the start (it will be set to a valid
        //         pointer by this call). Buf and create_port_host_opt are set according to the
        //         libcoap documentation.
        if unsafe { coap_uri_into_optlist(&self.raw_uri, std::ptr::null(), &mut optlist, 1) } < 0 {
            // We have already parsed this URI. If converting it into options fails, something went
            // terribly wrong.
            panic!("could not convert valid coap URI into options");
        }
        let mut out_opts = Vec::new();
        while !optlist.is_null() {
            // SAFETY: coap_uri_into_options should have ensured that optlist is either null or a
            //         valid coap option list. In the former case, we wouldn't be in this loop, in
            //         the latter case calling from_optlist_entry is fine.
            out_opts.push(unsafe {
                CoapOption::from_optlist_entry(optlist.as_ref().expect("self-generated options should always be valid"))
                    .expect("self-generated options should always be valid")
            });
            optlist = unsafe { *optlist }.next;
        }
        // SAFETY: optlist has been set by coap_uri_into_options, which has not returned an error.
        unsafe {
            coap_delete_optlist(optlist);
        }
        drop(self);
        out_opts
    }

    /// Provides a reference to the raw [coap_uri_t] struct represented by this [CoapUri].
    ///
    /// Note that while obtaining this struct and reading the fields is safe (which is why this
    /// method is safe), modifying the referenced URI parts by (unsafely) dereferencing and mutating
    /// the `const` pointers inside is not.
    pub fn as_raw_uri(&self) -> &coap_uri_t {
        &self.raw_uri
    }

    /// Converts the given `raw_uri` to a new [CoapUri] instance.
    ///
    /// This method will create a copy of the provided URI, i.e. `raw_uri` will remain valid and not
    /// be owned by the created [CoapUri] instance.
    ///
    /// # Safety
    ///
    /// The provided `raw_uri` must point to a valid instance of [coap_uri_t].
    /// In particular, the provided pointers for the URI components must also be valid.
    ///
    /// # Panics
    ///
    /// Panics if the provided `raw_uri` is null or the provided URI contains a null byte.
    pub unsafe fn from_raw_uri(raw_uri: *const coap_uri_t, is_proxy: bool) -> CoapUri {
        // Loosely based on coap_clone_uri.
        assert!(!raw_uri.is_null());
        let host_slice = (*raw_uri)
            .host
            .s
            .is_null()
            .then_some(&[] as &[u8])
            .unwrap_or_else(|| std::slice::from_raw_parts((*raw_uri).host.s, (*raw_uri).host.length));
        let path_slice = (*raw_uri)
            .path
            .s
            .is_null()
            .then_some(&[] as &[u8])
            .unwrap_or_else(|| std::slice::from_raw_parts((*raw_uri).path.s, (*raw_uri).path.length));
        let query_slice = (*raw_uri)
            .query
            .s
            .is_null()
            .then_some(&[] as &[u8])
            .unwrap_or_else(|| std::slice::from_raw_parts((*raw_uri).query.s, (*raw_uri).query.length));
        // Clone the actual URI string.
        let (uri_str_copy, host_pos, path_pos, query_pos) = Self::construct_uri_string_from_parts(
            CoapUriScheme::from_raw_scheme((*raw_uri).scheme),
            host_slice,
            (*raw_uri).port,
            path_slice,
            query_slice,
        )
        .expect("provided raw URI is invalid");

        let mut result = CoapUri::create_unparsed_uri(
            CString::new(uri_str_copy).expect("provided raw_uri contains null bytes!"),
            is_proxy,
        );
        result.raw_uri.port = (*raw_uri).port;
        result.raw_uri.scheme = (*raw_uri).scheme;
        // Now, _after_ the uri_str is pinned, we can set the new object's raw_uri string fields.
        result.raw_uri.host = coap_str_const_t {
            length: (*raw_uri).host.length,
            s: result.uri_str.0.as_bytes_with_nul()[host_pos..host_pos + 1].as_ptr(),
        };
        result.raw_uri.path = coap_str_const_t {
            length: (*raw_uri).path.length,
            s: result.uri_str.0.as_bytes_with_nul()[path_pos..path_pos + 1].as_ptr(),
        };
        result.raw_uri.query = coap_str_const_t {
            length: (*raw_uri).query.length,
            s: result.uri_str.0.as_bytes_with_nul()[query_pos..query_pos + 1].as_ptr(),
        };

        result
    }

    /// Create an instance of [CoapUri] with the given `uri_str`, but don't parse the value, i.e.
    /// the resulting `raw_uri` is not set correctly.
    fn create_unparsed_uri(uri_str: CString, is_proxy: bool) -> Self {
        let uri_str = Box::pin(CoapUriInner(uri_str, PhantomPinned));
        CoapUri {
            raw_uri: coap_uri_t {
                host: coap_str_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
                port: 0,
                path: coap_str_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
                query: coap_str_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
                scheme: coap_uri_scheme_t_COAP_URI_SCHEME_COAP,
            },
            uri_str,
            is_proxy,
        }
    }

    /// Create and parse a URI from a CString.
    ///
    /// # Safety
    ///
    /// parsing_fn must be either coap_split_uri or coap_split_proxy_uri.
    unsafe fn create_parsed_uri(
        uri_str: CString,
        parsing_fn: unsafe extern "C" fn(*const u8, usize, *mut coap_uri_t) -> c_int,
        is_proxy: bool,
    ) -> Result<CoapUri, UriParsingError> {
        ensure_coap_started();
        let mut uri = Self::create_unparsed_uri(uri_str, is_proxy);

        // SAFETY: The provided pointers to raw_uri and uri_str are valid.
        // Because uri_str is pinned (and its type is not Unpin), the pointer locations are always
        // valid while this object lives, therefore the resulting coap_uri_t remains valid for the
        // entire lifetime of this object too.
        if unsafe {
            parsing_fn(
                uri.uri_str.0.as_ptr() as *const u8,
                CStr::from_ptr(uri.uri_str.0.as_ptr()).count_bytes(),
                std::ptr::from_mut(&mut uri.raw_uri),
            )
        } < 0
        {
            return Err(UriParsingError::Unknown);
        }
        Ok(uri)
    }

    /// Constructs a CString representing the given URI parts in a form parsable by libcoap.
    fn construct_uri_string_from_parts(
        scheme: CoapUriScheme,
        host: &[u8],
        port: u16,
        path: &[u8],
        query: &[u8],
    ) -> Result<(CString, usize, usize, usize), UriParsingError> {
        // Reconstruct string for scheme.
        let scheme = if !host.is_empty() {
            format!("{}://", scheme)
        } else {
            String::new()
        };
        let port = if port != 0 { format!(":{}", port) } else { String::new() };
        let parts = [scheme.as_bytes(), host, port.as_bytes(), path, query];
        let uri_str_len = parts.iter().map(|v| v.len()).sum::<usize>();

        let mut uri_str_copy = vec![0u8; uri_str_len];
        let mut cur;
        let mut rest = uri_str_copy.as_mut_slice();
        for part in parts.iter() {
            (cur, rest) = rest.split_at_mut(part.len());
            cur.clone_from_slice(part)
        }

        // The host is index 1 in the parts list
        let host_pos = parts[..1].iter().map(|v| v.len()).sum();
        // The path is index 3 in the parts list
        let path_pos = parts[..3].iter().map(|v| v.len()).sum();
        // The query is index 4 in the parts list
        let query_pos = parts[..4].iter().map(|v| v.len()).sum();

        CString::new(uri_str_copy)
            .map(|v| (v, host_pos, path_pos, query_pos))
            .map_err(UriParsingError::from)
    }
}

impl PartialEq for CoapUri {
    fn eq(&self, other: &Self) -> bool {
        self.raw_uri.port == other.raw_uri.port
            && self.raw_uri.scheme == other.raw_uri.scheme
            // SAFETY: After construction the fields of self.raw_uri always reference the
            //         corresponding parts of the underlying string, which is pinned. Therefore, the
            //         pointer and length are valid for the lifetime of this struct.
            && unsafe {
            coap_string_equal!(&self.raw_uri.host, &other.raw_uri.host)
                && coap_string_equal!(&self.raw_uri.path, &other.raw_uri.path)
                && coap_string_equal!(&self.raw_uri.query, &other.raw_uri.query)
        }
    }
}

impl Eq for CoapUri {}

impl Clone for CoapUri {
    fn clone(&self) -> Self {
        // SAFETY: raw_uri is a valid pointer to a coap_uri_t (by construction of this type and
        // contract of from_raw_uri)
        unsafe { CoapUri::from_raw_uri(&self.raw_uri, self.is_proxy) }
    }
}

#[cfg(feature = "url")]
impl TryFrom<&Url> for CoapUri {
    type Error = UriParsingError;

    fn try_from(value: &Url) -> Result<Self, Self::Error> {
        CoapUri::try_from_url(value)
    }
}

impl FromStr for CoapUri {
    type Err = UriParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s)
    }
}

impl Display for CoapUri {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.uri_str.fmt(f)
    }
}

/// Transport protocols that can be used with libcoap.
#[repr(u32)]
#[non_exhaustive]
#[derive(Copy, Clone, FromPrimitive, PartialEq, Eq, Hash)]
pub enum CoapProtocol {
    None = coap_proto_t_COAP_PROTO_NONE as u32,
    Udp = coap_proto_t_COAP_PROTO_UDP as u32,
    Dtls = coap_proto_t_COAP_PROTO_DTLS as u32,
    Tcp = coap_proto_t_COAP_PROTO_TCP as u32,
    Tls = coap_proto_t_COAP_PROTO_TLS as u32,
}

impl CoapProtocol {
    pub fn is_secure(&self) -> bool {
        match self {
            CoapProtocol::None | CoapProtocol::Udp | CoapProtocol::Tcp => false,
            CoapProtocol::Dtls | CoapProtocol::Tls => true,
        }
    }
}

#[doc(hidden)]
impl From<coap_proto_t> for CoapProtocol {
    fn from(raw_proto: coap_proto_t) -> Self {
        <CoapProtocol as FromPrimitive>::from_u32(raw_proto as u32).expect("unknown protocol")
    }
}

impl Display for CoapProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CoapProtocol::None => "none",
            CoapProtocol::Udp => "udp",
            CoapProtocol::Dtls => "dtls",
            CoapProtocol::Tcp => "tcp",
            CoapProtocol::Tls => "tls",
        })
    }
}

fn convert_to_fixed_size_slice(n: usize, val: &[u8]) -> Box<[u8]> {
    if val.len() > n {
        panic!("supplied slice too short");
    }
    let mut buffer: Vec<u8> = vec![0; n];
    let (_, target_buffer) = buffer.split_at_mut(n - val.len());
    target_buffer.copy_from_slice(val);
    buffer.truncate(n);
    buffer.into_boxed_slice()
}

// TODO the following functions should probably return a result and use generics.
pub(crate) fn decode_var_len_u32(val: &[u8]) -> u32 {
    u32::from_be_bytes(
        convert_to_fixed_size_slice(4, val)[..4]
            .try_into()
            .expect("could not convert from variable sized value to fixed size number as the lengths don't match"),
    )
}

pub(crate) fn encode_var_len_u32(val: u32) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

// Kept for consistency
#[allow(unused)]
pub(crate) fn decode_var_len_u64(val: &[u8]) -> u64 {
    u64::from_be_bytes(
        convert_to_fixed_size_slice(8, val)[..8]
            .try_into()
            .expect("could not convert from variable sized value to fixed size number as the lengths don't match"),
    )
}

// Kept for consistency
#[allow(unused)]
pub(crate) fn encode_var_len_u64(val: u64) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub(crate) fn decode_var_len_u16(val: &[u8]) -> u16 {
    u16::from_be_bytes(
        convert_to_fixed_size_slice(2, val)[..2]
            .try_into()
            .expect("could not convert from variable sized value to fixed size number as the lengths don't match"),
    )
}

pub(crate) fn encode_var_len_u16(val: u16) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub(crate) fn decode_var_len_u8(val: &[u8]) -> u16 {
    u16::from_be_bytes(
        convert_to_fixed_size_slice(1, val)[..1]
            .try_into()
            .expect("could not convert from variable sized value to fixed size number as the lengths don't match"),
    )
}

pub(crate) fn encode_var_len_u8(val: u8) -> Box<[u8]> {
    Vec::from([val]).into_boxed_slice()
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * lib.rs - Main library entry point for raw libcoap bindings.
 * This file is part of the libcoap-sys crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Auto-generated unsafe bindings to [libcoap](https://github.com/obgm/libcoap), generated using
//! [bindgen](https://crates.io/crates/bindgen).
//!
//! This crate allows direct (but unsafe) usage of the libcoap C library from Rust. The declarations
//! made in this library are generated automatically using bindgen, for further documentation on how
//! to use them, refer to the [libcoap documentation](https://libcoap.net/documentation.html).
//!
//! In most cases you probably want to use the safe wrapper provided by the libcoap crate (or
//! another coap library written in pure rust such as [coap-rs](https://github.com/covertness/coap-rs))
//! instead.
//!
//! Cargo Features
//! --------------
//! We currently define a number of features that affect the functionality provided by this wrapper
//! and required by the linked libcoap library.
//!
//! Features affecting functionality:
//! - `dtls`: Enable usage of DTLS for transport security. Supports a number of different backends.
//!
//!   Note that while not specified here due to limitations in Cargo's syntax, the DTLS feature
//!   depends on one of the DTLS backends being enabled, and failing to enable a DTLS backend will
//!   result in a build failure.
//!   
//!   If you are developing a library based on libcoap-sys and do not care about the DTLS backend,
//!   enable the dtls feature and let the user decide on the backend to use, either by
//!   re-exporting these features (see [the Cargo Book](https://doc.rust-lang.org/cargo/reference/features.html#dependency-features))
//!   or by assuming that the user will use libcoap-sys as a dependency and enable the
//!   corresponding backend feature themselves, relying on Cargo's feature unification to enable
//!   it for your crate as well.
//!   
//!   Also note that the backends are **mutually exclusive** due to the C library having these
//!   backends as mutually exclusive features. If multiple backends are enabled (e.g. because
//!   multiple dependencies use libcoap-sys and use different backends), we select one based on
//!   the auto-detection order specified in [the libcoap configure script](https://github.com/obgm/libcoap/blob/develop/configure.ac#L494)
//!   (gnutls > openssl > mbedtls > tinydtls).
//!   - `dtls_backend_(openssl|gnutls|mbedtls|tinydtls)`: Enable the corresponding DTLS backend.
//!      
//!      Note that enabling the OpenSSL, GnuTLS, TinyDTLS or MbedTLS backend will also require the
//!      appropriate library to be available (hence the dependency on the corresponding sys-crate).
//!      The TinyDTLS backend is built using a vendored (and statically linked) version of TinyDTLS
//!      by default, see the tinydtls-sys crate for more info.
//!      Choosing a DTLS backend also means that the license terms of these libraries may apply to
//!      you. See the relevant parts of the [libcoap license file](https://github.com/obgm/libcoap/blob/develop/LICENSE)
//!      for more information.
//! - `tcp` (default): Enable CoAP over TCP support
//! - `async` (default): Enable async functionality.
//!   
//!   Note that this async functionality is not translated to Rust's async language functionality,
//!   but instead adds functionality to the underlying C library to allow for making asynchronous
//!   requests (i.e. function calls that return before the response has arrived).
//!
//!   Integrating libcoap into Rusts async language features is out of scope for this crate, but
//!   might be implemented later on in the libcoap (safe abstraction) crate.
//! - `server` (default): Enable code related to server functionality
//! - `client` (default): Enable code related to client functionality
//! - `epoll` (default): Allow the underlying C library to perform IO operations using epoll.
//!
//! Other features:
//! - `vendored` (default): Use a vendored version of libcoap instead of the system-provided one.
//!   Note that `vendored` implies `static`.
//! - `static` (default): Perform static linking to the libcoap C library.
//!
//! ### Note on features affecting functionality
//! The features that add or remove functionality do not change the generated bindings as libcoap's
//! headers (unlike the source files themselves) are not affected by the corresponding `#define`s.
//!
//! For library users that link to a shared version of libcoap, this means that the feature flags
//! do not have any effect and the supported features will correspond directly to the features
//! enabled during the build of the shared libcoap instance (using the configure-script).
//!
//! For users of the vendored version of libcoap (see the `vendored` feature), the supported
//! features of the vendored libcoap will be set to match the cargo features during build.

// Bindgen translates the C headers, clippy's and rustfmt's recommendations are not applicable here.
#![allow(clippy::all)]
#![allow(non_camel_case_types)]
#![allow(deref_nullptr)]
#![allow(non_snake_case)]

use std::ffi::c_void;

#[allow(unused_imports)]
#[cfg(not(target_os = "espidf"))]
use libc::epoll_event;
#[allow(unused_imports)]
use libc::{fd_set, memcmp, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, socklen_t, time_t};
// use dtls backend libraries in cases where they set our linker flags, otherwise cargo will
// optimize them out.
#[allow(unused_imports)]
#[cfg(feature = "dtls_backend_mbedtls_vendored")]
use mbedtls_sys as _;
#[allow(unused_imports)]
#[cfg(feature = "dtls_backend_openssl")]
use openssl_sys as _;
#[allow(unused_imports)]
#[cfg(feature = "dtls_backend_tinydtls")]
use tinydtls_sys as _;

#[cfg(target_family = "windows")]
include!(concat!(env!("OUT_DIR"), "\\bindings.rs"));
#[cfg(not(target_family = "windows"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[inline]
#[cfg(not(non_inlined_coap_send_rst))]
pub unsafe fn coap_send_rst(session: *mut coap_session_t, request: *const coap_pdu_t) -> coap_mid_t {
    coap_send_message_type(session, request, crate::coap_pdu_type_t::COAP_MESSAGE_RST)
}

/// Compares instances of coap_str_const_t and/or coap_string_t.
///
/// This macro is a reimplementation of the macro defined in coap_str.h, see
/// <https://libcoap.net/doc/reference/develop/group__string.html#ga7f43c10b486dc6d45c37fcaf987d711b>.
#[macro_export]
macro_rules! coap_string_equal {
    ( $string1:expr, $string2:expr ) => {{
        use libcoap_sys::coap_string_equal_internal;
        let s1 = $string1;
        let s2 = $string2;
        coap_string_equal_internal((*s1).s, (*s1).length, (*s2).s, (*s2).length)
    }};
}

/// Internal only function for CoAP string comparisons.
///
/// *DO NOT USE THIS FUNCTION DIRECTLY.* It is only public because it is used by the
/// [coap_string_equal] macro, which is the function you probably wanted to call instead.
///
/// # Safety
///
/// This function should not be called directly, use [coap_string_equal] instead.
pub unsafe fn coap_string_equal_internal(
    str1_ptr: *const u8,
    str1_len: usize,
    str2_ptr: *const u8,
    str2_len: usize,
) -> bool {
    str1_len == str2_len
        && (str1_len == 0
            || !str1_ptr.is_null()
                && !str2_ptr.is_null()
                && memcmp(str1_ptr as *const c_void, str2_ptr as *const c_void, str1_len) == 0)
}

/// Initialize the CoAP library and additionally perform runtime checks to ensure that required
/// features (as enabled in `Cargo.toml`) are available.
///
/// You *should* prefer using this function over [coap_startup], as without calling this function
/// some of the features enabled using the Cargo features may not actually be available.
/// (NOTE: However, see the below section on safety).
///
/// Either this function or [coap_startup] must be run once before any libcoap function is called.
///
/// If you are absolutely 100% certain that all features you require are always available (or are
/// prepared to deal with error return values/different behavior on your own if they aren't), you
/// may use [coap_startup] instead.
///
/// # SAFETY WARNING
/// In order to preserve backwards compatibility, this method may (for now) skip the feature checks
/// altogether if they aren't provided by libcoap (which may be the case for libcoap < 4.3.5rc3).
///
/// If you want to be absolutely certain that a given feature is available, you *must* also check
/// the libcoap version to ensure that it is at least 4.3.5rc3.
///
/// This behavior will be changed as soon as libcoap 4.3.5 is released, after which libcoap 4.3.5
/// will become the minimum supported version and these checks will be mandatory.
pub fn coap_startup_with_feature_checks() {
    // only compile checks if they are available for the given libcoap version.
    #[cfg(feature_checks_available)]
    {
        #[cfg(feature = "af-unix")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_af_unix_is_supported() != 1 } {
            panic!("Required feature \"af-unix\" is not supported by libcoap")
        }
        #[cfg(feature = "async")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_async_is_supported() != 1 } {
            panic!("Required feature \"async\" is not supported by libcoap")
        }
        #[cfg(feature = "client")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_client_is_supported() != 1 } {
            panic!("Required feature \"ipv4\" is not supported by libcoap")
        }
        #[cfg(feature = "dtls")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_dtls_is_supported() != 1 } {
            panic!("Required feature \"dtls\" is not supported by libcoap")
        }
        #[cfg(feature = "dtls-cid")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_dtls_cid_is_supported() != 1 } {
            panic!("Required feature \"dtls-cid\" is not supported by libcoap")
        }
        #[cfg(feature = "dtls-psk")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_dtls_psk_is_supported() != 1 } {
            panic!("Required feature \"dtls-psk\" is not supported by libcoap")
        }
        #[cfg(feature = "dtls-pki")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_dtls_pki_is_supported() != 1 } {
            panic!("Required feature \"dtls-pki\" is not supported by libcoap")
        }
        #[cfg(feature = "dtls-pkcs11")]
        // SAFETY: Function is always safe to call.
        if !unsafe { coap_dtls_pkcs11_is_supported() == 1 } {
            panic!("Required feature \"dtls-pkcs11\" is not supported by libcoap")
        }
        #[cfg(feature = "dtls-rpk")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_dtls_rpk_is_supported() != 1 } {
            panic!("Required feature \"dtls-rpk\" is not supported by libcoap")
        }
        #[cfg(feature = "epoll")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_epoll_is_supported() != 1 } {
            panic!("Required feature \"epoll\" is not supported by libcoap")
        }
        #[cfg(feature = "ipv4")]
        // SAFETY: Function is always safe to call.
        if !unsafe { coap_ipv4_is_supported() == 1 } {
            panic!("Required feature \"ipv4\" is not supported by libcoap")
        }
        #[cfg(feature = "ipv6")]
        // SAFETY: Function is always safe to call.
        if !unsafe { coap_ipv6_is_supported() == 1 } {
            panic!("Required feature \"ipv6\" is not supported by libcoap")
        }
        #[cfg(feature = "observe-persist")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_observe_persist_is_supported() != 1 } {
            panic!("Required feature \"ipv4\" is not supported by libcoap")
        }
        #[cfg(feature = "oscore")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_oscore_is_supported() != 1 } {
            panic!("Required feature \"oscore\" is not supported by libcoap")
        }
        #[cfg(feature = "q-block")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_q_block_is_supported() != 1 } {
            panic!("Required feature \"q-block\" is not supported by libcoap")
        }
        #[cfg(feature = "server")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_server_is_supported() != 1 } {
            panic!("Required feature \"ipv4\" is not supported by libcoap")
        }
        #[cfg(feature = "tcp")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_tcp_is_supported() != 1 } {
            panic!("Required feature \"tcp\" is not supported by libcoap")
        }
        #[cfg(feature = "thread-safe")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_threadsafe_is_supported() != 1 } {
            panic!("Required feature \"thread-safe\" is not supported by libcoap")
        }
        #[cfg(feature = "tls")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_tls_is_supported() != 1 } {
            panic!("Required feature \"tls\" is not supported by libcoap")
        }
        #[cfg(feature = "websockets")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_ws_is_supported() != 1 } {
            panic!("Required feature \"websockets\" is not supported by libcoap")
        }
        #[cfg(feature = "secure-websockets")]
        // SAFETY: Function is always safe to call.
        if unsafe { coap_wss_is_supported() != 1 } {
            panic!("Required feature \"websockets\" is not supported by libcoap")
        }
    }
    #[cfg(feature_checks_available)]
    {
        println!("WARNING: coap_startup_with_feature_checks() could not assert the availability of features because the linked version of libcoap is too old (< 4.3.5rc3)!")
    }
    // SAFETY: Function is always safe to call.
    unsafe { coap_startup() }
}

#[cfg(all(test, not(target_os = "espidf")))]
mod tests {
    use std::{
        ffi::c_void,
        net::{SocketAddr, UdpSocket},
        os::raw::c_int,
        sync::{Arc, Barrier},
    };

    use libc::{in6_addr, in_addr, sa_family_t, size_t, AF_INET, AF_INET6};

    use crate::{
        coap_pdu_code_t::{COAP_REQUEST_CODE_GET, COAP_RESPONSE_CODE_CONTENT},
        coap_proto_t::COAP_PROTO_UDP,
        coap_request_t::COAP_REQUEST_GET,
        coap_response_t::COAP_RESPONSE_OK,
    };

    use super::*;

    const COAP_TEST_RESOURCE_URI: &str = "test";
    const COAP_TEST_RESOURCE_RESPONSE: &str = "Hello World!";

    /// Creates a coap_address_t from a &SocketAddr.
    fn coap_address_from_socketaddr(addr: &SocketAddr) -> coap_address_t {
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
                    coap_addr
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
                    coap_addr
                }
            },
        }
    }

    /// Response handler for the CoAP client/server test (client-side)
    /// # Safety
    /// Assumes all pointers to be valid and pointing to data structures containing valid data
    /// according to the specification of the method handler function provided in libcoap.
    /// Assumes that the application data in the CoAP context associated with the session is a
    /// pointer to a boolean specifying whether a successful request was received (will be set to
    /// true by this function).
    unsafe extern "C" fn test_resource_handler(
        _resource: *mut coap_resource_t,
        session: *mut coap_session_t,
        _incoming_pdu: *const coap_pdu_t,
        _query: *const coap_string_t,
        response_pdu: *mut coap_pdu_t,
    ) {
        let mut buf: [u8; 3] = [0; 3];
        coap_add_option(
            response_pdu,
            COAP_OPTION_CONTENT_TYPE as coap_option_num_t,
            coap_encode_var_safe(buf.as_mut_ptr(), buf.len(), COAP_MEDIATYPE_TEXT_PLAIN) as usize,
            buf.as_ptr(),
        );
        coap_add_data(
            response_pdu,
            COAP_TEST_RESOURCE_RESPONSE.len(),
            COAP_TEST_RESOURCE_RESPONSE.as_ptr(),
        );
        coap_set_app_data(coap_session_get_context(session), (&true) as *const bool as *mut c_void);
        coap_pdu_set_code(response_pdu, COAP_RESPONSE_CODE_CONTENT);
    }

    /// Response handler for the CoAP client/server test (client-side)
    /// # Safety
    /// Assumes all pointers to be valid and pointing to data structures containing valid data
    /// according to the specification of the response handler function provided in libcoap.
    /// Assumes that the application data in the CoAP context associated with the session is a
    /// pointer to a boolean specifying whether a successful response was received (will be set to
    /// true by this function).
    unsafe extern "C" fn test_response_handler(
        session: *mut coap_session_t,
        _sent: *const coap_pdu_t,
        received: *const coap_pdu_t,
        _mid: coap_mid_t,
    ) -> coap_response_t {
        assert_eq!(coap_pdu_get_code(received), COAP_RESPONSE_CODE_CONTENT);
        let mut len: size_t = 0;
        let mut data: *const u8 = std::ptr::null();
        assert_ne!(coap_get_data(received, &mut len, &mut data), 0);
        let data = std::slice::from_raw_parts(data, len);

        assert_eq!(data, COAP_TEST_RESOURCE_RESPONSE.as_bytes());
        coap_set_app_data(coap_session_get_context(session), (&true) as *const bool as *mut c_void);
        return COAP_RESPONSE_OK;
    }

    /// Creates a CoAP server that provides a single resource under COAP_TEST_RESOURCE_URI over the
    /// supplied socket
    fn run_coap_test_server(addr: &SocketAddr, barrier: Arc<Barrier>) {
        // SAFETY: Null pointer is a valid parameter here.
        let context = unsafe { coap_new_context(std::ptr::null()) };
        assert!(!context.is_null());

        let address: coap_address_t = coap_address_from_socketaddr(addr);

        // SAFETY: We asserted that context != null, listen_addr is a reference and can therefore not be null.
        let endpoint = unsafe { coap_new_endpoint(context, &address, coap_proto_t::COAP_PROTO_UDP) };
        assert!(!endpoint.is_null());

        // SAFETY: Since we use a string constant here, the arguments to the function are all valid.
        let uri = unsafe { coap_new_str_const(COAP_TEST_RESOURCE_URI.as_ptr(), COAP_TEST_RESOURCE_URI.len()) };
        assert!(!uri.is_null());

        // SAFETY: We just asserted that uri is valid, COAP_RESOURCE_FLAGS_RELEASE_URI is valid because we will not free the uri ourselves.
        let test_resource = unsafe { coap_resource_init(uri, COAP_RESOURCE_FLAGS_RELEASE_URI as c_int) };
        assert!(!test_resource.is_null());

        // SAFETY: We asserted that test_resource and context are valid, other pointers are always valid.
        // The fact that we cast a constant to a mutable pointer is not problematic, because neither we
        // nor libcoap ever mutate the pointer. This is necessary, because the underlying libcoap
        // struct allows for mutable pointers to be set there, so that applications can use this to
        // modify some application specific state.
        unsafe {
            coap_register_request_handler(test_resource, COAP_REQUEST_GET, Some(test_resource_handler));
            coap_add_resource(context, test_resource);
            coap_set_app_data(context, (&false) as *const bool as *mut c_void);
        }

        barrier.wait();
        loop {
            let time_spent_millis = unsafe { coap_io_process(context, 10000) };
            // SAFETY: We are the only ones setting or accessing this value, so we know it is a
            // const bool pointer (we have also set it to *false before and only ever set it to
            // *true afterwards).
            if unsafe { *(coap_get_app_data(context) as *const bool).as_ref().unwrap() } {
                break;
            }
            if time_spent_millis == -1 || time_spent_millis >= 10000 {
                panic!("Test timeout exceeded");
            }
        }
        // SAFETY: Context is not referenced outside this function, and handlers (which get the
        // context from libcoap) will not be called after the context is freed.
        // This also seems to free all resources.
        unsafe {
            coap_free_context(context);
        }
    }

    /// Test case that creates a basic coap server and makes a request to it from a separate context
    #[test]
    fn test_coap_client_server_basic() {
        // This will give us a SocketAddress with a port in the local port range automatically
        // assigned by the operating system.
        // Because the UdpSocket goes out of scope, the Port will be free for usage by libcoap.
        // This seems to be the only portable way to get a port number assigned from the operating
        // system, which is necessary here because of potential parallelisation (we can't just use
        // the default CoAP port if multiple tests are run in parallel).
        // It is assumed here that after unbinding the temporary socket, the OS will not reassign
        // this port until we bind it again. This should work in most cases (unless we run on a
        // system with very few free ports), because at least Linux will not reuse port numbers
        // unless necessary, see https://unix.stackexchange.com/a/132524.
        let server_address = UdpSocket::bind("localhost:0")
            .expect("Failed to bind server socket")
            .local_addr()
            .expect("Failed to get server socket address");

        let preparation_barrier = Arc::new(Barrier::new(2));

        let server_address_clone = server_address.clone();
        let preparation_barrier_clone = preparation_barrier.clone();
        let server_thread_handle =
            std::thread::spawn(move || run_coap_test_server(&server_address_clone, preparation_barrier_clone));

        // SAFETY: Null pointer is a valid parameter here.
        let context = unsafe { coap_new_context(std::ptr::null()) };
        assert!(!context.is_null());

        preparation_barrier.wait();

        let server_address = coap_address_from_socketaddr(&server_address);

        // SAFETY: null pointer is valid argument for local_if, server_address is guaranteed to be
        // a correct value (conversion cannot fail), validity of context was asserted before.
        let client_session =
            unsafe { coap_new_client_session(context, std::ptr::null(), &server_address, COAP_PROTO_UDP) };

        // SAFETY: context and client_session were asserted to be valid.
        // Casting *const to *mut is fine because we don't mutate the value pointed to and the
        // pointer is not used by libcoap (the application data pointer is intended to be used by
        // client applications to store and/or modify their own data, which is why it is a mutable
        // pointer in the first place).
        // coap_request_pdu is asserted to be valid before it is used.
        unsafe {
            coap_register_response_handler(context, Some(test_response_handler));
            coap_set_app_data(context, (&false) as *const bool as *mut c_void);
            let coap_request_pdu =
                coap_new_pdu(coap_pdu_type_t::COAP_MESSAGE_NON, COAP_REQUEST_CODE_GET, client_session);
            assert!(!coap_request_pdu.is_null());
            assert_ne!(
                coap_add_option(
                    coap_request_pdu,
                    COAP_OPTION_URI_PATH as coap_option_num_t,
                    COAP_TEST_RESOURCE_URI.len(),
                    COAP_TEST_RESOURCE_URI.as_ptr(),
                ),
                0
            );
            assert_ne!(coap_send(client_session, coap_request_pdu), COAP_INVALID_MID);
        }

        loop {
            // SAFETY: context is asserted to be valid, no known side effects that would violate any guarantees
            let time_spent_millis = unsafe { coap_io_process(context, 10000) };
            // SAFETY: We are the only ones setting or accessing this value, so we know it is a
            // const bool pointer (we have also set it to *false before and only ever set it to
            // *true afterwards).
            if unsafe { *(coap_get_app_data(context) as *const bool).as_ref().unwrap() } {
                break;
            }
            if time_spent_millis == -1 || time_spent_millis >= 10000 {
                panic!("Test timeout exceeded");
            }
        }
        // SAFETY: Context is not references outside this function, and handlers (which get the
        // context from libcoap) will not be called after the context is freed.
        // This also seems to free all resources.
        unsafe {
            coap_free_context(context);
        }
        server_thread_handle.join().expect("Error waiting for server thread");
    }
}

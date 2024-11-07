// SPDX-License-Identifier: BSD-2-Clause
/*
 * lib.rs - Main library entry point for safe libcoap bindings.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! A safe wrapper around the libcoap C library.
//!
//! This wrapper allows for safe and idiomatic usage of the libcoap C library in Rust.
//!
//! # Feature support
//! libcoap-rs currently supports the following subset of the libcoap feature set:
//! - [x] Basic CoAP client
//! - [x] Basic CoAP server
//! - [ ] Transports:
//!     - [x] UDP
//!     - [x] DTLS
//!         - [x] DTLS using PSK
//!         - [x] DTLS using PKI/RPK
//!     - [ ] TCP
//!     - [ ] TLS
//!     - [ ] OSCORE
//!     - [ ] WebSockets
//! - [ ] Blockwise Transfer
//!     - [x] Receiving large messages
//!         - Note: Handled in libcoap by setting `COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY`.
//!                 Manually constructing and managing blockwise transfers is currently not in scope
//!                 for this library.
//!     - [x] sending client-side large messages
//!     - [ ] sending server-side large messages
//! - [ ] Resource observation
//!     - [ ] Observing resources as a client
//!     - [x] Notifying observers as a server
//!
//! # Building
//! libcoap-rs can be linked to either an included version of libcoap or to a version provided by
//! the environment.
//! By default, it will use the vendored version, which can be disabled by disabling the default
//! feature `vendored`.
//!
//! In order to use DTLS, a DTLS library must be chosen, see the later section on using
//! cryptography for more information.
//!
//! Some (but not all) of the available DTLS libraries may also be vendored using the
//! `dtls_[LIBRARY]_vendored` feature.
//!
//! ## Building on the ESP32
//!
//! libcoap-rs and libcoap-sys support building for the ESP32.
//! This is done by using the version of libcoap provided by the ESP-IDF as a managed component
//! and generating bindings for it.
//!
//! In order to build for the ESP, ensure that the following preconditions are met:
//!
//! - The version of `esp-idf-sys` used by your crate matches the one used by `libcoap-sys`.
//! - Ensure that your `sdkconfig.defaults` enables the features required by your chosen
//!   feature set of `libcoap-rs`
//! - Ensure that the ESP-IDF version you link against is supported. `libcoap-rs` _should_
//!   compile on at least ESP-IDF 5.1.3 and 5.3.
//!   If it does not (or you require support for newer versions of ESP-IDF), please open an issue
//!   in the [`libcoap-rs` issue tracker](https://github.com/namib-project/libcoap-rs/issues).
//!
//! An example for a typical excerpt from `sdkconfig.defaults` can be found here:
//! ```ini
//! # libcoap base functionality (client and server)
//! CONFIG_COAP_SERVER_SUPPORT=y
//! CONFIG_COAP_CLIENT_SUPPORT=y
//!
//! # enable DTLS in libcoap
//! CONFIG_COAP_MBEDTLS_PSK=y
//! CONFIG_COAP_MBEDTLS_PKI=y
//! CONFIG_MBEDTLS_SSL_PROTO_DTLS=y
//! CONFIG_MBEDTLS_PSK_MODES=y
//! CONFIG_MBEDTLS_KEY_EXCHANGE_PSK=y
//! ```
//!
//! # Using cryptography
//! If you wish to use CoAP over DTLS, you have to provide credential and key information to
//! libcoap. See the documentation of the [`crypto`] module for more information and examples.
//!
//! libcoap requires a DTLS library to be selected for DTLS functionality. By default, libcoap-rs
//! will use `openssl` for this purpose. If you wish to use one of the other supported DTLS
//! libraries (GnuTLS, MbedTLS, TinyDTLS), disable the `dtls_openssl` feature and replace it with
//! the feature for the library of your choice.
//!
//! Note that enabling multiple backends is not possible and doing so will result in a single
//! backend being chosen based on the priority order (gnutls > openssl > mbedtls > tinydtls).
//!
//! # Examples
//!
//! ## Client
//! This example runs a simple CoAP client which makes a request to `coap://[::1]:5683/hello_world`
//! and checks whether the result has the code 2.00 (Content) and the payload `Hello World!`.
//!
//! ```no_run
//! use std::{
//!     net::{SocketAddr, UdpSocket},
//!     time::Duration,
//! };
//!
//! use libcoap_rs::{
//!     CoapContext,
//!     message::{CoapMessageCommon, CoapResponse, CoapRequest},
//!     protocol::{CoapRequestCode, CoapResponseCode, CoapMessageCode, CoapMessageType},
//!     CoapRequestHandler, CoapResource,
//!     session::{CoapSessionCommon, CoapClientSession},
//!     types::{CoapUriScheme, CoapUri}
//! };
//!
//! let server_address : SocketAddr = "[::1]:5683".parse().unwrap();
//!
//! // Create a new context.
//! let mut context = CoapContext::new().expect("Failed to create CoAP context");
//!
//! // Connect to the server at the specified address over UDP (no encryption)
//! let session = CoapClientSession::connect_udp(&mut context, server_address)
//!                 .expect("Failed to create client-side session");
//!
//! // Create a new CoAP URI to request from.
//! let uri = "coap://[::1]:5683/hello_world".parse().unwrap();
//!
//! // Create a new request of type get with the specified URI.
//! let mut request = CoapRequest::new(CoapMessageType::Con, CoapRequestCode::Get, uri).unwrap();
//!
//! // Send the request and wait for a response.
//! let req_handle = session.send_request(request).expect("Unable to send request");
//! loop {
//!     context.do_io(Some(Duration::from_secs(10))).expect("error during IO");
//!     // Poll for responses to a request using the request handle.
//!     for response in session.poll_handle(&req_handle) {
//!         assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Content));
//!         assert_eq!(response.data().unwrap().as_ref(), "Hello World!".as_bytes());
//!         return;
//!     }
//! }
//! ```
//!
//! ## Server
//! This example runs a simple CoAP server that provides a resource under the URI path
//! `/hello_world` with `Hello World!` as the response payload.
//!
//! ```no_run
//! use std::{
//!     net::{SocketAddr, UdpSocket},
//!     time::Duration,
//! };
//!
//! use libcoap_rs::{
//!     CoapContext,
//!     message::{CoapMessageCommon, CoapResponse, CoapRequest},
//!     protocol::{CoapRequestCode, CoapResponseCode},
//!     CoapRequestHandler, CoapResource,
//!     session::{CoapSessionCommon, CoapServerSession},
//! };
//!
//! // a new CoAP context and bind to the generated SocketAddr.
//! let mut context = CoapContext::new().expect("Failed to create CoAP context");
//! context.add_endpoint_udp("[::1]:5683".parse().unwrap()).expect("Unable to add/bind to endpoint");
//!
//! // Create a new resource that is available at the URI path `hello_world`
//! // The second argument can be used to provide any kind of user-specific data, which will
//! // then be passed to the handler function.
//! let resource = CoapResource::new("hello_world", (), false);
//! // Set a method handler for the GET method.
//! resource.set_method_handler(
//!     CoapRequestCode::Get,
//!     Some(CoapRequestHandler::new(
//!         // The handler can be a lambda or some other kind of function.
//!         // Using methods is also possible by setting the resource's user data to an instance
//!         // of the struct, as the first argument will then be a mutable reference to the
//!         // user data. Methods will then use this user data as the `&mut self` reference.
//!         //
//!         // The provided CoapResponse is already filled with the correct token to be
//!         // interpreted as a response to the correct request by the client.
//!         |completed: &mut (), session: &mut CoapServerSession, request: &CoapRequest, mut response: CoapResponse| {
//!             // Set content of the response message to "Hello World!"
//!             let data = Vec::<u8>::from("Hello World!".as_bytes());
//!             response.set_data(Some(data));
//!             // Set the response code to 2.00 "Content"
//!             response.set_code(CoapResponseCode::Content);
//!             // Send the response message.
//!             session.send(response).expect("Unable to send response");
//!         },
//!     )),
//! );
//!
//! // Add the resource to the context.
//! context.add_resource(resource);
//! loop {
//!     // process IO in a loop...
//!     if let Err(e) = context.do_io(Some(Duration::from_secs(1))) {
//!         break;
//!     }
//!     // ...until we want to shut down.
//! }
//! // Properly shut down, completing outstanding IO requests and properly closing sessions.
//! context.shutdown(Some(Duration::from_secs(0))).unwrap();
//! ```

extern crate core;

pub use context::CoapContext;
pub use event::CoapEventHandler;
pub use resource::{CoapRequestHandler, CoapResource};

mod context;
#[cfg(dtls)]
pub mod crypto;
pub mod error;
mod event;
mod mem;
pub mod message;
pub mod prng;
pub mod protocol;
mod resource;
pub mod session;
pub mod transport;
pub mod types;

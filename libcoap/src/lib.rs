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
//! libcoap-rs is based on libcoap-sys, which provide many different ways to obtain and link against
//! a system-provided or vendored version of the libcoap C library.
//!
//! Refer to [its documentation](libcoap_sys) for detailed instructions on how to
//! build libcoap-sys as well as this library.
//!
//! Most of these instructions can be applied to libcoap-rs directly, although libcoap-rs does
//! abstract away some of the features.
//!
//! For your convenience, libcoap-rs "re-exports" some features that do not have any influence on
//! the safe wrapper, but may have to be set in libcoap-sys to enable building (e.g., the
//! `dtls-<LIBRARY NAME>-sys` features).
//! This way, you don't need to add libcoap-sys as a dependency yourself, and may just enable the
//! feature in this crate instead.
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
#[cfg(feature = "dtls")]
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

// SPDX-License-Identifier: BSD-2-Clause
/*
 * lib.rs - Main library entry point for safe libcoap bindings.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
#![cfg_attr(feature = "nightly", feature(trait_upcasting))]

//! A safe wrapper around the libcoap C library.
//!
//! This wrapper allows for safe and idiomatic usage of the libcoap C library in Rust.
//!
//! # Protocol support
//! libcoap-rs currently supports the following subset of the libcoap feature set:
//! - [x] Basic CoAP client
//! - [x] Basic CoAP server
//! - [-] Transports:
//!     - [x] UDP
//!     - [-] DTLS
//!         - [x] DTLS using PSK
//!         - [ ] DTLS using PKI/RPK
//!     - [ ] TCP
//!     - [ ] TLS
//! - [-] Blockwise Transfer
//!     - [x] Receiving large messages
//!         - Note: Handled by libcoap by setting `COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY`
//!     - [x] sending client-side large messages
//!     - [ ] sending server-side large messages
//! - [-] Resource observation
//!     - [ ] Observing resources as a client
//!     - [x] Notifying observers as a server
//!
//! # Examples
//!
//! ## Client
//!
//! ```no_run
//! use std::{
//!     net::{SocketAddr, UdpSocket},
//!     time::Duration,
//! };
//!
//! use libcoap::{
//!     CoapContext,
//!     message::{CoapMessageCommon, CoapResponse, CoapRequest},
//!     protocol::{CoapRequestCode, CoapResponseCode, CoapMessageCode, CoapMessageType},
//!     CoapRequestHandler, CoapResource,
//!     session::{CoapSessionCommon, CoapClientSession},
//!     types::{CoapUriScheme, CoapUri}
//! };
//!
//! use url::Url;
//!
//! pub fn main() {
//!     let server_address : SocketAddr = "[::1]:5683".parse().unwrap();
//!
//!     // Create a new context.
//!     let mut context = CoapContext::new().unwrap();
//!
//!     // Connect to the server at the specified address over UDP (plaintext CoAP)
//!     let session = CoapClientSession::connect_udp(&mut context, server_address).unwrap();
//!
//!     // Create a new CoAP URI to request from.
//!     let uri = CoapUri::try_from_url(Url::parse("coap://localhost:5683/hello_world").unwrap()).unwrap();
//!
//!     // Create a new request of type get with the specified URI.
//!     let mut request = CoapRequest::new(CoapMessageType::Con, CoapRequestCode::Get).unwrap();
//!     request.set_uri(Some(uri)).unwrap();
//!
//!     // Send the request and wait for a response.
//!     let req_handle = session.send_request(request).unwrap();
//!     loop {
//!         context.do_io(Some(Duration::from_secs(10))).expect("error during IO");
//!         // Poll for responses to a request using the request handle.
//!         for response in session.poll_handle(&req_handle) {
//!             assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Content));
//!             assert_eq!(response.data().unwrap().as_ref(), "Hello World!".as_bytes());
//!             return;
//!         }
//!     }
//! }
//! ```
//!
//! ## Server
//!
//! ```no_run
//! use std::{
//!     net::{SocketAddr, UdpSocket},
//!     time::Duration,
//! };
//!
//! use libcoap::{
//!     CoapContext,
//!     message::{CoapMessageCommon, CoapResponse, CoapRequest},
//!     protocol::{CoapRequestCode, CoapResponseCode},
//!     CoapRequestHandler, CoapResource,
//!     session::{CoapSessionCommon, CoapServerSession},
//! };
//!  
//! fn main() {
//!     // This will give us a SocketAddress with a port in the local port range automatically
//!     // assigned by the operating system.
//!     // Because the UdpSocket goes out of scope, the Port will be free for usage by libcoap.
//!     // This seems to be the only portable way to get a port number assigned from the operating
//!     // system.
//!     // It is assumed here that after unbinding the temporary socket, the OS will not reassign
//!     // this port until we bind it again. This should work in most cases (unless we run on a
//!     // system with very few free ports), because at least Linux will not reuse port numbers
//!     // unless necessary, see https://unix.stackexchange.com/a/132524.
//!     let server_address = UdpSocket::bind("localhost:0")
//!         .expect("Failed to bind server socket")
//!         .local_addr()
//!         .expect("Failed to get server socket address");
//!
//!     // a new CoAP context and bind to the generated SocketAddr.
//!     let mut context = CoapContext::new().unwrap();
//!     context.add_endpoint_udp(server_address).unwrap();
//!
//!     // Create a new resource that is available at the URI path `hello_world`
//!     // The second argument can be used to provide any kind of user-specific data, which will
//!     // then be passed to the handler function.
//!     let resource = CoapResource::new("hello_world", (), false);
//!     // Set a method handler for the GET method.
//!     resource.set_method_handler(
//!         CoapRequestCode::Get,
//!         Some(CoapRequestHandler::new(
//!             // The handler can be a lambda or some other kind of function.
//!             // Using methods is also possible by setting the resource's user data to an instance
//!             // of the struct, as the first argument will then be a mutable reference to the
//!             // user data (methods will then use this user data as the `&mut self` reference.
//!             //
//!             // The provided CoapResponse is already filled with the correct token to be
//!             // interpreted as a response to the correct request by the client.
//!             |completed: &mut (), session: &mut CoapServerSession, request: &CoapRequest, mut response: CoapResponse| {
//!                 // Set content of the response message to "Hello World!"
//!                 let data = Vec::<u8>::from("Hello World!".as_bytes());
//!                 response.set_data(Some(data));
//!                 // Set the response code to 2.00 "Content"
//!                 response.set_code(CoapResponseCode::Content);
//!                 // Send the response message.
//!                 session.send(response).unwrap();
//!             },
//!         )),
//!     );
//!
//!     // Add the resource to the context.
//!     context.add_resource(resource);
//!     loop {
//!         // process IO in a loop...
//!         context.do_io(Some(Duration::from_secs(1))).unwrap();
//!         // ...until we want to shut down.
//!     }
//!     // Properly shut down, completing outstanding IO requests and properly closing sessions.
//!     context.shutdown(Some(Duration::from_secs(0))).unwrap();
//! }
//! ```
//!
//! # Using cryptography
//! If you wish to use CoAP over DTLS, you have to provide credential and key information to
//! libcoap. To do so, you need to provide an instance of [CoapClientCryptoProvider] to
//! [CoapClientSession::connect_dtls()] (for client sessions) and/or an instance of
//! [CoapServerCryptoProvider] to [CoapContext::set_server_crypto_provider()] (for server sessions).
//!
//! libcoap requires a DTLS library to be selected for DTLS functionality. By default, libcoap-rs
//! will use `openssl` for this purpose. If you wish to use one of the other supported DTLS
//! libraries (GnuTLS, MBedTLS, TinyDTLS), disable the `dtls_openssl` feature and replace it with
//! the feature for the library of your choice.
//!
//! Note that enabling multiple backends is not possible and doing so will result in a single
//! backend being chosen based on the priority order (gnutls > openssl > mbedtls > tinydtls).

mod context;
pub mod crypto;
pub mod error;
mod event;
mod mem;
pub mod message;
pub mod protocol;
mod resource;
pub mod session;
#[cfg(feature = "server")]
pub mod transport;
pub mod types;

pub use context::CoapContext;
pub use event::CoapEventHandler;
pub use resource::{CoapRequestHandler, CoapResource};

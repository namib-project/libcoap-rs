// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto/psk/mod.rs - Interfaces and types for PSK support in libcoap-rs.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
//! Types and traits related to support for (D)TLS with pre-shared keys for CoAP.
//!
//! PSK configuration differs between client-side and server-side configuration.
//!
//! # Client Configuration
//! Typically, you would follow these steps to configure a DTLS PSK client:
//! 1. Create a [`PskKey`](psk::PskKey) that should be used as a default key when connecting to servers.
//! 2. Create a [`ClientPskContextBuilder`](psk::ClientPskContextBuilder) using the default key,
//!    (optionally) make some additional configuration changes in the builder.
//!    Most notably, you might want to call [`ClientPskContextBuilder::key_provider`](psk::ClientPskContextBuilder::key_provider)
//!    to set a key provider that may use server-provided identity hints to select a different key
//!    than the default key (if your target server sends those hints).
//! 3. Call [`ClientPskContextBuilder::build`](psk::ClientPskContextBuilder::build) to create a
//!    [`ClientPskContext`](psk::ClientPskContext).
//! 4. Provide the created context to [`CoapClientSession::connect_dtls`](crate::session::CoapClientSession::connect_dtls).
//!
//! ## Example
//!
//! ```no_run
//! use libcoap_rs::CoapContext;
//! use libcoap_rs::crypto::psk::{ClientPskContextBuilder, PskKey};
//! use libcoap_rs::session::CoapClientSession;
//!
//!
//! let example_key = PskKey::new(Some("dtls_test_id_client1"), "dtls_test_key__1");
//! let psk_context = ClientPskContextBuilder::new(example_key.clone());
//!
//! let psk_context = psk_context.build();
//!
//! let mut context = CoapContext::new().unwrap();
//! let session = CoapClientSession::connect_dtls(
//!                 &mut context,
//!                 "example.com:5684".parse().unwrap(),
//!                 psk_context
//!               ).unwrap();
//!
//! // The session might not be immediately established, but you can already create and send
//! // requests as usual after this point.
//! // To check for errors and/or disconnections, you might want to call and check the return value
//! // of `session.state()` occasionally.
//! // For error handling, you might also want to register an event handler with the CoAP context.
//! // Remaining code omitted for brevity, see the crate-level docs for a full example of client
//! // operation.
//! ```
//!
//! # Server Configuration
//! Typically, you would follow these steps to configure a DTLS PSK server:
//! 1. Create a [`PskKey`](psk::PskKey) that should be used as a default key when connecting to clients.
//! 2. Create a [`ServerPskContextBuilder`](psk::ServerPskContextBuilder) using the default key, (optionally) make some additional
//!    configuration changes in the builder.
//!    Most notably, you might want to call [`ServerPskContextBuilder::id_key_provider`](psk::ServerPskContextBuilder::id_key_provider) to choose
//!    different pre-shared keys depending on the identity sent by clients, and
//!    [`ServerPskContextBuilder::sni_key_provider`](psk::ServerPskContextBuilder::sni_key_provider) to send different identity hints for different
//!    requested domains.
//! 3. Call [`ServerPskContextBuilder::build`](psk::ServerPskContextBuilder::build) to create a [`ServerPskContext`](psk::ServerPskContext).
//! 4. Provide the created context to [`CoapContext::set_psk_context`](crate::CoapContext::set_psk_context).
//! 5. Add a DTLS endpoint using [`CoapContext::add_endpoint_dtls`](crate::CoapContext::add_endpoint_dtls).
//!
//! ## Example
//!
//! ```no_run
//! use std::collections::HashMap;
//! use libcoap_rs::CoapContext;
//! use libcoap_rs::crypto::psk::{ClientPskContextBuilder, PskKey, ServerPskContextBuilder};
//! use libcoap_rs::session::CoapClientSession;
//!
//!
//! let example_key = PskKey::new(Some("dtls_test_id"), "dtls_test_key___");
//!
//! let mut client_keys = [
//!     PskKey::new(Some("dtls_test_id_client1"), "dtls_test_key__1"),
//!     PskKey::new(Some("dtls_test_id_client2"), "dtls_test_key__2"),
//! ];
//!
//! let psk_context = ServerPskContextBuilder::new(example_key.clone())
//!                     // Some types already implement ServerPskIdentityKeyProvider by default.
//!                     // Namely, all types that implement AsRef<[PskKey]> do, such as [PskKey] and
//!                     // Vec<PskKey>.
//!                     .id_key_provider(client_keys);
//!
//! let psk_context = psk_context.build();
//!
//! let mut context = CoapContext::new().unwrap();
//! context.set_psk_context(psk_context).expect("error while setting PSK context");
//! context.add_endpoint_dtls("[::1]:5684".parse().unwrap()).expect("unable to create DTLS endpoint");
//!
//! // For error handling, you might want to register an event handler with the CoAP context.
//! // Remaining code omitted for brevity, see the crate-level docs for a full example of server
//! // operation.
//!
//! ```

/// Data structures and builders for PSK client-side operation.
mod client;
/// Data structures for PSK keys.
mod key;
/// Data structures and builders for PSK server-side operation.
mod server;

pub use client::*;
pub use key::*;
pub use server::*;

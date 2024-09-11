// SPDX-License-Identifier: BSD-2-Clause
/*
 * dtls_psk_client_server_test.rs - Tests for DTLS PSK clients+servers.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

#![cfg(feature = "dtls-psk")]
use std::time::Duration;

use libcoap_rs::crypto::psk::PskKey;
use libcoap_rs::crypto::psk::{ClientPskContextBuilder, ServerPskContextBuilder};
use libcoap_rs::session::CoapClientSession;
use libcoap_rs::{
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::CoapSessionCommon,
    CoapContext,
};

mod common;

#[test]
pub fn dtls_psk_client_server_request() {
    let server_address = common::get_unused_server_addr();
    let dummy_key = PskKey::new(Some("dtls_test_id"), "dtls_test_key___");
    let client_psk_context = ClientPskContextBuilder::new(dummy_key.clone()).build();

    let server_handle = common::spawn_test_server(move |mut context| {
        let server_psk_context = ServerPskContextBuilder::new(dummy_key.clone()).build();
        context.set_psk_context(server_psk_context);
        context.add_endpoint_dtls(server_address).unwrap();
        context
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_dtls(&mut context, server_address, client_psk_context).unwrap();

    let request = common::gen_test_request();
    let req_handle = session.send_request(request).unwrap();
    loop {
        assert!(context.do_io(Some(Duration::from_secs(10))).expect("error during IO") <= Duration::from_secs(10));
        for response in session.poll_handle(&req_handle) {
            assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Content));
            assert_eq!(response.data().unwrap().as_ref(), "Hello World!".as_bytes());
            server_handle.join().expect("Test server crashed with failure.");
            return;
        }
    }
}

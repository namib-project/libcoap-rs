// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * tests/dtls_psk_client_server_test.rs - Tests for DTLS PSK clients+servers.
 */

#![cfg(feature = "dtls-psk")]
use std::time::Duration;

use libcoap_rs::{
    crypto::psk::{ClientPskContextBuilder, PskKey, ServerPskContextBuilder},
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::{CoapClientSession, CoapSessionCommon},
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
        context.set_psk_context(server_psk_context).unwrap();
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

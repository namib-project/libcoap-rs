// SPDX-License-Identifier: BSD-2-Clause
/*
 * tcp_client_server_test.rs - Tests for TCP clients+servers.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
#![cfg(feature = "tcp")]

use std::time::Duration;

use libcoap_rs::{
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::{CoapClientSession, CoapSessionCommon},
    CoapContext,
};

mod common;

#[test]
pub fn basic_client_server_request() {
    let server_address = common::get_unused_server_addr();

    let server_handle = common::spawn_test_server(move |mut context, _request_complete| {
        context.add_endpoint_tcp(server_address).unwrap();
        context
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_tcp(&mut context, server_address).unwrap();

    let request = common::gen_test_request();
    let req_handle = session.send_request(request).unwrap();
    loop {
        assert!(context.do_io(Some(Duration::from_secs(10))).expect("error during IO") <= Duration::from_secs(10));
        for response in session.poll_handle(&req_handle) {
            assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Content));
            assert_eq!(response.data().unwrap().as_ref(), "Hello World!".as_bytes());
            if let Err(e) = server_handle.join() {
                std::panic::resume_unwind(e);
            }
            return;
        }
    }
}

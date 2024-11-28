// SPDX-License-Identifier: BSD-2-Clause
/*
 * dtls_client_server_test.rs - Tests for UDP clients+servers.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::{
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use libcoap_rs::{
    message::{CoapMessageCommon, CoapRequest},
    protocol::{CoapMessageCode, CoapMessageType, CoapRequestCode, CoapResponseCode},
    session::{CoapClientSession, CoapSessionCommon},
    types::CoapUri,
    CoapContext, CoapRequestHandler, CoapResource,
};

mod common;

#[test]
pub fn observe_client_server_request() {
    let server_address = common::get_unused_server_addr();

    let uri: CoapUri = "/observe-test".parse().expect("unable to parse request URI");

    let server_handle = common::spawn_test_server(move |mut context: CoapContext, request_complete| {
        context.add_endpoint_udp(server_address).unwrap();

        let observe_resource = CoapResource::new("observe-test", (0u8, request_complete), true);
        observe_resource.set_get_observable(true);
        observe_resource.set_method_handler(
            CoapRequestCode::Get,
            Some(CoapRequestHandler::new(
                |data: &mut (u8, Rc<AtomicBool>), session, request, response| {
                    response.set_code(CoapResponseCode::Content);
                    response.set_data(Some([data.0]));
                    if data.0 != 0u8 {
                        data.1.store(true, Ordering::Relaxed);
                    }
                },
            )),
        );
        observe_resource.set_method_handler(
            CoapRequestCode::Post,
            Some(CoapRequestHandler::new_resource_ref(
                move |resource: &CoapResource<(u8, Rc<AtomicBool>)>, session, request, response| {
                    resource.user_data_mut().0 = request.data().expect("sent empty data")[0];
                    response.set_code(CoapResponseCode::Changed);
                    resource.notify_observers();
                },
            )),
        );
        context.add_resource(observe_resource);
        context
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_udp(&mut context, server_address).unwrap();

    let mut request = CoapRequest::new(CoapMessageType::Non, CoapRequestCode::Get, uri.clone()).unwrap();
    request.set_observe(Some(0));
    let mut update_request_handle = None;

    let req_handle = session.send_request(request).unwrap();
    let mut expected_request_response = 0u8;
    loop {
        assert!(context.do_io(Some(Duration::from_secs(10))).expect("error during IO") <= Duration::from_secs(10));
        if let Some(update_request_handle) = update_request_handle.as_ref() {
            for response in session.poll_handle(&update_request_handle) {
                assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Changed));
                expected_request_response = 1u8;
            }
        }
        for response in session.poll_handle(&req_handle) {
            assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Content));
            assert_eq!(response.data().unwrap().as_ref(), [expected_request_response]);
            if expected_request_response != 0u8 {
                if let Err(e) = server_handle.join() {
                    std::panic::resume_unwind(e);
                }
                return;
            }
            if update_request_handle.is_none() {
                // trigger update of resource to test observe notification
                let mut update_request =
                    CoapRequest::new(CoapMessageType::Non, CoapRequestCode::Post, uri.clone()).unwrap();
                update_request.set_data(Some([1u8]));
                update_request_handle = Some(
                    session
                        .send_request(update_request)
                        .expect("unable to send update request"),
                );
            }
        }
    }
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * tests/common/mod.rs - Common code for integration tests.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

#[cfg(any(feature = "dtls-pki", feature = "dtls-rpk"))]
pub mod dtls;

use std::{
    net::{SocketAddr, UdpSocket},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

use libcoap_rs::{
    message::{CoapMessageCommon, CoapRequest, CoapResponse},
    protocol::{CoapMessageCode, CoapMessageType, CoapRequestCode, CoapResponseCode},
    CoapContext, CoapRequestHandler, CoapResource,
};
use libcoap_sys::{coap_dtls_set_log_level, coap_log_t, coap_set_log_level};

pub(crate) fn get_unused_server_addr() -> SocketAddr {
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
    UdpSocket::bind("localhost:0")
        .expect("Failed to bind server socket")
        .local_addr()
        .expect("Failed to get server socket address")
}

/// Spawns a test server in a new thread and waits for context_configurator to complete before
/// returning.
/// As the context_configurator closure is responsible for binding to sockets, this can be used to
/// spawn a test server and wait for it to be ready to accept requests before returning (avoiding
/// test failure due to "Connection Refused" errors).
pub(crate) fn spawn_test_server<
    F: FnOnce(CoapContext<'static>, Rc<AtomicBool>) -> CoapContext<'static>+Send+'static,
>(
    context_configurator: F,
) -> JoinHandle<()> {
    let ready_condition = Arc::new((Mutex::new(false), Condvar::new()));
    let ready_condition2 = Arc::clone(&ready_condition);

    let server_handle = std::thread::spawn(move || {
        let (ready_var, ready_cond) = &*ready_condition2;
        run_test_server(|context, request_complete| {
            let context = context_configurator(context, request_complete);
            let mut ready_var = ready_var.lock().expect("ready condition mutex is poisoned");
            *ready_var = true;
            ready_cond.notify_all();
            context
        });
    });

    let (ready_var, ready_cond) = &*ready_condition;
    drop(
        ready_cond
            .wait_while(ready_var.lock().expect("ready condition mutex is poisoned"), |ready| {
                !*ready
            })
            .expect("ready condition mutex is poisoned"),
    );
    server_handle
}

/// Configures and starts a test server in the current thread.
pub(crate) fn run_test_server<F: FnOnce(CoapContext<'static>, Rc<AtomicBool>) -> CoapContext<'static>>(
    context_configurator: F,
) {
    unsafe {
        libcoap_sys::coap_startup_with_feature_checks();
        coap_dtls_set_log_level(coap_log_t::COAP_LOG_DEBUG);
        coap_set_log_level(coap_log_t::COAP_LOG_DEBUG);
    }
    let mut context = CoapContext::new().unwrap();
    let request_completed = Rc::new(AtomicBool::new(false));
    context = context_configurator(context, Rc::clone(&request_completed));
    let resource = CoapResource::new("test1", request_completed.clone(), false);
    resource.set_method_handler(
        CoapRequestCode::Get,
        Some(CoapRequestHandler::new(
            |completed: &mut Rc<AtomicBool>, sess, _req, rsp: &mut CoapResponse| {
                let data = Vec::<u8>::from("Hello World!".as_bytes());
                rsp.set_data(Some(data));
                rsp.set_code(CoapMessageCode::Response(CoapResponseCode::Content));
                completed.store(true, Ordering::Relaxed);
            },
        )),
    );

    context.add_resource(resource);
    loop {
        assert!(
            context.do_io(Some(Duration::from_secs(1000))).unwrap() < Duration::from_secs(1000),
            "timeout while waiting for test client request"
        );
        if request_completed.load(Ordering::Relaxed) {
            break;
        }
    }
    context.shutdown(Some(Duration::from_secs(5))).unwrap();
}

pub(crate) fn gen_test_request() -> CoapRequest {
    let uri = "/test1".parse().expect("unable to parse request URI");

    CoapRequest::new(CoapMessageType::Con, CoapRequestCode::Get, uri).unwrap()
}

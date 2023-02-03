use libcoap_rs::session::CoapClientSession;
use libcoap_rs::{
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::CoapSessionCommon,
    CoapContext,
};
use std::time::Duration;

mod common;

#[test]
pub fn basic_client_server_request() {
    let server_address = common::get_unused_server_addr();

    let server_handle = std::thread::spawn(move || {
        common::run_test_server(|context| context.add_endpoint_udp(server_address).unwrap());
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_udp(&mut context, server_address).unwrap();

    let request = common::gen_test_request(server_address);
    let req_handle = session.send_request(request).unwrap();
    loop {
        assert!(context.do_io(Some(Duration::from_secs(10))).expect("error during IO") <= Duration::from_secs(10));
        for response in session.poll_handle(&req_handle) {
            assert_eq!(response.code(), CoapMessageCode::Response(CoapResponseCode::Content));
            assert_eq!(response.data().unwrap().as_ref(), "Hello World!".as_bytes());
            server_handle.join().unwrap();
            return;
        }
    }
}

use std::{
    net::{SocketAddr, UdpSocket},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use libcoap::message::request::CoapRequest;
use libcoap::message::response::CoapResponse;
use libcoap::session::CoapClientSession;
use libcoap::{
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapMessageType, CoapRequestCode, CoapResponseCode},
    session::CoapSessionCommon,
    types::{CoapUri, CoapUriHost},
    CoapContext, CoapRequestHandler, CoapResource,
};

fn run_basic_test_server(server_address: SocketAddr) {
    let mut context = CoapContext::new().unwrap();
    context.add_endpoint_udp(server_address).unwrap();
    let request_completed = Rc::new(AtomicBool::new(false));
    let resource = CoapResource::new("test1", request_completed.clone(), false);
    resource.set_method_handler(
        CoapRequestCode::Get,
        Some(CoapRequestHandler::new(
            |completed: &mut Rc<AtomicBool>, sess, _req, mut rsp: CoapResponse| {
                let data = Vec::<u8>::from("Hello World!".as_bytes());
                rsp.set_data(Some(data));
                rsp.set_code(CoapMessageCode::Response(CoapResponseCode::Content));
                sess.send(rsp).unwrap();
                completed.store(true, Ordering::Relaxed);
            },
        )),
    );

    context.add_resource(resource);
    loop {
        assert!(context.do_io(Some(Duration::from_secs(10))).unwrap() < Duration::from_secs(10));
        if request_completed.load(Ordering::Relaxed) {
            break;
        }
    }
    context.shutdown(Some(Duration::from_secs(0))).unwrap();
}

#[test]
pub fn test_basic_client_server() {
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
    let server_address = UdpSocket::bind("localhost:0")
        .expect("Failed to bind server socket")
        .local_addr()
        .expect("Failed to get server socket address");

    let addr_clone = server_address;
    let server_handle = std::thread::spawn(move || {
        run_basic_test_server(addr_clone);
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_udp(&mut context, server_address).unwrap();

    let uri = CoapUri::new(
        None,
        Some(CoapUriHost::IpLiteral(server_address.ip())),
        Some(server_address.port()),
        Some(vec!["test1".to_string()]),
        None,
    );

    let mut request = CoapRequest::new(CoapMessageType::Con, CoapRequestCode::Get).unwrap();
    request.set_uri(Some(uri)).unwrap();
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

#![cfg(feature = "dtls")]
use std::fmt::Debug;
use std::time::Duration;

use libcoap_rs::crypto::{
    CoapClientCryptoProvider, CoapCryptoProviderResponse, CoapCryptoPskData, CoapCryptoPskIdentity, CoapCryptoPskInfo,
    CoapServerCryptoProvider,
};
use libcoap_rs::session::CoapClientSession;
use libcoap_rs::{
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::CoapSessionCommon,
    CoapContext,
};

mod common;

#[derive(Debug)]
struct DummyCryptoProvider;

impl CoapServerCryptoProvider for DummyCryptoProvider {
    fn provide_default_info(&mut self) -> CoapCryptoPskInfo {
        CoapCryptoPskInfo {
            identity: String::from("dtls_test_identity").into_boxed_str().into(),
            key: String::from("dtls_test_key___").into_boxed_str().into(),
        }
    }
}

impl CoapClientCryptoProvider for DummyCryptoProvider {
    fn provide_key_for_hint(
        &mut self,
        _hint: &CoapCryptoPskIdentity,
    ) -> CoapCryptoProviderResponse<Box<CoapCryptoPskData>> {
        CoapCryptoProviderResponse::UseCurrent
    }

    fn provide_default_info(&mut self) -> CoapCryptoPskInfo {
        CoapCryptoPskInfo {
            identity: String::from("dtls_test_identity").into_boxed_str().into(),
            key: String::from("dtls_test_key___").into_boxed_str().into(),
        }
    }
}

#[test]
pub fn dtls_client_server_request() {
    let server_address = common::get_unused_server_addr();

    let server_handle = std::thread::spawn(move || {
        common::run_test_server(|context| {
            context.set_server_crypto_provider(Some(Box::new(DummyCryptoProvider {})));
            context.add_endpoint_dtls(server_address).unwrap();
        });
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_dtls(&mut context, server_address, DummyCryptoProvider {}).unwrap();

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

use std::{path::PathBuf, time::Duration};

use libcoap_rs::{
    crypto::{
        pki_rpk::{KeyDef, KeyType, NonCertVerifying, PkiRpkContext, PkiRpkContextBuilder, ServerPkiRpkCryptoContext},
        ClientCryptoContext,
    },
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::{CoapClientSession, CoapSessionCommon},
    CoapContext,
};

use crate::common;

// Is used in some test cases, but not in others (causing a compiler warning)
#[allow(unused)]
pub fn dtls_client_server_request_common<KTY: KeyType, FC, FS>(
    client_key: impl KeyDef<KeyType=KTY>+'static,
    server_key: impl KeyDef<KeyType=KTY>+'static+Send,
    client_ctx_setup: FC,
    server_ctx_setup: FS,
) where
    FC: FnOnce(PkiRpkContextBuilder<'static, KTY, NonCertVerifying>) -> PkiRpkContext<'static, KTY>+'static,
    FS: FnOnce(PkiRpkContextBuilder<'static, KTY, NonCertVerifying>) -> PkiRpkContext<'static, KTY>+Send+'static,
    ServerPkiRpkCryptoContext<'static>: From<PkiRpkContext<'static, KTY>>,
    ClientCryptoContext<'static>: From<PkiRpkContext<'static, KTY>>,
{
    let server_address = common::get_unused_server_addr();
    let client_crypto_ctx = client_ctx_setup(PkiRpkContextBuilder::<'static, KTY, NonCertVerifying>::new(client_key));
    let server_handle = common::spawn_test_server(move |mut context: CoapContext, _request_complete| {
        let server_crypto_ctx =
            server_ctx_setup(PkiRpkContextBuilder::<'static, KTY, NonCertVerifying>::new(server_key));
        context.set_pki_rpk_context(server_crypto_ctx).unwrap();
        context.add_endpoint_dtls(server_address).unwrap();
        #[cfg(feature = "dtls-pki")]
        context.set_pki_root_ca_paths(Some("./resources/test-keys/ca/ca.crt.pem"), None::<PathBuf>);
        context
    });

    let mut context = CoapContext::new().unwrap();
    #[cfg(feature = "dtls-pki")]
    context.set_pki_root_ca_paths(Some("./resources/test-keys/ca/ca.crt.pem"), None::<PathBuf>);
    let session = CoapClientSession::connect_dtls(&mut context, server_address, client_crypto_ctx).unwrap();

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

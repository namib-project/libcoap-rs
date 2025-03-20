// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * tests/common/dtls.rs - common code for DTLS tests.
 */

use std::{ffi::CStr, path::PathBuf, time::Duration};

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
use libcoap_sys::{
    coap_get_tls_library_version, coap_package_version, coap_tls_library_t_COAP_TLS_LIBRARY_GNUTLS,
    coap_tls_library_t_COAP_TLS_LIBRARY_MBEDTLS, coap_tls_library_t_COAP_TLS_LIBRARY_NOTLS,
    coap_tls_library_t_COAP_TLS_LIBRARY_OPENSSL, coap_tls_library_t_COAP_TLS_LIBRARY_TINYDTLS,
    coap_tls_library_t_COAP_TLS_LIBRARY_WOLFSSL,
};

use crate::common;

// Is used in some test cases, but not in others (causing a compiler warning)
#[allow(unused)]
pub fn dtls_client_server_request_common<KTY: KeyType, FC, FS>(
    client_key: impl KeyDef<KeyType = KTY> + 'static,
    server_key: impl KeyDef<KeyType = KTY> + 'static + Send,
    client_ctx_setup: FC,
    server_ctx_setup: FS,
) where
    FC: FnOnce(PkiRpkContextBuilder<'static, KTY, NonCertVerifying>) -> PkiRpkContext<'static, KTY> + 'static,
    FS: FnOnce(PkiRpkContextBuilder<'static, KTY, NonCertVerifying>) -> PkiRpkContext<'static, KTY> + Send + 'static,
    ServerPkiRpkCryptoContext<'static>: From<PkiRpkContext<'static, KTY>>,
    ClientCryptoContext<'static>: From<PkiRpkContext<'static, KTY>>,
{
    // Variant names are named by bindgen, we have no influence on this.
    // Ref: https://github.com/rust-lang/rust/issues/39371
    #[allow(non_upper_case_globals)]
    let tls_library = match unsafe { *coap_get_tls_library_version() }.type_ {
        coap_tls_library_t_COAP_TLS_LIBRARY_NOTLS => "notls",
        coap_tls_library_t_COAP_TLS_LIBRARY_TINYDTLS => "tinydtls",
        coap_tls_library_t_COAP_TLS_LIBRARY_OPENSSL => "openssl",
        coap_tls_library_t_COAP_TLS_LIBRARY_GNUTLS => "gnutls",
        coap_tls_library_t_COAP_TLS_LIBRARY_MBEDTLS => "mbedtls",
        coap_tls_library_t_COAP_TLS_LIBRARY_WOLFSSL => "wolfssl",
        _ => "unknown",
    };
    println!(
        "Libcoap-Version: {}, DTLS library: {}",
        unsafe { CStr::from_ptr(coap_package_version()) }.to_string_lossy(),
        tls_library
    );

    let server_address = common::get_unused_server_addr();
    let client_crypto_ctx = client_ctx_setup(PkiRpkContextBuilder::<'static, KTY, NonCertVerifying>::new(client_key));
    let server_handle = common::spawn_test_server(move |mut context: CoapContext| {
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
            server_handle.join().expect("Test server crashed with failure.");
            return;
        }
    }
}

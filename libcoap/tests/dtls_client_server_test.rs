// SPDX-License-Identifier: BSD-2-Clause
/*
 * dtls_client_server_test.rs - Tests for DTLS clients+servers.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

#![cfg(feature = "dtls")]
use std::fmt::Debug;
use std::time::Duration;

use libcoap_rs::{
    CoapContext,
    message::CoapMessageCommon,
    protocol::{CoapMessageCode, CoapResponseCode},
    session::CoapSessionCommon,
};
use libcoap_rs::crypto::{
    CoapClientCryptoProvider, CoapCryptoProviderResponse, CoapCryptoPskData, CoapCryptoPskIdentity, CoapCryptoPskInfo,
    CoapServerCryptoProvider,
};
use libcoap_rs::session::CoapClientSession;

mod common;

#[derive(Debug)]
struct DummyCryptoProvider;

impl CoapServerCryptoProvider for DummyCryptoProvider {
    fn provide_key_for_identity(
        &mut self,
        _identity: &CoapCryptoPskIdentity,
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

    let server_handle = common::spawn_test_server(move |context| {
        context.set_server_crypto_provider(Some(Box::new(DummyCryptoProvider {})));
        context.add_endpoint_dtls(server_address).unwrap();
    });

    let mut context = CoapContext::new().unwrap();
    let session = CoapClientSession::connect_dtls(&mut context, server_address, DummyCryptoProvider {}).unwrap();

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

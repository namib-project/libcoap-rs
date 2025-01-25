// SPDX-License-Identifier: BSD-2-Clause
/*
 * dtls_rpk_client_server_test.rs - Tests for DTLS RPK clients+servers.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

#![cfg(feature = "dtls-rpk")]

use libcoap_rs::crypto::pki_rpk::{NonCertVerifying, PkiRpkContextBuilder, Rpk, RpkKeyDef};

use crate::common::dtls::dtls_client_server_request_common;

mod common;

#[test]
pub fn dtls_pki_pem_memory_client_server_request() {
    // TODO Implement validator using https://docs.rs/spki/0.7.3/spki/struct.SubjectPublicKeyInfo.html#impl-Eq-for-SubjectPublicKeyInfo%3CParams,+Key%3E
    const PEM_CLIENT_PUBLIC_KEY: &str = include_str!("../resources/test-keys/client/client.pub.pem");
    const PEM_SERVER_PUBLIC_KEY: &str = include_str!("../resources/test-keys/server/server.pub.pem");
    const PEM_CLIENT_PRIVATE_KEY: &str = include_str!("../resources/test-keys/client/client.key.pem");
    const PEM_SERVER_PRIVATE_KEY: &str = include_str!("../resources/test-keys/server/server.key.pem");
    let client_key = RpkKeyDef::with_pem_memory(Vec::from(PEM_CLIENT_PUBLIC_KEY), Vec::from(PEM_CLIENT_PRIVATE_KEY));
    let server_key = RpkKeyDef::with_pem_memory(Vec::from(PEM_SERVER_PUBLIC_KEY), Vec::from(PEM_SERVER_PRIVATE_KEY));

    let ctx_configurator = |ctx: PkiRpkContextBuilder<'static, Rpk, NonCertVerifying>| ctx.build();
    dtls_client_server_request_common(client_key, server_key, ctx_configurator, ctx_configurator)
}

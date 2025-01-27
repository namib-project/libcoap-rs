// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * tests/dtls_rpk_client_server_test.rs - Tests for DTLS PKI clients+servers.
 */

#![cfg(feature = "dtls-pki")]

use std::path::PathBuf;

use libcoap_rs::crypto::pki_rpk::{
    Asn1PrivateKeyType, DerFileKeyComponent, NonCertVerifying, Pki, PkiKeyDef, PkiRpkContextBuilder,
};

use crate::common::dtls::dtls_client_server_request_common;

mod common;

#[test]
pub fn dtls_pki_pem_file_client_server_request() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_storage = manifest_dir.join("./resources/test-keys");
    let client_key = PkiKeyDef::with_pem_files(
        Some(key_storage.join("./ca/ca.crt.pem")),
        key_storage.join("./client/client.crt.pem"),
        key_storage.join("./client/client.key.pem"),
    );
    let server_key = PkiKeyDef::with_pem_files(
        Some(key_storage.join("./ca/ca.crt.pem")),
        key_storage.join("./server/server.crt.pem"),
        key_storage.join("./server/server.key.pem"),
    );

    let ctx_configurator = |ctx: PkiRpkContextBuilder<'static, Pki, NonCertVerifying>| {
        ctx.verify_peer_cert().check_common_ca(true).build()
    };
    dtls_client_server_request_common(client_key, server_key, ctx_configurator, ctx_configurator)
}

#[test]
pub fn dtls_pki_pem_memory_client_server_request() {
    const PEM_CA_CERT: &str = include_str!("../resources/test-keys/ca/ca.crt.pem");
    const PEM_CLIENT_PUBLIC_CERT: &str = include_str!("../resources/test-keys/client/client.crt.pem");
    const PEM_SERVER_PUBLIC_CERT: &str = include_str!("../resources/test-keys/server/server.crt.pem");
    const PEM_CLIENT_PRIVATE_KEY: &str = include_str!("../resources/test-keys/client/client.key.pem");
    const PEM_SERVER_PRIVATE_KEY: &str = include_str!("../resources/test-keys/server/server.key.pem");
    let client_key = PkiKeyDef::with_pem_memory(
        Some(Vec::from(PEM_CA_CERT)),
        Vec::from(PEM_CLIENT_PUBLIC_CERT),
        Vec::from(PEM_CLIENT_PRIVATE_KEY),
    );
    let server_key = PkiKeyDef::with_pem_memory(
        Some(Vec::from(PEM_CA_CERT)),
        Vec::from(PEM_SERVER_PUBLIC_CERT),
        Vec::from(PEM_SERVER_PRIVATE_KEY),
    );

    let ctx_configurator = |ctx: PkiRpkContextBuilder<'static, Pki, NonCertVerifying>| {
        ctx.verify_peer_cert().check_common_ca(true).build()
    };
    dtls_client_server_request_common(client_key, server_key, ctx_configurator, ctx_configurator)
}

#[test]
pub fn dtls_pki_asn1_file_client_server_request() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let key_storage = manifest_dir.join("./resources/test-keys");
    let client_key = PkiKeyDef::with_asn1_files(
        None::<DerFileKeyComponent>,
        key_storage.join("./client/client.crt.der"),
        key_storage.join("./client/client.key.der"),
        Asn1PrivateKeyType::Ec,
    );
    let server_key = PkiKeyDef::with_asn1_files(
        // For some inexplicable reason, setting the CA cert fails _only_ with ASN1 files using the
        // OpenSSL library.
        // I'm pretty sure this is a libcoap issue, so we'll not set the CA cert there for now.
        #[cfg(not(dtls_backend = "openssl"))]
        Some(key_storage.join("./ca/ca.crt.der")),
        #[cfg(dtls_backend = "openssl")]
        None::<DerFileKeyComponent>,
        key_storage.join("./server/server.crt.der"),
        key_storage.join("./server/server.key.der"),
        Asn1PrivateKeyType::Ec,
    );

    let ctx_configurator = |ctx: PkiRpkContextBuilder<'static, Pki, NonCertVerifying>| {
        ctx.verify_peer_cert().check_common_ca(true).build()
    };
    dtls_client_server_request_common(client_key, server_key, ctx_configurator, ctx_configurator)
}

#[test]
// GnuTLS does not like DER-encoded EC keys from memory (for some reason. Loading them from files as
// done in the test above works fine).
#[cfg_attr(dtls_backend = "gnutls", ignore)]
pub fn dtls_pki_asn1_memory_client_server_request() {
    const DER_CA_CERT: &[u8] = include_bytes!("../resources/test-keys/ca/ca.crt.der");
    const DER_CLIENT_PUBLIC_CERT: &[u8] = include_bytes!("../resources/test-keys/client/client.crt.der");
    const DER_SERVER_PUBLIC_CERT: &[u8] = include_bytes!("../resources/test-keys/server/server.crt.der");
    const DER_CLIENT_PRIVATE_KEY: &[u8] = include_bytes!("../resources/test-keys/client/client.key.der");
    const DER_SERVER_PRIVATE_KEY: &[u8] = include_bytes!("../resources/test-keys/server/server.key.der");
    let client_key = PkiKeyDef::with_asn1_memory(
        Some(Vec::from(DER_CA_CERT)),
        Vec::from(DER_CLIENT_PUBLIC_CERT),
        Vec::from(DER_CLIENT_PRIVATE_KEY),
        Asn1PrivateKeyType::Ec,
    );
    let server_key = PkiKeyDef::with_asn1_memory(
        Some(Vec::from(DER_CA_CERT)),
        Vec::from(DER_SERVER_PUBLIC_CERT),
        Vec::from(DER_SERVER_PRIVATE_KEY),
        Asn1PrivateKeyType::Ec,
    );

    let ctx_configurator = |ctx: PkiRpkContextBuilder<'static, Pki, NonCertVerifying>| {
        ctx.verify_peer_cert().check_common_ca(true).build()
    };
    dtls_client_server_request_common(client_key, server_key, ctx_configurator, ctx_configurator)
}

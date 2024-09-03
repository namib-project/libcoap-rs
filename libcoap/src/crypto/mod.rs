// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto.rs - CoAP cryptography provider interfaces and types.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Cryptography provider interfaces and types

#[cfg(any(feature = "dtls-rpk", feature = "dtls-pki"))]
pub mod pki_rpk;
#[cfg(feature = "dtls-psk")]
pub mod psk;

use std::fmt::Debug;

#[derive(Clone, Debug)]
pub enum ClientCryptoContext<'a> {
    #[cfg(feature = "dtls-psk")]
    Psk(psk::ClientPskContext<'a>),
    #[cfg(feature = "dtls-pki")]
    Pki(pki_rpk::PkiRpkContext<'a, pki_rpk::Pki>),
    #[cfg(feature = "dtls-rpk")]
    Rpk(pki_rpk::PkiRpkContext<'a, pki_rpk::Rpk>),
}

impl<'a> From<psk::ClientPskContext<'a>> for ClientCryptoContext<'a> {
    fn from(value: psk::ClientPskContext<'a>) -> Self {
        ClientCryptoContext::Psk(value)
    }
}

#[cfg(feature = "dtls-pki")]
impl<'a> From<pki_rpk::PkiRpkContext<'a, pki_rpk::Pki>> for ClientCryptoContext<'a> {
    fn from(value: pki_rpk::PkiRpkContext<'a, pki_rpk::Pki>) -> Self {
        ClientCryptoContext::Pki(value)
    }
}

#[cfg(feature = "dtls-rpk")]
impl<'a> From<pki_rpk::PkiRpkContext<'a, pki_rpk::Rpk>> for ClientCryptoContext<'a> {
    fn from(value: pki_rpk::PkiRpkContext<'a, pki_rpk::Rpk>) -> Self {
        ClientCryptoContext::Rpk(value)
    }
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto.rs - CoAP cryptography provider interfaces and types.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Cryptography provider interfaces and types

pub(crate) mod pki_rpk;
pub mod psk;

use std::fmt::Debug;

use psk::ClientPskContext;

#[derive(Clone, Debug)]
pub enum ClientCryptoContext {
    #[cfg(feature = "dtls-psk")]
    Psk(ClientPskContext),
}

#[cfg(feature = "dtls-psk")]
impl From<ClientPskContext> for ClientCryptoContext {
    fn from(value: ClientPskContext) -> Self {
        ClientCryptoContext::Psk(value)
    }
}

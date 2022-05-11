// SPDX-License-Identifier: BSD-2-Clause
/*
 * event.rs - Event handling traits and logic for the libcoap Rust Wrapper.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use crate::context::CoapContext;
use crate::session::{CoapClientSession, CoapServerSession, CoapSession, CoapSessionCommon};
use crate::types::{CoapAppDataRef, FfiPassthroughRefContainer, FfiPassthroughWeakContainer};
use libcoap_sys::{coap_event_t, coap_session_get_context, coap_session_get_type, coap_session_t, coap_session_type_t};
use std::fmt::Debug;

/// Trait for CoAP event handlers.
///
/// Implementations of this trait can be provided to a CoapContext to handle various events relating
/// to sessions.
///
/// This is the equivalent to the [libcoap `coap_event_handler_t` type](https://libcoap.net/doc/reference/develop/group__events.html#ga5d57fba7df54eae6f8cb3a47a4cb3569).
pub trait CoapEventHandler: Debug {
    #[allow(unused_variables)]
    fn handle_dtls_connected(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_dtls_closed(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_dtls_renegotiate(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_dtls_error(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_tcp_connected(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_tcp_closed(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_tcp_failed(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_session_connected(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_session_closed(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_session_failed(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_partial_block(&mut self, session: &mut CoapSession) {}

    #[allow(unused_variables)]
    fn handle_server_session_new(&mut self, session: &mut CoapServerSession) {}

    #[allow(unused_variables)]
    fn handle_server_session_del(&mut self, session: &mut CoapServerSession) {}
}

pub(crate) unsafe extern "C" fn event_handler_callback(raw_session: *mut coap_session_t, event: coap_event_t) -> i32 {
    let mut session: CoapSession = if event == coap_event_t::COAP_EVENT_SERVER_SESSION_NEW {
        CoapServerSession::initialize_raw(raw_session).into()
    } else {
        CoapSession::from_raw(raw_session)
    };
    // SAFETY: Pointer is always valid as long as there is no bug in libcoap.
    let context = CoapContext::from_raw(coap_session_get_context(raw_session));
    context.handle_event(session, event);
    0
}

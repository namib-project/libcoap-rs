// SPDX-License-Identifier: BSD-2-Clause
/*
 * session/client.rs - Types relating to client-side CoAP sessions.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::{
    cell::{Ref, RefMut},
    net::SocketAddr,
};

#[cfg(feature = "oscore")]
use libcoap_sys::{coap_context_oscore_server, coap_new_client_session_oscore, coap_new_oscore_conf, coap_str_const_t};
use libcoap_sys::{
    coap_new_client_session, coap_proto_t_COAP_PROTO_DTLS, coap_proto_t_COAP_PROTO_TCP, coap_proto_t_COAP_PROTO_UDP,
    coap_register_event_handler, coap_session_get_app_data, coap_session_get_context, coap_session_get_type,
    coap_session_init_token, coap_session_release, coap_session_set_app_data, coap_session_t,
    coap_session_type_t_COAP_SESSION_TYPE_CLIENT, coap_session_type_t_COAP_SESSION_TYPE_HELLO,
    coap_session_type_t_COAP_SESSION_TYPE_NONE, coap_session_type_t_COAP_SESSION_TYPE_SERVER, COAP_TOKEN_DEFAULT_MAX,
};

use super::{CoapSessionCommon, CoapSessionInner, CoapSessionInnerProvider};
#[cfg(feature = "oscore")]
use crate::oscore::OscoreConf;
#[cfg(feature = "dtls")]
use crate::crypto::ClientCryptoContext;
use crate::{
    context::CoapContext,
    error::SessionCreationError,
    event::event_handler_callback,
    mem::{CoapFfiRcCell, DropInnerExclusively},
    prng::coap_prng_try_fill,
    types::CoapAddress,
};

#[derive(Debug)]
struct CoapClientSessionInner<'a> {
    inner: CoapSessionInner<'a>,
    #[cfg(feature = "dtls")]
    // This field is actually referred to be libcoap, so it isn't actually unused.
    #[allow(unused)]
    crypto_ctx: Option<ClientCryptoContext<'a>>,
}

impl<'a> CoapClientSessionInner<'a> {
    /// Initializes a new [`CoapClientSessionInner`] for an unencrypted session from its raw counterpart
    /// with the provided initial information.
    ///
    /// Also initializes the message token to a random value to prevent off-path response spoofing
    /// (see [RFC 7252, section 5.3.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.3.1)).
    ///
    /// # Safety
    /// The provided pointer for `raw_session` must be valid and point to the newly constructed raw
    /// session.
    unsafe fn new(raw_session: *mut coap_session_t) -> CoapFfiRcCell<CoapClientSessionInner<'a>> {
        // For insecure protocols, generate a random initial token to prevent off-path response
        // spoofing, see https://datatracker.ietf.org/doc/html/rfc7252#section-5.3.1
        let mut token = [0; COAP_TOKEN_DEFAULT_MAX as usize];
        coap_prng_try_fill(&mut token).expect("unable to generate random initial token");
        coap_session_init_token(raw_session, token.len(), token.as_ptr());

        let inner_session = CoapFfiRcCell::new(CoapClientSessionInner {
            inner: CoapSessionInner::new(raw_session),
            #[cfg(feature = "dtls")]
            crypto_ctx: None,
        });

        // SAFETY: raw session is valid, inner session pointer must be valid as it was just created
        // from one of Rust's smart pointers.
        coap_session_set_app_data(raw_session, inner_session.create_raw_weak());

        inner_session
    }

    /// Initializes a new [`CoapClientSessionInner`] for an encrypted session from its raw counterpart
    /// with the provided initial information.
    ///
    /// # Safety
    /// The provided pointer for `raw_session` must be valid and point to the newly constructed raw
    /// session.
    #[cfg(feature = "dtls")]
    unsafe fn new_with_crypto_ctx(
        raw_session: *mut coap_session_t,
        crypto_ctx: ClientCryptoContext<'a>,
    ) -> CoapFfiRcCell<CoapClientSessionInner<'a>> {
        let inner_session = CoapFfiRcCell::new(CoapClientSessionInner {
            inner: CoapSessionInner::new(raw_session),
            crypto_ctx: Some(crypto_ctx),
        });

        // SAFETY: raw session is valid, inner session pointer must be valid as it was just created
        // from one of Rust's smart pointers.
        coap_session_set_app_data(raw_session, inner_session.create_raw_weak());

        inner_session
    }
}

/// Representation of a client-side CoAP session.
#[derive(Debug, Clone)]
pub struct CoapClientSession<'a> {
    inner: CoapFfiRcCell<CoapClientSessionInner<'a>>,
}

impl CoapClientSession<'_> {
    /// Create a new DTLS encrypted session with the given peer `addr` using the given `crypto_ctx`.
    ///
    /// # Errors
    /// Will return a [SessionCreationError] if libcoap was unable to create a session (most likely
    /// because it was not possible to bind to a port).
    #[cfg(feature = "dtls")]
    pub fn connect_dtls<'a>(
        ctx: &mut CoapContext<'a>,
        addr: SocketAddr,
        crypto_ctx: impl Into<ClientCryptoContext<'a>>,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        let crypto_ctx = crypto_ctx.into();
        // SAFETY: The returned raw session lives for as long as the constructed
        // CoapClientSessionInner does, which is limited to the lifetime of crypto_ctx.
        // When the CoapClientSessionInner instance is dropped, the session is dropped before the
        // crypto context is.
        let raw_session = unsafe {
            match &crypto_ctx {
                #[cfg(feature = "dtls-psk")]
                ClientCryptoContext::Psk(psk_ctx) => {
                    psk_ctx.create_raw_session(ctx, &addr.into(), coap_proto_t_COAP_PROTO_DTLS)?
                },
                #[cfg(feature = "dtls-pki")]
                ClientCryptoContext::Pki(pki_ctx) => {
                    pki_ctx.create_raw_session(ctx, &addr.into(), coap_proto_t_COAP_PROTO_DTLS)?
                },
                #[cfg(feature = "dtls-rpk")]
                ClientCryptoContext::Rpk(rpk_ctx) => {
                    rpk_ctx.create_raw_session(ctx, &addr.into(), coap_proto_t_COAP_PROTO_DTLS)?
                },
            }
        };

        // SAFETY: raw_session was just checked to be valid pointer.
        Ok(CoapClientSession {
            inner: unsafe { CoapClientSessionInner::new_with_crypto_ctx(raw_session.as_ptr(), crypto_ctx) },
        })
    }

    /// Create a new unencrypted session with the given peer over UDP.
    ///
    /// # Errors
    /// Will return a [SessionCreationError] if libcoap was unable to create a session (most likely
    /// because it was not possible to bind to a port).
    pub fn connect_udp<'a>(
        ctx: &mut CoapContext<'a>,
        addr: SocketAddr,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null.
        let session = unsafe {
            coap_new_client_session(
                ctx.as_mut_raw_context(),
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                coap_proto_t_COAP_PROTO_UDP,
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // SAFETY: Session was just checked for validity.
        Ok(CoapClientSession {
            inner: unsafe { CoapClientSessionInner::new(session) },
        })
    }

    /// Create a new unencrypted session with the given peer over TCP.
    ///
    /// # Errors
    /// Will return a [SessionCreationError] if libcoap was unable to create a session (most likely
    /// because it was not possible to bind to a port).
    pub fn connect_tcp<'a>(
        ctx: &mut CoapContext<'a>,
        addr: SocketAddr,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null.
        let session = unsafe {
            coap_new_client_session(
                ctx.as_mut_raw_context(),
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                coap_proto_t_COAP_PROTO_TCP,
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // SAFETY: Session was just checked for validity.
        Ok(CoapClientSession {
            inner: unsafe { CoapClientSessionInner::new(session) },
        })
    }

    /// Create an encrypted session with the given peer over UDP using OSCORE
    ///
    /// Will return a [SessionCreationError] if libcoap was unable to create a session
    /// (most likely because it was not possible to bind to a port).
    #[cfg(feature = "oscore")]
    pub fn connect_oscore<'a>(
        ctx: &mut CoapContext<'a>,
        addr: SocketAddr,
        conf: OscoreConf,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        // TODO: SAFETY
        let session = unsafe {
            coap_new_client_session_oscore(
                ctx.as_mut_raw_context(),
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                coap_proto_t_COAP_PROTO_UDP,
                OscoreConf::from(conf).as_mut_raw_conf(),
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // TODO: SAFETY
        Ok(CoapClientSession {
            inner: unsafe { CoapClientSessionInner::new(session) },
        })
    }

    /// Restores a [CoapClientSession] from its raw counterpart.
    ///
    /// Note that it is not possible to statically infer the lifetime of the created session from
    /// the raw pointer, i.e., the session will be created with an arbitrary lifetime.
    /// Therefore, callers of this function should ensure that the created session instance does not
    /// outlive the context it is bound to.
    /// Failing to do so will result in a panic/abort in the context destructor as it is unable to
    /// claim exclusive ownership of the client session.
    ///
    /// # Panics
    ///
    /// Panics if the given pointer is a null pointer or the raw session is not a client-side
    /// session with app data.
    ///
    /// # Safety
    /// The provided pointer must be valid, the provided session's app data must be a valid argument
    /// to [`CoapFfiRawCell<CoapClientSessionInner>::clone_raw_rc`].
    pub(crate) unsafe fn from_raw<'a>(raw_session: *mut coap_session_t) -> CoapClientSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        // Variant names are named by bindgen, we have no influence on this.
        // Ref: https://github.com/rust-lang/rust/issues/39371
        #[allow(non_upper_case_globals)]
        match raw_session_type {
            coap_session_type_t_COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t_COAP_SESSION_TYPE_CLIENT => {
                let raw_app_data_ptr = coap_session_get_app_data(raw_session);
                assert!(!raw_app_data_ptr.is_null(), "provided raw session has no app data");
                let inner = CoapFfiRcCell::clone_raw_rc(raw_app_data_ptr);
                CoapClientSession { inner }
            },
            coap_session_type_t_COAP_SESSION_TYPE_SERVER | coap_session_type_t_COAP_SESSION_TYPE_HELLO => {
                panic!("attempted to create CoapClientSession from raw server session")
            },
            _ => unreachable!("unknown session type"),
        }
    }
}

impl DropInnerExclusively for CoapClientSession<'_> {
    fn drop_exclusively(self) {
        self.inner.drop_exclusively();
    }
}

impl Drop for CoapClientSessionInner<'_> {
    fn drop(&mut self) {
        // SAFETY:
        // - raw_session is always valid as long as we are not dropped yet (as this is the only
        //   function that calls coap_session_release on client-side sessions).
        // - Application data validity is asserted.
        // - For event handling access, see later comment.
        unsafe {
            let app_data = coap_session_get_app_data(self.inner.raw_session);
            assert!(!app_data.is_null());
            // Recreate weak pointer instance so that it can be dropped (which in turn reduces the
            // weak reference count, avoiding memory leaks).
            CoapFfiRcCell::<CoapClientSessionInner>::raw_ptr_to_weak(app_data);
            // We need to temporarily disable event handling so that our own event handler does not
            // access this already partially invalid session (and recursively also calls this Drop
            // implementation), causing a SIGABRT.
            // This is fine, because:
            // - While this destructor is called, nothing is concurrently accessing the raw context
            //   (as libcoap is single-threaded and all types are !Send)
            // - The only way this could be problematic would be if libcoap assumed sessions to be
            //   unchanging during a call to coap_io_process. However, this would be considered a
            //   bug in libcoap (as the documentation does not explicitly forbid this AFAIK).
            let raw_context = coap_session_get_context(self.inner.raw_session);
            assert!(!raw_context.is_null());
            coap_register_event_handler(raw_context, None);
            // Let libcoap do its cleanup of the raw session and free the associated memory.
            coap_session_release(self.inner.raw_session);
            // Restore event handler.
            coap_register_event_handler(raw_context, Some(event_handler_callback));
        }
    }
}

impl<'a> CoapSessionInnerProvider<'a> for CoapClientSession<'a> {
    fn inner_ref<'b>(&'b self) -> Ref<'b, CoapSessionInner<'a>> {
        Ref::map(self.inner.borrow(), |v| &v.inner)
    }

    fn inner_mut<'b>(&'b self) -> RefMut<'b, CoapSessionInner<'a>> {
        RefMut::map(self.inner.borrow_mut(), |v| &mut v.inner)
    }
}

impl<'a, T: CoapSessionCommon<'a>> PartialEq<T> for CoapClientSession<'_> {
    fn eq(&self, other: &T) -> bool {
        // SAFETY: Pointers are only compared, never accessed.
        self.if_index() == other.if_index()
            && unsafe { self.raw_session() == other.raw_session() }
            && self.addr_local() == other.addr_local()
            && self.addr_remote() == other.addr_remote()
    }
}

impl Eq for CoapClientSession<'_> {}

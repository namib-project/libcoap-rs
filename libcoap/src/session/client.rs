// SPDX-License-Identifier: BSD-2-Clause
/*
 * session/client.rs - Types relating to client-side CoAP sessions.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::cell::{Ref, RefMut};
use std::net::SocketAddr;

use libcoap_sys::{
    coap_bin_const_t, coap_dtls_cpsk_info_t, coap_dtls_cpsk_t, coap_new_client_session, coap_new_client_session_psk2,
    coap_proto_t, coap_register_event_handler, coap_session_get_app_data, coap_session_get_context,
    coap_session_get_type, coap_session_release, coap_session_set_app_data, coap_session_t, coap_session_type_t,
    COAP_DTLS_SPSK_SETUP_VERSION,
};

#[cfg(feature = "dtls")]
use crate::crypto::{
    dtls_ih_callback, CoapClientCryptoProvider, CoapCryptoProviderResponse, CoapCryptoPskIdentity, CoapCryptoPskInfo,
};
use crate::event::event_handler_callback;
use crate::mem::{CoapFfiRcCell, DropInnerExclusively};
use crate::{context::CoapContext, error::SessionCreationError, types::CoapAddress};

use super::{CoapSessionCommon, CoapSessionInner, CoapSessionInnerProvider};

#[derive(Debug)]
struct CoapClientSessionInner<'a> {
    inner: CoapSessionInner<'a>,
    #[cfg(feature = "dtls")]
    crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>,
    #[cfg(feature = "dtls")]
    crypto_current_data: Option<CoapCryptoPskInfo>,
    // coap_dtls_cpsk_info_t created upon calling dtls_client_ih_callback().
    // The caller of the callback will make a defensive copy, so this one only has
    // to be valid for a very short time and can always be overridden.
    #[cfg(feature = "dtls")]
    crypto_last_info_ref: coap_dtls_cpsk_info_t,
}

/// Representation of a client-side CoAP session.
#[derive(Debug, Clone)]
pub struct CoapClientSession<'a> {
    inner: CoapFfiRcCell<CoapClientSessionInner<'a>>,
}

impl CoapClientSession<'_> {
    /// Create a new DTLS encrypted session with the given peer.
    ///
    /// To supply cryptographic information (like PSK hints or key data), you have to provide a
    /// struct implementing [CoapClientCryptoProvider].
    ///
    /// # Errors
    /// Will return a [SessionCreationError] if libcoap was unable to create a session (most likely
    /// because it was not possible to bind to a port).
    #[cfg(feature = "dtls")]
    pub fn connect_dtls<'a, P: 'static + CoapClientCryptoProvider>(
        ctx: &mut CoapContext<'a>,
        addr: SocketAddr,
        mut crypto_provider: P,
    ) -> Result<CoapClientSession<'a>, SessionCreationError> {
        // Get default identity.
        let id = crypto_provider.provide_default_info();
        let client_setup_data = Box::into_raw(Box::new(coap_dtls_cpsk_t {
            version: COAP_DTLS_SPSK_SETUP_VERSION as u8,
            reserved: [0; 7],
            validate_ih_call_back: {
                // Unsupported by MbedTLS
                #[cfg(not(feature = "dtls_mbedtls"))]
                {
                    Some(dtls_ih_callback)
                }
                #[cfg(feature = "dtls_mbedtls")]
                {
                    None
                }
            },
            ih_call_back_arg: std::ptr::null_mut(),
            client_sni: std::ptr::null_mut(),
            psk_info: coap_dtls_cpsk_info_t {
                identity: coap_bin_const_t {
                    length: id.identity.len(),
                    s: id.identity.as_ptr(),
                },
                key: coap_bin_const_t {
                    length: id.key.len(),
                    s: id.key.as_ptr(),
                },
            },
        }));
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null, constructed
        // coap_dtls_cpsk_t is of valid format and has no out-of-bounds issues.
        let raw_session = unsafe {
            coap_new_client_session_psk2(
                ctx.as_mut_raw_context(),
                std::ptr::null(),
                CoapAddress::from(addr).as_raw_address(),
                coap_proto_t::COAP_PROTO_DTLS,
                client_setup_data,
            )
        };

        if raw_session.is_null() {
            return Err(SessionCreationError::Unknown);
        }

        // SAFETY: raw_session was just checked, crypto_current_data is data provided to
        // coap_new_client_session_psk2().
        Ok(unsafe { CoapClientSession::new(raw_session, Some(id), Some(Box::new(crypto_provider))) })
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
                coap_proto_t::COAP_PROTO_UDP,
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // SAFETY: Session was just checked for validity, no crypto info was provided to
        // coap_new_client_session().
        Ok(unsafe {
            CoapClientSession::new(
                session as *mut coap_session_t,
                #[cfg(feature = "dtls")]
                None,
                #[cfg(feature = "dtls")]
                None,
            )
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
                coap_proto_t::COAP_PROTO_TCP,
            )
        };
        if session.is_null() {
            return Err(SessionCreationError::Unknown);
        }
        // SAFETY: Session was just checked for validity, no crypto info was provided to
        // coap_new_client_session().
        Ok(unsafe {
            CoapClientSession::new(
                session as *mut coap_session_t,
                #[cfg(feature = "dtls")]
                None,
                #[cfg(feature = "dtls")]
                None,
            )
        })
    }

    /// Initializes a new CoapClientSession from its raw counterpart with the provided initial
    /// information.
    ///
    /// # Safety
    /// The provided pointer for `raw_session` must be valid and point to the newly constructed raw
    /// session.
    ///
    /// The provided value for `crypto_current_data` must be the one whose memory pointers were used
    /// when calling `coap_new_client_session_*` (if any was provided).
    unsafe fn new<'a>(
        raw_session: *mut coap_session_t,
        #[cfg(feature = "dtls")] crypto_current_data: Option<CoapCryptoPskInfo>,
        #[cfg(feature = "dtls")] crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>,
    ) -> CoapClientSession<'a> {
        let inner_session = CoapFfiRcCell::new(CoapClientSessionInner {
            inner: CoapSessionInner::new(raw_session),
            #[cfg(feature = "dtls")]
            crypto_provider,
            #[cfg(feature = "dtls")]
            crypto_current_data,
            #[cfg(feature = "dtls")]
            crypto_last_info_ref: coap_dtls_cpsk_info_t {
                identity: coap_bin_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
                key: coap_bin_const_t {
                    length: 0,
                    s: std::ptr::null(),
                },
            },
        });

        let client_session = CoapClientSession {
            inner: inner_session.clone(),
        };
        // SAFETY: raw session is valid, inner session pointer must be valid as it was just created
        // from one of Rusts smart pointers.
        coap_session_set_app_data(raw_session, inner_session.create_raw_weak());

        client_session
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
    /// Panics if the given pointer is a null pointer or the raw session is not a client-side
    /// session with app data.
    ///
    /// # Safety
    /// The provided pointer must be valid.
    pub(crate) unsafe fn from_raw<'a>(raw_session: *mut coap_session_t) -> CoapClientSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        match raw_session_type {
            coap_session_type_t::COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t::COAP_SESSION_TYPE_CLIENT => {
                let raw_app_data_ptr = coap_session_get_app_data(raw_session);
                assert!(!raw_app_data_ptr.is_null(), "provided raw session has no app data");
                let inner = CoapFfiRcCell::clone_raw_rc(raw_app_data_ptr);
                CoapClientSession { inner }
            },
            coap_session_type_t::COAP_SESSION_TYPE_SERVER | coap_session_type_t::COAP_SESSION_TYPE_HELLO => {
                panic!("attempted to create CoapClientSession from raw server session")
            },
            _ => unreachable!("unknown session type"),
        }
    }

    /// Sets the provider for cryptographic information for this session.
    #[cfg(feature = "dtls")]
    pub fn set_crypto_provider(&mut self, crypto_provider: Option<Box<dyn CoapClientCryptoProvider>>) {
        self.inner.borrow_mut().crypto_provider = crypto_provider;
    }

    #[cfg(feature = "dtls")]
    pub(crate) fn provide_raw_key_for_hint(
        &mut self,
        hint: &CoapCryptoPskIdentity,
    ) -> Option<*const coap_dtls_cpsk_info_t> {
        let inner_ref = &mut *self.inner.borrow_mut();

        match inner_ref.crypto_provider.as_mut().map(|v| v.provide_key_for_hint(hint)) {
            Some(CoapCryptoProviderResponse::UseNew(new_data)) => {
                inner_ref.crypto_current_data = Some(CoapCryptoPskInfo {
                    identity: Box::from(hint),
                    key: new_data,
                });
                inner_ref
                    .crypto_current_data
                    .as_ref()
                    .unwrap()
                    .apply_to_cpsk_info(&mut inner_ref.crypto_last_info_ref);
                Some(&inner_ref.crypto_last_info_ref as *const coap_dtls_cpsk_info_t)
            },
            Some(CoapCryptoProviderResponse::UseCurrent) => {
                if inner_ref.crypto_current_data.is_some() {
                    inner_ref
                        .crypto_current_data
                        .as_ref()
                        .unwrap()
                        .apply_to_cpsk_info(&mut inner_ref.crypto_last_info_ref);
                    Some(&inner_ref.crypto_last_info_ref as *const coap_dtls_cpsk_info_t)
                } else {
                    None
                }
            },
            None | Some(CoapCryptoProviderResponse::Unacceptable) => None,
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

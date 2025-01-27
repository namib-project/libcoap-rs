// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * session/server.rs - Types relating to client-side CoAP sessions.
 */

use std::cell::{Ref, RefMut};

use libcoap_sys::{
    coap_session_get_app_data, coap_session_get_type, coap_session_reference, coap_session_release,
    coap_session_set_app_data, coap_session_t, coap_session_type_t_COAP_SESSION_TYPE_CLIENT,
    coap_session_type_t_COAP_SESSION_TYPE_HELLO, coap_session_type_t_COAP_SESSION_TYPE_NONE,
    coap_session_type_t_COAP_SESSION_TYPE_SERVER,
};

use super::{CoapSessionCommon, CoapSessionInner, CoapSessionInnerProvider};
use crate::mem::{CoapFfiRcCell, DropInnerExclusively};

impl DropInnerExclusively for CoapServerSession<'_> {
    fn drop_exclusively(self) {
        let sess_ref = self.inner.clone();
        std::mem::drop(self);
        sess_ref.drop_exclusively();
    }
}

/// Representation of a server-side CoAP session.
#[derive(Debug, Clone)]
pub struct CoapServerSession<'a> {
    /// Inner part of this server-side session
    /// A weak version of this reference is stored inside of the user/app data pointer in the
    /// raw session struct so that it can be passed through the FFI barrier.
    inner: CoapFfiRcCell<CoapServerSessionInner<'a>>,
    ref_counted: bool,
}

#[derive(Debug)]
/// Inner part of a server-side CoAP session.
struct CoapServerSessionInner<'a> {
    inner: CoapSessionInner<'a>,
}

impl CoapServerSession<'_> {
    /// Creates a CoapServerSession from a raw session.
    ///
    /// This function will increment the libcoap-internal reference counter for the session by one.
    /// Dropping the CoapServerSession will then decrement it again.
    ///
    /// # Panics
    /// Panics if the given pointer is a null pointer or the raw session is not a server-side
    /// session.
    ///
    /// # Safety
    /// The provided pointer must be valid for the entire (here arbitrarily chosen) lifetime of the
    /// CoapServerSession<'a>, most notably the program will abort if the [CoapContext] is dropped
    /// before this session is.
    /// The existing value in the `app_data` field of the raw session will be overridden.
    /// Make sure that this is actually okay to do so — most importantly, no other [CoapSession] may
    /// already be stored there.
    ///
    /// If you wish to restore an existing [CoapSession] from its raw counterpart, use
    /// [from_raw()](CoapServerSession::from_raw) instead.
    pub(crate) unsafe fn initialize_raw<'a>(raw_session: *mut coap_session_t) -> CoapServerSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        let inner = CoapSessionInner::new(raw_session);
        // Variant names are named by bindgen, we have no influence on this.
        // Ref: https://github.com/rust-lang/rust/issues/39371
        #[allow(non_upper_case_globals)]
        let session_inner = match raw_session_type {
            coap_session_type_t_COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t_COAP_SESSION_TYPE_CLIENT => {
                panic!("attempted to create server session from raw client session")
            },
            coap_session_type_t_COAP_SESSION_TYPE_SERVER => CoapServerSessionInner { inner },
            coap_session_type_t_COAP_SESSION_TYPE_HELLO => CoapServerSessionInner { inner },
            _ => unreachable!("unknown session type"),
        };
        let session_ref = CoapFfiRcCell::new(session_inner);
        coap_session_set_app_data(raw_session, session_ref.create_raw_weak());
        // Increase libcoap-internal reference counter for raw session so that it doesn't get freed
        // as long as this CoapServerSession instance exists.
        coap_session_reference(raw_session);
        CoapServerSession {
            inner: session_ref,
            ref_counted: true,
        }
    }

    /// Restores a [CoapServerSession] from its raw counterpart.
    ///
    /// Make sure that this struct cannot outlive the [CoapContext] its session originates from, as
    /// the lifetime cannot be inferred by the compiler and dropping the context will panic/abort if
    /// the inner session is still referenced anywhere else.
    ///
    /// This function will increment the libcoap-internal reference counter for the session by one.
    /// Dropping the CoapServerSession will then decrement it again.
    ///
    /// # Panics
    /// Panics if the provided raw session pointer or its app_data field is null or the raw session
    /// is not a server-side session.
    ///
    /// # Safety
    /// The provided pointer must be valid for the entire lifetime of this struct.
    /// The provided session's app data must be a valid argument to
    /// [`CoapFfiRcCell<CoapServerSessionInner>::clone_raw_rc`](CoapFfiRcCell::clone_raw_rc).
    pub(crate) unsafe fn from_raw<'a>(raw_session: *mut coap_session_t) -> CoapServerSession<'a> {
        let mut session = Self::from_raw_without_refcount(raw_session);
        coap_session_reference(raw_session);
        session.ref_counted = true;
        session
    }

    /// Restores a [CoapServerSession] from its raw counterpart without increasing its reference
    /// counter (useful if acquiring libcoap's global lock is undesired).
    ///
    /// Make sure that this struct cannot outlive the [CoapContext] its session originates from, as
    /// the lifetime cannot be inferred by the compiler and dropping the context will panic/abort if
    /// the inner session is still referenced anywhere else.
    ///
    /// In addition to the above, you must also ensure that the session will not be cleaned up by
    /// libcoap in the meantime, as the reference counter is not increased while constructing the
    /// instance.
    ///
    /// This function will increment the libcoap-internal reference counter for the session by one.
    /// Dropping the CoapServerSession will then decrement it again.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw session pointer or its app_data field is null or the raw session
    /// is not a server-side session.
    ///
    /// # Safety
    /// The provided pointer must be valid for the entire lifetime of this struct.
    ///
    /// This also implies that libcoap *must not* clean up this session during the lifetime of this
    /// struct, which could happen at any time if the libcoap context is not locked.
    ///
    /// The provided session's app data must be a valid argument to
    /// [`CoapFfiRcCell<CoapServerSessionInner>::clone_raw_rc`](CoapFfiRcCell::clone_raw_rc).
    pub(crate) unsafe fn from_raw_without_refcount<'a>(raw_session: *mut coap_session_t) -> CoapServerSession<'a> {
        assert!(!raw_session.is_null(), "provided raw session was null");
        let raw_session_type = coap_session_get_type(raw_session);
        // Variant names are named by bindgen, we have no influence on this.
        // Ref: https://github.com/rust-lang/rust/issues/39371
        #[allow(non_upper_case_globals)]
        match raw_session_type {
            coap_session_type_t_COAP_SESSION_TYPE_NONE => panic!("provided session has no type"),
            coap_session_type_t_COAP_SESSION_TYPE_SERVER | coap_session_type_t_COAP_SESSION_TYPE_HELLO => {
                let raw_app_data_ptr = coap_session_get_app_data(raw_session);
                assert!(!raw_app_data_ptr.is_null(), "provided raw session has no app data");
                CoapServerSession {
                    inner: CoapFfiRcCell::clone_raw_rc(raw_app_data_ptr),
                    ref_counted: false,
                }
            },
            coap_session_type_t_COAP_SESSION_TYPE_CLIENT => {
                panic!("attempted to create CoapServerSession from raw client session")
            },
            _ => unreachable!("unknown session type"),
        }
    }
}

impl<'a> Drop for CoapServerSession<'a> {
    fn drop(&mut self) {
        let raw_session = self.inner.borrow_mut().inner.raw_session;
        // Decrease libcoap-internal reference counter for raw session so that we don't leak memory
        // if we previously incremented the reference count.
        if self.ref_counted {
            // SAFETY: raw_session is always valid for the lifetime of this object.
            unsafe {
                coap_session_release(raw_session);
            }
        }
    }
}

impl<'a> CoapSessionInnerProvider<'a> for CoapServerSession<'a> {
    fn inner_ref<'b>(&'b self) -> Ref<'b, CoapSessionInner<'a>> {
        Ref::map(self.inner.borrow(), |v| &v.inner)
    }

    fn inner_mut<'b>(&'b self) -> RefMut<'b, CoapSessionInner<'a>> {
        RefMut::map(self.inner.borrow_mut(), |v| &mut v.inner)
    }
}

impl<'a, T: CoapSessionCommon<'a>> PartialEq<T> for CoapServerSession<'_> {
    fn eq(&self, other: &T) -> bool {
        // SAFETY: Pointers are only compared, never accessed.
        self.if_index() == other.if_index()
            && unsafe { self.raw_session() == other.raw_session() }
            && self.addr_local() == other.addr_local()
            && self.addr_remote() == other.addr_remote()
    }
}

impl Eq for CoapServerSession<'_> {}

impl Drop for CoapServerSessionInner<'_> {
    fn drop(&mut self) {
        unsafe {
            let app_data = coap_session_get_app_data(self.inner.raw_session);
            assert!(!app_data.is_null());
            std::mem::drop(CoapFfiRcCell::<CoapServerSessionInner>::raw_ptr_to_weak(app_data));
        }
    }
}

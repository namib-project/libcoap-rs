// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto/psk/server.rs - Interfaces and types for server-side PSK support in libcoap-rs.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use crate::crypto::psk::key::PskKey;
use crate::error::ContextConfigurationError;
use crate::session::CoapServerSession;
use libcoap_sys::{
    coap_bin_const_t, coap_context_set_psk2, coap_context_t, coap_dtls_spsk_info_t, coap_dtls_spsk_t, coap_session_t,
    COAP_DTLS_SPSK_SETUP_VERSION,
};
use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_void, CStr};
use std::fmt::Debug;
use std::hash::Hash;
use std::os::raw::c_char;
use std::ptr::NonNull;
use std::rc::{Rc, Weak};

/// Builder for a server-side DTLS encryption context for use with pre-shared keys (PSK).
#[derive(Debug)]
pub struct ServerPskContextBuilder<'a> {
    ctx: ServerPskContextInner<'a>,
}

impl<'a> ServerPskContextBuilder<'a> {
    /// Creates a new context builder with the given `key` as the default key to use.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Providing a raw public key will set `psk_info` to the provided key in the underlying
    /// [`coap_dtls_spsk_t`] structure.
    pub fn new(key: PskKey<'a>) -> Self {
        Self {
            ctx: ServerPskContextInner {
                id_key_provider: None,
                sni_key_provider: None,
                provided_keys: Vec::new(),
                raw_cfg: Box::new(coap_dtls_spsk_t {
                    version: COAP_DTLS_SPSK_SETUP_VERSION as u8,
                    reserved: Default::default(),
                    #[cfg(dtls_ec_jpake_support)]
                    ec_jpake: 0,
                    validate_id_call_back: None,
                    id_call_back_arg: std::ptr::null_mut(),
                    validate_sni_call_back: None,
                    sni_call_back_arg: std::ptr::null_mut(),
                    psk_info: key.into_raw_spsk_info(),
                }),
            },
        }
    }

    /// Sets the key provider that provides a PSK for a given identity.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Setting a `id_key_provider` will set the `validate_id_call_back` of the underlying
    /// [`coap_dtls_spsk_t`] to a wrapper function, which will then call the key provider.
    pub fn id_key_provider(mut self, id_key_provider: impl ServerPskIdentityKeyProvider<'a> + 'a) -> Self {
        self.ctx.id_key_provider = Some(Box::new(id_key_provider));
        self.ctx.raw_cfg.validate_id_call_back = Some(dtls_psk_server_id_callback);
        self
    }

    /// Sets the key provider that provides keys for a SNI provided by a client.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Setting a `sni_key_provider` will set the `validate_sni_call_back` of the underlying
    /// [`coap_dtls_spsk_t`] to a wrapper function, which will then call the key provider.
    ///
    /// Keys returned by the key provider will be stored in the context for at least as long as they
    /// are used by the respective session.
    pub fn sni_key_provider(mut self, sni_key_provider: impl ServerPskSniKeyProvider<'a> + 'a) -> Self {
        self.ctx.sni_key_provider = Some(Box::new(sni_key_provider));
        self.ctx.raw_cfg.validate_sni_call_back = Some(dtls_psk_server_sni_callback);
        self
    }

    /// Consumes this builder to construct the resulting PSK context.
    pub fn build(self) -> ServerPskContext<'a> {
        let ctx = Rc::new(RefCell::new(self.ctx));
        {
            let mut ctx_borrow = ctx.borrow_mut();
            if ctx_borrow.raw_cfg.validate_id_call_back.is_some() {
                ctx_borrow.raw_cfg.id_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void
            }
            if ctx_borrow.raw_cfg.validate_sni_call_back.is_some() {
                ctx_borrow.raw_cfg.sni_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void
            }
        }
        ServerPskContext { inner: ctx }
    }
}

impl ServerPskContextBuilder<'_> {
    /// Enables or disables support for EC JPAKE ([RFC 8236](https://datatracker.ietf.org/doc/html/rfc8236))
    /// key exchanges in (D)TLS.
    ///
    /// # Implementation details (informative, not covered by semver guarantees)
    ///
    /// Equivalent to setting `ec_jpake` in the underlying [`coap_dtls_spsk_t`] structure.
    #[cfg(dtls_ec_jpake_support)]
    pub fn ec_jpake(mut self, ec_jpake: bool) -> Self {
        self.ctx.raw_cfg.ec_jpake = if ec_jpake { 1 } else { 0 };
        self
    }
}

#[derive(Debug)]
struct ServerPskContextInner<'a> {
    /// Raw configuration object.
    raw_cfg: Box<coap_dtls_spsk_t>,
    /// Store for `coap_dtls_spsk_info_t` instances that we provided in previous SNI or ID
    /// callback invocations.
    ///
    /// The stored pointers *must* all be created from Box::into_raw().
    ///
    /// Using `Vec<coap_dtls_spsk_info_t>` instead is not an option, as a Vec resize may cause the
    /// instances to be moved to a different place in memory, invalidating pointers provided to
    /// libcoap.
    provided_keys: Vec<*mut coap_dtls_spsk_info_t>,
    /// User-supplied SNI key provider.
    sni_key_provider: Option<Box<dyn ServerPskSniKeyProvider<'a> + 'a>>,
    /// User-supplied identity key provider.
    id_key_provider: Option<Box<dyn ServerPskIdentityKeyProvider<'a> + 'a>>,
}

impl Drop for ServerPskContextInner<'_> {
    fn drop(&mut self) {
        for provided_key in std::mem::take(&mut self.provided_keys).into_iter() {
            // SAFETY: Vector has only ever been filled by instances created from to_raw_spsk_info.
            unsafe {
                PskKey::from_raw_spsk_info(*Box::from_raw(provided_key));
            }
        }
        if !self.raw_cfg.id_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been a call to Weak::into_raw with the correct
            //         type.
            unsafe {
                Weak::from_raw(self.raw_cfg.id_call_back_arg as *mut Self);
            }
        }
        if !self.raw_cfg.sni_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been a call to Weak::into_raw with the correct
            //         type.
            unsafe {
                Weak::from_raw(self.raw_cfg.sni_call_back_arg as *mut Self);
            }
        }
        unsafe {
            // SAFETY: Pointer should not have been changed by anything else and refers to a CPSK
            //         info instance created from DtlsPsk::into_raw_cpsk_info().
            PskKey::from_raw_spsk_info(self.raw_cfg.psk_info);
        }
    }
}

/// Server-side encryption context for PSK-based (D)TLS sessions.
#[derive(Clone, Debug)]
pub struct ServerPskContext<'a> {
    /// Inner structure of this context.
    inner: Rc<RefCell<ServerPskContextInner<'a>>>,
}

impl ServerPskContext<'_> {
    /// Returns a pointer to the PSK key data to use for a given `identity` and `session`, or
    /// [`std::ptr::null()`] if the provided identity hint and/or session are unacceptable.
    ///
    /// The returned pointer is guaranteed to remain valid as long as the underlying
    /// [`ServerPskContextInner`] is not dropped.
    /// As the [`ServerPskContext`] is also stored in the [`CoapServerSession`] instance, this
    /// implies that the pointer is valid for at least as long as the session is.
    ///
    /// **Important:** After the underlying [`ServerPskContextInner`] is dropped, the returned
    /// pointer will no longer be valid and should no longer be dereferenced.
    fn id_callback(&self, identity: &[u8], session: &CoapServerSession<'_>) -> *const coap_bin_const_t {
        let mut inner = (*self.inner).borrow_mut();
        let key = inner
            .id_key_provider
            .as_ref()
            .unwrap()
            .key_for_identity(identity, session);

        if let Some(key) = key {
            let boxed_key_info = Box::new(key.into_raw_spsk_info());
            let boxed_key_ptr = Box::into_raw(boxed_key_info);
            // TODO remove these entries prematurely if the underlying session is removed (would
            //      require modifications to the event handler).
            inner.provided_keys.push(boxed_key_ptr);
            // SAFETY: Pointer is obviously valid.
            &unsafe { *boxed_key_ptr }.key
        } else {
            std::ptr::null()
        }
    }

    /// Returns a pointer to the PSK (potentially with identity hint) to use for a given `sni` (and
    /// `session`), or [`std::ptr::null()`] if the provided identity hint and/or session are
    /// unacceptable.
    ///
    /// The returned pointer is guaranteed to remain valid as long as the underlying
    /// [`ServerPskContextInner`] is not dropped.
    /// As the [`ServerPskContext`] is also stored in the [`CoapServerSession`] instance, this
    /// implies that the pointer is valid for at least as long as the session is.
    ///
    /// **Important:** After the underlying [`ServerPskContextInner`] is dropped, the returned
    /// pointer will no longer be valid and should no longer be dereferenced.
    fn sni_callback(&self, sni: &CStr, session: &CoapServerSession<'_>) -> *const coap_dtls_spsk_info_t {
        let mut inner = (*self.inner).borrow_mut();
        let key = inner.sni_key_provider.as_ref().unwrap().key_for_sni(sni, session);

        if let Some(key) = key {
            let boxed_key_info = Box::new(key.into_raw_spsk_info());
            let boxed_key_ptr = Box::into_raw(boxed_key_info);
            inner.provided_keys.push(boxed_key_ptr);
            // SAFETY: Pointer is obviously valid.
            boxed_key_ptr
        } else {
            std::ptr::null()
        }
    }

    /// Applies this encryption configuration to the given raw `coap_context_t`.
    ///
    /// # Safety
    /// This [ServerPskContext] must outlive the provided CoAP context, the provided pointer must be
    /// valid.
    pub(crate) unsafe fn apply_to_context(
        &self,
        mut ctx: NonNull<coap_context_t>,
    ) -> Result<(), ContextConfigurationError> {
        let mut inner = self.inner.borrow_mut();
        // SAFETY: context is valid as per caller contract, raw_cfg is a valid configuration as
        // ensured by the builder.
        match unsafe { coap_context_set_psk2(ctx.as_mut(), inner.raw_cfg.as_mut()) } {
            1 => Ok(()),
            _ => Err(ContextConfigurationError::Unknown),
        }
    }
}

impl<'a> ServerPskContext<'a> {
    /// Restores a [`ServerPskContext`] from a pointer to its inner structure (i.e. from the
    /// user-provided pointer given to DTLS callbacks).
    ///
    /// # Panics
    ///
    /// Panics if the given pointer is a null pointer or the inner structure was already dropped.
    ///
    /// # Safety
    /// The provided pointer must be a valid reference to a [`RefCell<ServerPskContextInner>`]
    /// instance created from a call to [`Weak::into_raw()`].
    unsafe fn from_raw(raw_ctx: *const RefCell<ServerPskContextInner<'a>>) -> Self {
        assert!(!raw_ctx.is_null(), "provided raw DTLS PSK server context was null");
        let inner_weak = Weak::from_raw(raw_ctx);
        let inner = inner_weak
            .upgrade()
            .expect("provided DTLS PSK server context was already dropped!");
        let _ = Weak::into_raw(inner_weak);
        ServerPskContext { inner }
    }
}

/// Trait for types that can provide pre-shared keys for a key identity given by a client to a
/// server.
pub trait ServerPskIdentityKeyProvider<'a>: Debug {
    /// Provides the key for the key `identity` given by the client that is connected through
    /// `session`, or `None` if the identity unacceptable or no key is available.
    fn key_for_identity(&self, identity: &[u8], session: &CoapServerSession<'_>) -> Option<PskKey<'a>>;
}

impl<'a, T: Debug> ServerPskIdentityKeyProvider<'a> for T
where
    T: AsRef<[PskKey<'a>]>,
{
    /// Returns the first key whose identity is equal to the one requested.
    /// If not found, returns the first key that has no key ID set.
    fn key_for_identity(&self, identity: &[u8], _session: &CoapServerSession<'_>) -> Option<PskKey<'a>> {
        let keys = self.as_ref();
        keys.iter()
            .find(|k| k.identity().as_deref().is_some_and(|kid| kid == identity))
            .or_else(|| keys.iter().find(|k| k.identity().is_none()))
            .cloned()
    }
}

/// Trait for things that can provide PSK DTLS keys for a given Server Name Indication.
pub trait ServerPskSniKeyProvider<'a>: Debug {
    /// Provide a key for the server name indication given as `sni`, or `None` if the SNI is not
    /// valid and no key is available.
    ///
    /// Note that libcoap will remember the returned key and re-use it for future handshakes with
    /// the same SNI (even if the peer is not the same), the return value should therefore not
    /// depend on the provided `session`.
    fn key_for_sni(&self, sni: &CStr, session: &CoapServerSession<'_>) -> Option<PskKey<'a>>;
}

impl<'a, T: AsRef<[u8]> + Debug, U: AsRef<PskKey<'a>> + Debug> ServerPskSniKeyProvider<'a> for Vec<(T, U)> {
    /// Return the second tuple object if the first one matches the given SNI.
    fn key_for_sni(&self, sni: &CStr, _session: &CoapServerSession<'_>) -> Option<PskKey<'a>> {
        self.iter()
            .find_map(|(key_sni, key)| (key_sni.as_ref() == sni.to_bytes()).then_some(key.as_ref().clone()))
    }
}

impl<'a, T: AsRef<[u8]> + Debug, U: AsRef<PskKey<'a>> + Debug> ServerPskSniKeyProvider<'a> for [(T, U)] {
    /// Return the second tuple object if the first one matches the given SNI.
    fn key_for_sni(&self, sni: &CStr, _session: &CoapServerSession<'_>) -> Option<PskKey<'a>> {
        let keys = self.as_ref();
        keys.iter()
            .find_map(|(key_sni, key)| (key_sni.as_ref() == sni.to_bytes()).then_some(key.as_ref().clone()))
    }
}

impl<'a, T: Borrow<[u8]> + Debug + Eq + Hash, U: AsRef<PskKey<'a>> + Debug> ServerPskSniKeyProvider<'a>
    for HashMap<T, U>
{
    /// Return the map value if the key matches the given SNI.
    fn key_for_sni(&self, sni: &CStr, _session: &CoapServerSession<'_>) -> Option<PskKey<'a>> {
        self.get(sni.to_bytes()).map(|v| v.as_ref()).cloned()
    }
}

impl<'a, T: Borrow<[u8]> + Debug + Ord, U: AsRef<PskKey<'a>> + Debug> ServerPskSniKeyProvider<'a> for BTreeMap<T, U> {
    /// Return the map value if the key matches the given SNI.
    fn key_for_sni(&self, sni: &CStr, _session: &CoapServerSession<'_>) -> Option<PskKey<'a>> {
        self.get(sni.to_bytes()).map(|v| v.as_ref()).cloned()
    }
}

/// Raw PSK identity callback that can be provided to libcoap.
///
/// # Safety
///
/// This function expects the arguments to be provided in a way that libcoap would when invoking
/// this function as an identity callback.
///
/// Additionally, `arg` must be a valid argument to [`ServerPskContext::from_raw`].
pub(crate) unsafe extern "C" fn dtls_psk_server_id_callback(
    identity: *mut coap_bin_const_t,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_bin_const_t {
    let identity = std::slice::from_raw_parts((*identity).s, (*identity).length);
    // We must not increase the refcount here, as doing so would require locking the global context,
    // which is not possible during a DTLS callback.
    // SAFETY: While we are in this callback, libcoap's context is locked by our current thread.
    //         therefore, it is impossible that the reference counter would be decreased by any
    //         other means, and constructing the server side session without increasing the refcount
    //         is fine.
    let session = CoapServerSession::from_raw_without_refcount(session);
    let server_context = ServerPskContext::from_raw(userdata as *const RefCell<ServerPskContextInner>);
    server_context.id_callback(identity, &session)
}

/// Raw PSK SNI callback that can be provided to libcoap.
///
/// # Safety
///
/// This function expects the arguments to be provided in a way that libcoap would when invoking
/// this function as an PSK SNI callback.
///
/// Additionally, `arg` must be a valid argument to [`ServerPskContext::from_raw`].
pub(crate) unsafe extern "C" fn dtls_psk_server_sni_callback(
    sni: *const c_char,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_dtls_spsk_info_t {
    let sni = CStr::from_ptr(sni);
    // We must not increase the refcount here, as doing so would require locking the global context,
    // which is not possible during a DTLS callback.
    // SAFETY: While we are in this callback, libcoap's context is locked by our current thread.
    //         therefore, it is impossible that the reference counter would be decreased by any
    //         other means, and constructing the server side session without increasing the refcount
    //         is fine.
    let session = CoapServerSession::from_raw_without_refcount(session);
    let server_context = ServerPskContext::from_raw(userdata as *const RefCell<ServerPskContextInner>);
    server_context.sni_callback(sni, &session)
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * crypto/psk/key.rs - Interfaces and types for PSK keys in libcoap-rs.
 */

use std::{borrow::Cow, marker::PhantomData, ptr::NonNull};

use libcoap_sys::{coap_bin_const_t, coap_dtls_cpsk_info_t, coap_dtls_spsk_info_t};

/// A pre-shared DTLS key.
#[derive(Debug, Clone)]
pub struct PskKey<'a> {
    /// Identity of this key (or None if no identity is known).
    identity: Option<Box<[u8]>>,
    /// Actual key data (the key bytes).
    data: Box<[u8]>,
    // This lifetime is not strictly necessary for now. This is just future-proofing for later
    // changes, which might allow PskKey instances with limited lifetimes (e.g. using borrowed byte
    // slices).
    // In practice (at least for now), all PskKey instances have a 'static lifetime.
    _lifetime_marker: PhantomData<&'a ()>,
}

impl<'a> PskKey<'a> {
    /// Creates a new key object with the given `identity` and the actual key bytes given in `data`.
    pub fn new<T: Into<Vec<u8>>, U: Into<Vec<u8>>>(identity: Option<T>, data: U) -> PskKey<'a> {
        PskKey {
            identity: identity.map(Into::into).map(|v| v.into_boxed_slice()),
            data: data.into().into_boxed_slice(),
            _lifetime_marker: Default::default(),
        }
    }
}

impl PskKey<'_> {
    /// Returns the key's identity or `None` if no key identity was set.
    pub fn identity(&self) -> Option<&[u8]> {
        self.identity.as_ref().map(|v| v.as_ref())
    }

    /// Returns the key data bytes as an immutable slice.
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Creates a [`coap_dtls_spsk_info_t`] instance from this [`PskKey`].
    ///
    /// This call converts the identity and data field of this PSK into raw pointers and creates a
    /// [`coap_dtls_spsk_info_t`] structure that allows libcoap to use those values.
    ///
    /// After this call, the caller is responsible for managing the memory allocated for the
    /// identity and key byte strings referred to be the created struct instance, i.e., simply
    /// dropping the created [`coap_dtls_spsk_info_t`] will cause a memory leak.
    /// The easiest way to clean up the memory is by calling [`from_raw_spsk_info`](Self::from_raw_spsk_info)
    /// to reverse the conversion done by this method and then dropping the restored [`PskKey`]
    /// instance.
    pub(crate) fn into_raw_spsk_info(self) -> coap_dtls_spsk_info_t {
        let (hint, key) = self.into_bin_consts();
        coap_dtls_spsk_info_t { hint, key }
    }

    /// Restores a `DtlsPsk` instance from a [`coap_dtls_spsk_info_t`] structure.
    ///
    /// # Safety
    ///
    /// The provided object must point to a valid instance of [`coap_dtls_spsk_info_t`] that *must*
    /// have been created by a previous call to [`into_raw_spsk_info`](Self::into_raw_spsk_info).
    ///
    /// The byte strings the provided `spsk_info` points to *must* not be in use anywhere else (as
    /// this might violate the aliasing rules), i.e. libcoap must no longer use these byte strings.
    pub(crate) unsafe fn from_raw_spsk_info(spsk_info: coap_dtls_spsk_info_t) -> Self {
        // SAFETY: Caller contract requires the provided spsk_info to be created by a previous call
        // to into_raw_spsk_info.
        Self::from_bin_consts(&spsk_info.hint, &spsk_info.key)
    }

    /// Creates a [`coap_dtls_cpsk_info_t`] instance from this [`PskKey`].
    ///
    /// This call converts the identity and data field of this PSK into raw pointers and creates a
    /// [`coap_dtls_cpsk_info_t`] structure that allows libcoap to use those values.
    ///
    /// After this call, the caller is responsible for managing the memory allocated for the
    /// identity and key byte strings referred to be the created struct instance, i.e., simply
    /// dropping the created [`coap_dtls_cpsk_info_t`] will cause a memory leak.
    /// The easiest way to clean up the memory is by calling [`from_raw_cpsk_info`](Self::from_raw_cpsk_info)
    /// to reverse the conversion done by this method and then dropping the restored [`PskKey`]
    /// instance.
    pub(crate) fn into_raw_cpsk_info(self) -> coap_dtls_cpsk_info_t {
        let (identity, key) = self.into_bin_consts();
        coap_dtls_cpsk_info_t { identity, key }
    }

    /// Restores a DtlsPsk instance from a [`coap_dtls_cpsk_info_t`] structure.
    ///
    /// # Safety
    ///
    /// The provided object must point to a valid instance of [`coap_dtls_cpsk_info_t`] that *must*
    /// have been created by a previous call to [`into_raw_cpsk_info`](Self::into_raw_cpsk_info).
    ///
    /// The byte strings the provided `cpsk_info` points to *must* not be in use anywhere else (as
    /// this might violate the aliasing rules), i.e., libcoap must no longer use these byte strings.
    pub(crate) unsafe fn from_raw_cpsk_info(cpsk_info: coap_dtls_cpsk_info_t) -> Self {
        // SAFETY: Caller contract requires the provided cpsk_info to be created by a previous call
        // to into_raw_cpsk_info.
        Self::from_bin_consts(&cpsk_info.identity, &cpsk_info.key)
    }

    /// Consumes this key object to create two [`coap_bin_const_t`] instances referring to the
    /// `identity` and `data` fields.
    ///
    /// The pointers given in [`coap_bin_const_t`] have been created by a call to [`Box::into_raw`]
    /// with the `length` field set to the length of the given field.
    fn into_bin_consts(self) -> (coap_bin_const_t, coap_bin_const_t) {
        let identity = self
            .identity
            .map(|v| coap_bin_const_t {
                length: v.len(),
                s: Box::into_raw(v) as *const u8,
            })
            .unwrap_or(coap_bin_const_t {
                length: 0,
                s: std::ptr::null(),
            });
        let key = coap_bin_const_t {
            length: self.data.len(),
            s: Box::into_raw(self.data) as *const u8,
        };
        (identity, key)
    }

    /// Converts the given pair of [`coap_bin_const_t`]s back into a [`PskKey`] instance with the
    /// given `identity` and `key`
    ///
    /// # Safety
    /// The provided `identity` and `key` must have been created by a previous call to
    /// [`PskKey::into_bin_consts`], the `length` field and pointers of both constants must not have
    /// been modified.
    unsafe fn from_bin_consts(identity: &coap_bin_const_t, key: &coap_bin_const_t) -> Self {
        // SAFETY: Caller contract requires the provided identity and key to be created by a
        // previous call to into_bin_consts, which means that the pointer in identity.s refers to a
        // pointer created by a previous call to Box::into_raw(), identity.length refers
        // to the correct length of the slice, and the pointer can actually be treated as a mutable
        // pointer.
        let identity = NonNull::new(identity.s as *mut u8)
            .map(|mut v| unsafe { Box::from_raw(std::slice::from_raw_parts_mut(v.as_mut(), identity.length)) });

        // SAFETY same as above.
        let data = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(key.s as *mut u8, key.length)) };
        Self {
            identity,
            data,
            _lifetime_marker: Default::default(),
        }
    }
}

impl From<Box<[u8]>> for PskKey<'static> {
    fn from(value: Box<[u8]>) -> Self {
        PskKey {
            identity: None,
            data: value,
            _lifetime_marker: Default::default(),
        }
    }
}

impl From<&[u8]> for PskKey<'static> {
    fn from(value: &[u8]) -> Self {
        PskKey {
            identity: None,
            data: value.into(),
            _lifetime_marker: Default::default(),
        }
    }
}

impl<'a> From<Cow<'a, [u8]>> for PskKey<'static> {
    fn from(value: Cow<'a, [u8]>) -> Self {
        PskKey {
            identity: None,
            data: value.into(),
            _lifetime_marker: Default::default(),
        }
    }
}

impl<T: Into<Box<[u8]>>, U: Into<Box<[u8]>>> From<(T, U)> for PskKey<'static> {
    fn from(value: (T, U)) -> Self {
        PskKey {
            identity: Some(value.0.into()),
            data: value.1.into(),
            _lifetime_marker: Default::default(),
        }
    }
}

impl<'a> AsRef<PskKey<'a>> for PskKey<'a> {
    fn as_ref(&self) -> &PskKey<'a> {
        self
    }
}

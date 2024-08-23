mod client;
mod server;

pub use client::*;
pub use server::*;

use libcoap_sys::{coap_bin_const_t, coap_dtls_cpsk_info_t, coap_dtls_spsk_info_t};
use std::borrow::Cow;
use std::fmt::Debug;
use std::ptr::NonNull;
#[derive(Debug, Clone)]
pub struct PskKey {
    identity: Option<Box<[u8]>>,
    data: Box<[u8]>,
}

impl PskKey {
    pub fn new<T: Into<Vec<u8>>, U: Into<Vec<u8>>>(identity: Option<T>, data: U) -> PskKey {
        PskKey {
            identity: identity.map(Into::into).map(|v| v.into_boxed_slice()),
            data: data.into().into_boxed_slice(),
        }
    }

    /// Creates a [`coap_dtls_spsk_info_t`] instance from this [`PskKey`].
    ///
    /// This call converts the identity and data field of this PSK into raw pointers and creates a
    /// [`coap_dtls_spsk_info_t`] structure that allows libcoap to use those values.
    ///
    /// After this call, the caller is responsible for managing the memory allocated for the
    /// identity and key byte strings referred to be the created struct instance, i.e. simply
    /// dropping the created [`coap_dtls_spsk_info_t`] will cause a memory leak.
    /// The easiest way to clean up the memory is by calling [from_raw_spsk_info](Self::from_raw_spsk_info)
    /// to reverse the conversion done by this method and then dropping the restored [`PskKey`]
    /// instance.
    pub(crate) fn into_raw_spsk_info(self) -> coap_dtls_spsk_info_t {
        let (hint, key) = self.into_bin_consts();
        coap_dtls_spsk_info_t { hint, key }
    }

    /// Restores a DtlsPsk instance from a [`coap_dtls_spsk_info_t`] structure.
    ///
    /// # Safety
    ///
    /// The provided object must point to a valid instance of [`coap_dtls_spsk_info_t`] that *must*
    /// have been created by a previous call to [into_raw_spsk_info](Self::into_raw_spsk_info).
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
    /// identity and key byte strings referred to be the created struct instance, i.e. simply
    /// dropping the created [`coap_dtls_cpsk_info_t`] will cause a memory leak.
    /// The easiest way to clean up the memory is by calling [from_raw_cpsk_info](Self::from_raw_cpsk_info)
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
    /// have been created by a previous call to [into_raw_cpsk_info](Self::into_raw_cpsk_info).
    ///
    /// The byte strings the provided `cpsk_info` points to *must* not be in use anywhere else (as
    /// this might violate the aliasing rules), i.e. libcoap must no longer use these byte strings.
    pub(crate) unsafe fn from_raw_cpsk_info(cpsk_info: coap_dtls_cpsk_info_t) -> Self {
        // SAFETY: Caller contract requires the provided cpsk_info to be created by a previous call
        // to into_raw_cpsk_info.
        Self::from_bin_consts(&cpsk_info.identity, &cpsk_info.key)
    }

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

    unsafe fn from_bin_consts(identity: &coap_bin_const_t, key: &coap_bin_const_t) -> Self {
        // SAFETY: Caller contract requires the provided identity and key to be created by a
        // previous call to into_bin_consts, which means that the pointer in identity.s refers to a
        // pointer created by a previous call to Box::into_raw(), identity.length refers
        // to the correct length of the slice, and the pointer can actually be treated as a mutable
        // pointer.
        let identity = NonNull::new(identity.s as *mut u8)
            .map(|mut v| unsafe { Box::from_raw(std::slice::from_raw_parts_mut(v.as_mut(), identity.length)) });

        // SAFETY same as above.
        let data = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(key.s as *mut u8, key.length) as *mut [u8]) };
        Self { identity, data }
    }
}

impl From<Box<[u8]>> for PskKey {
    fn from(value: Box<[u8]>) -> Self {
        PskKey {
            identity: None,
            data: value.into(),
        }
    }
}

impl From<&[u8]> for PskKey {
    fn from(value: &[u8]) -> Self {
        PskKey {
            identity: None,
            data: value.into(),
        }
    }
}

impl<'a> From<Cow<'a, [u8]>> for PskKey {
    fn from(value: Cow<'a, [u8]>) -> Self {
        PskKey {
            identity: None,
            data: value.into(),
        }
    }
}

impl<T: Into<Box<[u8]>>, U: Into<Box<[u8]>>> From<(T, U)> for PskKey {
    fn from(value: (T, U)) -> Self {
        PskKey {
            identity: Some(value.0.into()),
            data: value.1.into(),
        }
    }
}

impl AsRef<PskKey> for PskKey {
    fn as_ref(&self) -> &PskKey {
        self
    }
}

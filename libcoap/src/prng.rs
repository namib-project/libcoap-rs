// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * prng.rs - libcoap pseudo-random number generator function bindings.
 */

//! Module containing methods for accessing or configuring the libcoap PRNG.
//!
//! This module provides basic functions to seed the libcoap PRNG and retrieve random bytes from it.
//!
//! Additionally, if the `rand` feature is enabled, this module contains integrations with the
//! [rand] crate that allow using the libcoap PRNG as a [rand::Rng] or setting the libcoap PRNG to
//! an existing [rand::Rng].

use std::{
    ffi::{c_uint, c_void},
    sync::Mutex,
};

use libcoap_sys::{coap_prng, coap_prng_init};

use crate::{context::ensure_coap_started, error::RngError};

// TODO If we can assert that libcoap's own thread-safety features are enabled at some point, we
//      don't need these mutexes.
static COAP_RNG_SEED_MUTEX: Mutex<()> = Mutex::new(());
static COAP_RNG_ACCESS_MUTEX: Mutex<()> = Mutex::new(());

/// Attempts to fill `dest` with random bytes using libcoap's PRNG.
///
/// # Errors
///
/// Will return an error if libcoap's PRNG has an error or the underlying mutex was poisoned by a
/// panic in another thread.
///
/// # Example
///
/// ```
/// use libcoap_rs::error::RngError;
/// use libcoap_rs::prng::coap_prng_try_fill;
///
/// let mut token = [0u8; 8];
/// coap_prng_try_fill(&mut token)?;
///
///
/// # Result::<(), RngError>::Ok(())
/// ```
pub fn coap_prng_try_fill(dest: &mut [u8]) -> Result<(), RngError> {
    ensure_coap_started();
    let _acc_mutex = COAP_RNG_ACCESS_MUTEX.lock()?;
    // SAFETY: Supplied pointer and length describe the provided slice.
    match unsafe { coap_prng(dest.as_mut_ptr() as *mut c_void, dest.len()) } {
        1 => Ok(()),
        _v => Err(RngError::Unknown),
    }
}

/// Seeds the default PRNG of libcoap with the provided seed.
///
/// # Errors
///
/// May return an error if the mutex for seeding the PRNG is poisoned, i.e. there was some panic
/// in a previous attempt of seeding the PRNG.
pub fn seed_coap_prng(seed: c_uint) -> Result<(), RngError> {
    ensure_coap_started();
    let guard = COAP_RNG_SEED_MUTEX.lock()?;
    unsafe {
        coap_prng_init(seed);
    }
    drop(guard);
    Ok(())
}

#[cfg(feature = "rand")]
pub use rand_integration::*;

/// Module containing integration code with the [rand] crate.
#[cfg(feature = "rand")]
mod rand_integration {
    use core::{
        any::TypeId,
        ffi::{c_int, c_void},
    };
    use std::sync::Mutex;

    use libcoap_sys::coap_set_prng;
    use rand_core::{CryptoRng, TryRngCore, UnwrapErr, UnwrapMut};

    use crate::{context::ensure_coap_started, error::RngError, prng::coap_prng_try_fill};

    static COAP_RNG_FN_MUTEX: Mutex<Option<Box<dyn ErrorErasingTryRngCore + Send + Sync>>> = Mutex::new(None);

    /// Implementation of the [rand::TryRngCore] trait based on libcoap's PRNG.
    pub struct CoapRng {}

    impl TryRngCore for CoapRng {
        type Error = RngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            // This is the same as rand_core::impls::next_u32_via_fill(self), but with
            // support for returning errors.
            let mut buf = [0; 4];
            self.try_fill_bytes(&mut buf)?;
            Ok(u32::from_le_bytes(buf))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            // This is the same as rand_core::impls::next_u64_via_fill(self), but with
            // support for returning errors.
            let mut buf = [0; 8];
            self.try_fill_bytes(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            coap_prng_try_fill(dest)
        }
    }

    // For now, we can't implement this, as libcoap falls back to the not cryptographically secure
    // rand()/srand() if it can't find a cryptographically secure PRNG.
    // Should be reconsidered either if libcoap removes this fallback or if we can detect whether the
    // fallback was used.
    //impl CryptoRng for CoapRng {}

    /// Configures libcoap to use the provided `rng` for pseudo-random number generation instead of its
    /// default PRNG.
    ///
    /// The provided PRNG will be used globally across all contexts.
    ///
    /// Important: *DO NOT* provide an instance of [CoapRng] to [set_coap_prng]! This will probably
    /// lead to a stack overflow, as [CoapRng] would recursively call into itself to generate random
    /// bytes.
    /// This function will try to catch attempts to do so, but cannot reliably check for all
    /// possible cases (e.g., if the [CoapRng] is wrapped in another custom type).
    ///
    /// # Errors
    ///
    /// May return [RngError::GlobalMutexPoisonError] if the underlying mutex protecting the RNG is
    /// poisoned, i.e. a thread panicked while holding the lock (which should only happen if the
    /// previously set RNG panicked).
    ///
    /// Will return [RngError::CoapRngAsCustomRng] if the [TryRngCore] implementation provided to
    /// this function is a known reference to a [CoapRng] instance (which would cause infinite
    /// recursion).
    ///
    /// # Example
    ///
    /// ```
    /// use rand_core::{CryptoRng, RngCore};
    /// use libcoap_rs::error::RngError;
    /// use libcoap_rs::prng::{coap_prng_try_fill, set_coap_prng};
    ///
    /// pub struct NullRng {}
    ///
    /// // This implicitly also adds an implementation for TryRngCore, which is the type that is
    /// // actually required by set_coap_rng().
    /// impl RngCore for NullRng {
    ///     fn next_u32(&mut self) -> u32 {
    ///         0
    ///     }
    ///
    ///     fn next_u64(&mut self) -> u64 {
    ///         0
    ///     }
    ///
    ///     fn fill_bytes(&mut self, dest: &mut [u8]) {
    ///         dest.fill(0);
    ///     }
    /// }
    ///
    /// // Obviously, this is just for demonstration purposes and should not actually be done.
    /// impl CryptoRng for NullRng {}
    ///
    /// set_coap_prng(NullRng{})?;
    /// let mut token = [1u8; 8];
    /// coap_prng_try_fill(&mut token)?;
    ///
    /// assert_eq!(&token, &[0u8; 8]);
    ///
    ///
    /// # Result::<(), RngError>::Ok(())
    /// ```
    pub fn set_coap_prng<RNG: TryRngCore + CryptoRng + Send + Sync + 'static>(rng: RNG) -> Result<(), RngError> {
        // Check that we aren't adding CoapRng to libcoap (which would cause infinite
        // recursion/stack overflows).
        const RECURSIVE_RNG_TYPES: &[TypeId] = &[
            TypeId::of::<CoapRng>(),
            TypeId::of::<UnwrapErr<CoapRng>>(),
            TypeId::of::<UnwrapMut<CoapRng>>(),
        ];
        if RECURSIVE_RNG_TYPES.contains(&TypeId::of::<RNG>()) {
            return Err(RngError::CoapRngAsCustomRng);
        }
        ensure_coap_started();
        let mut guard = COAP_RNG_FN_MUTEX.lock()?;
        *guard = Some(Box::new(rng));
        // SAFETY: Pointer is valid and pointed-to function does what libcoap expects.
        unsafe {
            coap_set_prng(Some(prng_callback));
        }
        drop(guard);
        Ok(())
    }

    /// Trait that provides the same functionality as [TryRngCore], but with a fixed error type
    /// containing no detailed error information.
    ///
    /// Used in the type definition for the RNG function container provided to libcoap
    /// [COAP_RNG_FN_MUTEX], since we can't use [TryRngCore] directly without making the
    /// type dyn-incompatible.
    trait ErrorErasingTryRngCore {
        /// Does the same as [TryRngCore], but converts all errors to [RngError::Unknown].
        fn try_fill_bytes_erase_error(&mut self, dest: &mut [u8]) -> Result<(), RngError>;
    }

    impl<T: TryRngCore<Error = E>, E> ErrorErasingTryRngCore for T {
        fn try_fill_bytes_erase_error(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            <T as TryRngCore>::try_fill_bytes(self, dest).map_err(|_e| RngError::Unknown)
        }
    }

    /// Callback provided to libcoap for generating random numbers.
    ///
    /// # Safety
    ///
    /// This function is intended as a [libcoap_sys::coap_rand_func_t], therefore `out` should be valid
    /// and point to the start of an area of memory that can be filled with `len` bytes.
    unsafe extern "C" fn prng_callback(out: *mut c_void, len: usize) -> c_int {
        let out_slice = std::slice::from_raw_parts_mut(out as *mut u8, len);
        match COAP_RNG_FN_MUTEX.lock() {
            Ok(mut rng_fn) => rng_fn
                .as_mut()
                .expect("rng_callback has been set, but no RNG was set")
                .try_fill_bytes_erase_error(out_slice)
                .map_or(0, |_| 1),
            Err(_e) => 0,
        }
    }
}

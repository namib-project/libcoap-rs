// SPDX-License-Identifier: BSD-2-Clause
/*
 * prng.rs - libcoap pseudo-random number generator functions.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2024 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Module containing methods for accessing or configuring the libcoap PRNG.
//!
//! This module provides basic functions to seed the libcoap PRNG and retrieve random bytes from it.
//!
//! Additionally, if the `rand` feature is enabled, this module contains integrations with the
//! [rand] crate that allow using the libcoap PRNG as a [rand::Rng] or setting the libcoap PRNG to
//! an existing [rand::Rng].

use std::ffi::{c_uint, c_void};
#[cfg(feature = "rand")]
use std::ffi::c_int;
use std::sync::Mutex;

#[cfg(feature = "rand")]
use libc::size_t;
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};

use libcoap_sys::{coap_prng, coap_prng_init};
#[cfg(feature = "rand")]
use libcoap_sys::coap_set_prng;

use crate::context::ensure_coap_started;
use crate::error::RngError;

// TODO If we can assert that libcoap's own thread-safety features are enabled at some point, we
//      don't need these mutexes.
static COAP_RNG_SEED_MUTEX: Mutex<()> = Mutex::new(());
#[cfg(feature = "rand")]
static COAP_RNG_FN_MUTEX: Mutex<Option<Box<dyn RngCore + Send + Sync>>> = Mutex::new(None);
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
/// Implementation of the [rand::RngCore] trait based on libcoap's PRNG.
///
/// Important: *DO NOT* provide an instance of [CoapRng] to [set_coap_prng]! This will probably lead
/// to a stack overflow, as [CoapRng] would recursively call into itself to generate random bytes.
#[cfg(feature = "rand")]
pub struct CoapRng {}

#[cfg(feature = "rand")]
impl RngCore for CoapRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("error while generating bytes from libcoap RNG")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        coap_prng_try_fill(dest).map_err(|e| rand::Error::new(e))
    }
}

// For now, we can't implement this, as libcoap falls back to the not cryptographically secure
// rand()/srand() if it can't find a cryptographically secure PRNG.
// Should be reconsidered either if libcoap removes this fallback or if we can detect whether the
// fallback was used.
//impl CryptoRng for CoapRng {}

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

/// Configures libcoap to use the provided `rng` for pseudo-random number generation instead of its
/// default PRNG.
///
/// The provided PRNG will be used globally across all contexts.
///
/// # Errors
///
/// May return an error if the underlying mutex protecting the RNG is poisoned, i.e. a thread
/// panicked while holding the lock (which should only happen if the previously set RNG panicked).
///
/// # Example
///
/// ```
/// use rand_core::{CryptoRng, Error, RngCore};
/// use libcoap_rs::error::RngError;
/// use libcoap_rs::prng::{coap_prng_try_fill, set_coap_prng};
///
/// pub struct NullRng {}
///
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
///
///     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
///         dest.fill(0);
///         Ok(())
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
#[cfg(feature = "rand")]
pub fn set_coap_prng<RNG: RngCore + CryptoRng + Send + Sync + 'static>(rng: RNG) -> Result<(), RngError> {
    ensure_coap_started();
    let mut guard = COAP_RNG_FN_MUTEX.lock()?;
    *guard = Some(Box::new(rng));
    // SAFETY: Pointer is valid and pointed to function does what libcoap expects.
    unsafe {
        coap_set_prng(Some(prng_callback));
    }
    drop(guard);
    Ok(())
}

/// Callback provided to libcoap for generating random numbers.
///
/// # Safety
///
/// This function is intended as a [libcoap_sys::coap_rand_func_t], therefore `out` should be valid
/// and point to the start of an area of memory that can be filled with `len` bytes.
#[cfg(feature = "rand")]
unsafe extern "C" fn prng_callback(out: *mut c_void, len: size_t) -> c_int {
    let out_slice = std::slice::from_raw_parts_mut(out as *mut u8, len);
    match COAP_RNG_FN_MUTEX.lock() {
        Ok(mut rng_fn) => rng_fn
            .as_mut()
            .expect("rng_callback has been set, but no RNG was set")
            .try_fill_bytes(out_slice)
            .map_or(0, |_| 1),
        Err(_e) => 0,
    }
}

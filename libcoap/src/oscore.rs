// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * oscore.rs - Wrapper for libcoap OSCORE functionality.
 */

use core::{ffi::c_void, ptr};

use libcoap_sys::{coap_new_oscore_conf, coap_new_str_const, coap_oscore_conf_t};

use crate::error::OscoreConfigError;

/// Represents an oscore config object which stores the underlying
/// coap_oscore_conf_t C struct.
pub struct OscoreConf {
    raw_conf: *mut coap_oscore_conf_t,
    pub(crate) initial_recipient: Option<String>,
}

impl OscoreConf {
    /// Creates a new OscoreConf.
    ///
    /// # Errors
    /// Will return a [OscoreConfigError] if creating the oscore config fails (most likely due to
    /// invalid oscore config bytes provided).
    pub fn new(
        seq_initial: u64,
        oscore_conf_bytes: &[u8],
        save_seq_num_func: extern "C" fn(seq_num: u64, _param: *mut c_void) -> i32,
    ) -> Result<Self, OscoreConfigError> {
        // Creates the raw_struct containing the config provided by the caller.
        // SAFETY: Provided pointer and length point to a valid byte string usable by
        // coap_new_str_const().
        let conf = unsafe { coap_new_str_const(oscore_conf_bytes.as_ptr(), oscore_conf_bytes.len()) };
        if conf.is_null() {
            return Err(OscoreConfigError::Unknown);
        }

        // SAFETY:
        // The parts of the byte string referenced by conf are defensively copied if used
        // by the newly created oscore_conf.
        // Conf was just checked for invalidity, whether or not it containes all required fields.
        // - save_seq_num_func is specifically designed to work as a callback for this
        //   function.
        // - save_seq_num_func_param may be a null pointer (save_seq_num_func does
        //   not use it).
        let oscore_conf = unsafe { coap_new_oscore_conf(*conf, Some(save_seq_num_func), ptr::null_mut(), seq_initial) };
        if oscore_conf.is_null() {
            return Err(OscoreConfigError::Unknown);
        }

        // Save the initial recipient_id (if present). This needs to be added to the context when
        // calling oscore_server to prevent a double free when trying to add an identical
        // recipient_id later.
        let mut initial_recipient: Option<String> = None;
        let oscore_conf_str = core::str::from_utf8(oscore_conf_bytes).expect("could not parse config bytes to str");
        for line in oscore_conf_str.lines() {
            if line.starts_with("recipient_id") {
                let parts: Vec<&str> = line.split(",").collect();
                initial_recipient = Some(parts[2].trim().trim_matches('"').to_string());
                break;
            }
        }

        // Return the valid OscoreConf.
        Ok(Self {
            raw_conf: oscore_conf,
            initial_recipient,
        })
    }

    /// Cosumes the OscoreConf and returns the contained raw_conf libcoap struct as well as an
    /// optional initial recipient if set.
    pub(crate) fn into_raw_conf(self) -> (*mut coap_oscore_conf_t, Option<String>) {
        (self.raw_conf, self.initial_recipient.clone())
    }
}

impl Drop for OscoreConf {
    /// Drop the OscoreConf's raw_conf.
    fn drop(&mut self) {
        // TODO: Howto handle this now?
        unsafe {
            let _ = Box::from_raw(self.raw_conf);
        }
    }
}

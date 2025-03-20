use core::{ffi::c_void, ptr};
use libcoap_sys::{coap_bin_const_t, coap_new_oscore_conf, coap_oscore_conf_t, coap_str_const_t};

use crate::error::OscoreConfigCreationError;

/// Represents an oscore conf object which stores the underlying
/// coap_oscore_conf_t struct.
pub struct OscoreConf {
    raw_conf: *mut coap_oscore_conf_t,
    pub(crate) raw_conf_valid: bool,
    pub(crate) initial_recipient: Option<String>,
}

impl OscoreConf {
    /// Creates a new OscoreConf.
    pub fn new(
        seq_initial: u64,
        oscore_conf_bytes: &[u8],
        save_seq_num_func: extern "C" fn(seq_num: u64, _param: *mut c_void) -> i32,
    ) -> Result<Self, OscoreConfigCreationError> {
        let conf = coap_str_const_t {
            length: oscore_conf_bytes.len(),
            s: oscore_conf_bytes.as_ptr(),
        };

        // SAFETY: It is expected, that the user provides valid oscore_conf bytes. In case of
        // failure this will return null which will result in an error being thrown.
        let oscore_conf = unsafe { coap_new_oscore_conf(conf, Some(save_seq_num_func), ptr::null_mut(), seq_initial) };

        if oscore_conf.is_null() {
            return Err(OscoreConfigCreationError::Unknown);
        }

        // Safe the initial recipient_id (if present). This needs to be added to the context when
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

        Ok(Self {
            raw_conf: oscore_conf,
            raw_conf_valid: true,
            initial_recipient,
        })
    }
    /// SAFETY: raw_conf should be always valid until the OscoreConf is dropped, calling this
    /// function will only return a copy of the raw_conf which has to bee freed by the caller.
    /// The intitial raw_conf held within the OscoreConf is dropped via its Drop trade.
    pub(crate) fn as_mut_raw_conf(&mut self) -> *mut coap_oscore_conf_t {
        self.raw_conf
    }
}

impl Drop for OscoreConf {
    /// Drop the OscoreConf.
    /// The Conf will only be dropped, if the raw_struct hasn't been dropped already.
    fn drop(&mut self) {
        // SAFETY: Drop the raw_conf if the raw_struct is still valid and hasn't been dropped by
        // libcoap already. The raw_conf might be freed and invalidated already if connect_oscore
        // or oscore_server have been called with it previously, in which case the raw_conf_valid
        // has been set to false, to prevent a double free here.
        if self.raw_conf_valid {
            unsafe {
                let _ = Box::from_raw(self.raw_conf);
            }
        }
    }
}

/// OscoreRecipient represents a Recipient with an ID, and its underlying C struct.
#[derive(Debug)]
pub(crate) struct OscoreRecipient {
    recipient_id: String,
    recipient: *mut coap_bin_const_t,
}

impl OscoreRecipient {
    /// Returns a new OscoreRecipient with a given ID.
    pub(crate) fn new(recipient_id: &str) -> OscoreRecipient {
        // The User only supplies the Recipient ID, we will build the C Struct here
        let recipient = coap_bin_const_t {
            length: recipient_id.len(),
            s: recipient_id.as_ptr(),
        };

        let recipient: *mut coap_bin_const_t = Box::into_raw(Box::new(recipient));

        // And then return the newly created Recipient
        OscoreRecipient {
            recipient_id: recipient_id.to_string(),
            recipient,
        }
    }

    /// Returns the raw C Struct of the Recipient.
    pub(crate) fn get_c_struct(&self) -> *mut coap_bin_const_t {
        self.recipient
    }

    /// Returns the ID of the Recipient.
    pub(crate) fn get_recipient_id(&self) -> &str {
        self.recipient_id.as_str()
    }

    /// Drops the Recipient from Memory.
    /// Warning: THIS SHOULD NEVER BE CALLED UNLESS YOU'RE SURE THE coap_bin_const_t HAS NOT BEEN FREED BEFORE!
    /// This will trigger a double free, if coap_bin_const_t has already been freed!
    pub(crate) fn drop(&self) {
        // SAFETY: THIS SHOULD NEVER BE CALLED UNLESS YOU'RE SURE THE coap_bin_const_t HAS NOT BEEN
        // FREED BEFORE!
        // Currently, this is only used in 'add_new_oscore_recipient()' in case the recipient is not
        // added to the context (which would free the raw pointer when dropped). There is Currently
        // only one exception, which is filtered out, because trying to add a duplicate recipient
        // to the oscore context would already trigger a free() in libcoap
        unsafe {
            let _ = Box::from_raw(self.get_c_struct());
        }
    }
}

use core::{ffi::c_void, ptr};

use libcoap_sys::{coap_bin_const_t, coap_new_oscore_conf, coap_oscore_conf_t, coap_str_const_t};

use crate::error::OscoreConfigError;

/// Represents an oscore config object which stores the underlying
/// coap_oscore_conf_t C struct.
pub struct OscoreConf {
    raw_conf: *mut coap_oscore_conf_t,
    pub(crate) raw_conf_valid: bool,
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
        // Build the configs C struct from bytes.
        let conf = coap_str_const_t {
            length: oscore_conf_bytes.len(),
            s: oscore_conf_bytes.as_ptr(),
        };

        // SAFETY: It is expected, that the user provides valid oscore_conf bytes. In case of
        // failure this will return null which will result in an error being thrown.
        let oscore_conf = unsafe { coap_new_oscore_conf(conf, Some(save_seq_num_func), ptr::null_mut(), seq_initial) };
        if oscore_conf.is_null() {
            return Err(OscoreConfigError::Unknown);
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

        // Return the valid OscoreConf.
        Ok(Self {
            raw_conf: oscore_conf,
            raw_conf_valid: true,
            initial_recipient,
        })
    }

    /// Return the underlying C representation of the oscore config, if its still marked as valid.
    /// Fails with an error otherwise.
    ///
    /// # Errors
    /// Will return a [OscoreConfigError] if trying to read the raw_config's C struct on an already
    /// invalidated OscoreConf. Please make sure to only use the OscoreConf once as connect_oscore
    /// and oscore_server would free the underlying C struct of this config and mark it as invalid.
    ///
    /// WARNING: If you clear this pointer you have to mark the raw_conf as invalid by setting the
    /// raw_conf_valid to false to prevent a double free()!
    pub(crate) fn as_mut_raw_conf(&mut self) -> Result<*mut coap_oscore_conf_t, OscoreConfigError> {
        if self.raw_conf_valid {
            Ok(self.raw_conf)
        } else {
            Err(OscoreConfigError::Invalid)
        }
    }
}

impl Drop for OscoreConf {
    /// Drop the OscoreConf.
    /// The config will only be dropped, if the raw_struct hasn't been dropped already.
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

/// OscoreRecipient represents a recipient with an ID, and its underlying C struct.
#[derive(Debug)]
pub(crate) struct OscoreRecipient {
    recipient_id: String,
    recipient: *mut coap_bin_const_t,
}

impl OscoreRecipient {
    /// Returns a new OscoreRecipient with a given ID.
    pub(crate) fn new(recipient_id: &str) -> OscoreRecipient {
        // The user only supplies the recipients ID, we will build the recipients C struct here.
        let recipient = coap_bin_const_t {
            length: recipient_id.len(),
            s: recipient_id.as_ptr(),
        };

        let recipient: *mut coap_bin_const_t = Box::into_raw(Box::new(recipient));

        // And then return the newly created recipient.
        OscoreRecipient {
            recipient_id: recipient_id.to_string(),
            recipient,
        }
    }

    /// Returns the raw C struct of the recipient.
    pub(crate) fn get_c_struct(&self) -> *mut coap_bin_const_t {
        self.recipient
    }

    /// Returns the ID of the recipient.
    pub(crate) fn get_recipient_id(&self) -> &str {
        self.recipient_id.as_str()
    }

    /// Drops the recipient from memory.
    /// This will trigger a double free if coap_bin_const_t has already been freed!
    /// WARNING: THIS SHOULD NEVER BE CALLED UNLESS YOU'RE SURE THE coap_bin_const_t HAS NOT BEEN FREED BEFORE!
    pub(crate) fn drop(&self) {
        // SAFETY: Currently, this is only used in 'add_new_oscore_recipient()' in case the recipient
        // is not added to the context. There is currently only one exception, which is filtered out,
        // because trying to add a duplicate recipient to the oscore context would already trigger a
        // free() in libcoap.
        unsafe {
            let _ = Box::from_raw(self.get_c_struct());
        }
    }
}

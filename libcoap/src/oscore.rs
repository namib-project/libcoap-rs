use libcoap_sys::{coap_bin_const_t, coap_new_oscore_conf, coap_oscore_conf_t, coap_str_const_t};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::raw::c_void,
    ptr,
};

use crate::error::OscoreConfigCreationError;

// TODO: An even more insecure place to save the sequence number :)
static OSCORE_SEQ_SAFE_FILE_PATH: &str = "oscore.seq";

extern "C" fn save_seq_num(seq_num: u64, _param: *mut c_void) -> i32 {
    let mut oscore_seq_safe_file = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(OSCORE_SEQ_SAFE_FILE_PATH)
    {
        Ok(file) => file,
        Err(_) => return 0,
    };

    // TODO: refactor this
    if let Err(_) = writeln!(oscore_seq_safe_file, "{}\n", seq_num) {
        return 0;
    }
    if let Err(_) = oscore_seq_safe_file.flush() {
        return 0;
    }

    #[cfg(debug_assertions)]
    println!("DEBUG: Saving sequence number: {}", seq_num);

    1
}

// Represents a oscore conf object which stores the underlying
// coap_oscore_conf_t strcut.
pub(crate) struct OscoreConf {
    conf: *mut coap_oscore_conf_t,
}

impl OscoreConf {
    pub(crate) fn new(seq_initial: u64, oscore_conf_bytes: &[u8]) -> Result<Self, OscoreConfigCreationError> {
        let conf = coap_str_const_t {
            length: oscore_conf_bytes.len(),
            s: oscore_conf_bytes.as_ptr(),
        };

        let seq_initial = match OscoreConf::read_initial_sequence_number() {
            Some(num) => num,
            None => seq_initial,
        };

        // SAFETY: It is expected, that the user provides valid oscore_conf bytes. In case of
        // failure this will return None which will currently
        let oscore_conf = unsafe { coap_new_oscore_conf(conf, Some(save_seq_num), ptr::null_mut(), seq_initial) };

        if oscore_conf.is_null() {
            return Err(OscoreConfigCreationError::Unknown);
        }
        Ok(Self { conf: oscore_conf })
    }
    // TODO: SECURITY
    pub(crate) fn as_mut_raw_conf(&mut self) -> *mut coap_oscore_conf_t {
        self.conf
    }

    fn read_initial_sequence_number() -> Option<u64> {
        let file = match File::open(OSCORE_SEQ_SAFE_FILE_PATH) {
            Ok(f) => f,
            Err(_) => return None,
        };

        let mut reader = BufReader::new(file);

        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            return match line.trim().parse() {
                Ok(num) => Some(num),
                Err(_) => None,
            };
        }
        None
    }
}

#[derive(Debug)]
pub(crate) struct OscoreRecipient {
    recipient_id: String,
    recipient: *mut coap_bin_const_t,
}

impl OscoreRecipient {
    pub(crate) fn new(recipient_id: &str) -> OscoreRecipient {
        let recipient = coap_bin_const_t {
            length: recipient_id.len(),
            s: recipient_id.as_ptr(),
        };

        let recipient: *mut coap_bin_const_t = Box::into_raw(Box::new(recipient));

        OscoreRecipient {
            recipient_id: recipient_id.to_string(),
            recipient,
        }
    }
    pub(crate) fn get_c_struct(&self) -> *mut coap_bin_const_t {
        self.recipient
    }
    pub(crate) fn get_recipient_id(&self) -> &str {
        self.recipient_id.as_str()
    }
    pub(crate) fn drop(&self) {
        // SAFETY: THIS SHOULD NEVER BE CALLED UNLESS YOU'RE SURE THE coap_bin_const_t HAS NOT BEEN
        // FREED BEFORE!
        // Currently this is only used in 'add_new_oscore_recipient()' in case the recipient is not
        // added to the context (which would free the raw pointer when dropped). There is Currently
        // only one expection, which is filtered out, because trying to add a duplicate recipient
        // to the oscore context would already trigger a free() in libcoap
        unsafe {
            let _ = Box::from_raw(self.get_c_struct());
        }
    }
}

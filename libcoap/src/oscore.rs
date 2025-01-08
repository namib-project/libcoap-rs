use libcoap_sys::{coap_new_oscore_conf, coap_oscore_conf_t, coap_oscore_save_seq_num_t, coap_str_const_t};
use std::{ffi::CStr, fs, os::raw::c_void};

// Represents a oscore conf object which stores the underlying
// coap_oscore_conf_t strcut.
pub struct OscoreConf {
    conf: coap_oscore_conf_t,
}

impl OscoreConf {
    pub fn new(seq_initial: u64, oscore_conf_file_path: &str) -> OscoreConf {
        let oscore_conf_file = fs::read_to_string(oscore_conf_file_path).expect("ERROR: File could not be read.");
        let conf = coap_str_const_t {
            length: oscore_conf_file.len(),
            s: oscore_conf_file.as_ptr(),
        };
        let seq_func = None;
        let cvoid: *mut c_void = 0 as *const u64 as *mut c_void;

        // TODO: SECURITY
        let oscore_conf = unsafe { coap_new_oscore_conf(conf, seq_func, cvoid, seq_initial) };

        // TODO: SECURITY
        OscoreConf {
            conf: unsafe { *oscore_conf },
        }
    }
    // TODO: SECURITY
    pub fn as_mut_raw_conf(&mut self) -> &mut coap_oscore_conf_t {
        &mut self.conf
    }
}

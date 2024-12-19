use libcoap_sys::{coap_new_oscore_conf, coap_oscore_conf_t, coap_oscore_save_seq_num_t, coap_str_const_t};
use std::os::raw::c_void;

// TODO: Oscore configuration (currently hardcoded)
static OSCORE_CONFIG: &'static [u8] = b"master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n\
    master_salt,hex,\"9e7ca92223786340\"\n\
    server_id,ascii,\"client\"\n\
    recipient_id,ascii,\"server\"\n\
    replay_window,integer,30\n\
    aead_alg,integer,10\n\
    hkdf_alg,integer,-10\n";
// Represents a oscore conf object which stores the underlying
// coap_oscore_conf_t strcut.
pub struct OscoreConf {
    conf: coap_oscore_conf_t,
}

impl OscoreConf {
    pub fn new(seq_initial: u64) -> OscoreConf {
        let conf = coap_str_const_t {
            length: OSCORE_CONFIG.len(),
            s: OSCORE_CONFIG.as_ptr(),
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

use libc::uint64_t;
use libcoap_sys::{coap_new_oscore_conf, coap_oscore_conf_t, coap_oscore_save_seq_num_t, coap_str_const_t};
use std::{
    ffi::CStr,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::raw::c_void,
    ptr,
};

// TODO: An even more insecure place to save the sequence number :)
static OSCORE_SEQ_SAFE_FILE_PATH: &str = "oscore.seq";

extern "C" fn save_seq_num(seq_num: uint64_t, _param: *mut c_void) -> i32 {
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

    // TODO: remove debug
    println!("DEBUG: Saving sequence number: {}", seq_num);

    1
}

// Represents a oscore conf object which stores the underlying
// coap_oscore_conf_t strcut.
pub struct OscoreConf {
    conf: *mut coap_oscore_conf_t,
}

impl OscoreConf {
    pub fn new(seq_initial: uint64_t, oscore_conf_file_path: &str) -> OscoreConf {
        let oscore_conf_file = fs::read_to_string(oscore_conf_file_path).expect("ERROR: File could not be read.");
        let conf = coap_str_const_t {
            length: oscore_conf_file.len(),
            s: oscore_conf_file.as_ptr(),
        };

        // TODO: see function decleration
        let seq_initial: uint64_t = OscoreConf::read_initial_sequence_number(seq_initial);

        // TODO: SECURITY
        let mut oscore_conf = unsafe { coap_new_oscore_conf(conf, Some(save_seq_num), ptr::null_mut(), seq_initial) };

        // TODO: SECURITY
        OscoreConf {
            conf: unsafe { oscore_conf },
        }
    }
    // TODO: SECURITY
    pub fn as_mut_raw_conf(&mut self) -> *mut coap_oscore_conf_t {
        self.conf
    }

    // TODO: refactor this, maybe we can return an optional instead
    fn read_initial_sequence_number(specified_seq_initial: uint64_t) -> uint64_t {
        let file = match File::open(OSCORE_SEQ_SAFE_FILE_PATH) {
            Ok(f) => f,
            Err(_) => return specified_seq_initial,
        };

        let mut reader = BufReader::new(file);

        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            line.trim().parse().unwrap_or(specified_seq_initial)
        } else {
            specified_seq_initial
        }
    }
}

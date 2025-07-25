use std::ffi::{c_char, CStr, CString};
use std::ptr::slice_from_raw_parts_mut;
use std::rc::Rc;
use std::sync::Arc;
use libcoap_sys::c_stdlib::ptrace_syscall_info;

pub trait PayloadData: 'static {
    // TODO: API can be improved once the ptr_metadata feature is stabilized.
    fn into_raw_ptr(self) -> (usize, *const u8);

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self;
}

impl PayloadData for Box<[u8]> {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), Box::into_raw(self) as *const u8)
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        Box::from_raw(slice_from_raw_parts_mut(ptr as *mut u8, len))
    }
}

impl PayloadData for &'static [u8] {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), self.as_ptr())
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        std::slice::from_raw_parts(ptr, len)
    }
}
impl PayloadData for &'static mut [u8] {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), self.as_ptr())
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        std::slice::from_raw_parts_mut(ptr as *mut u8, len)
    }
}

impl PayloadData for Rc<[u8]> {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), Rc::into_raw(self) as *const u8)
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        Rc::from_raw(slice_from_raw_parts_mut(ptr as *mut u8, len))
    }
}

impl PayloadData for Arc<[u8]> {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), Arc::into_raw(self) as *const u8)
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        Arc::from_raw(slice_from_raw_parts_mut(ptr as *mut u8, len))
    }
}

impl PayloadData for String {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        self.into_bytes().into_boxed_slice().into_raw_ptr()
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        String::from_utf8_unchecked(Box::from_raw_ptr(len, ptr).to_vec())
    }
}

impl PayloadData for &'static str {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), self.as_ptr())
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
    }
}

impl PayloadData for &'static mut str {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.len(), self.as_mut_ptr())
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        core::str::from_utf8_unchecked_mut(core::slice::from_raw_parts_mut(ptr as *mut u8, len))
    }
}

// TODO: c_char can be either u8 or i8 depending on the platform (but it probably doesn't matter
//       here as long as the size is right).
impl PayloadData for &'static CStr {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.count_bytes(), self.as_ptr() as *const u8)
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        CStr::from_bytes_with_nul_unchecked(core::slice::from_raw_parts(ptr, len + 1))
    }
}


impl PayloadData for CString {
    fn into_raw_ptr(self) -> (usize, *const u8) {
        (self.count_bytes(), self.into_raw() as *const u8)
    }

    unsafe fn from_raw_ptr(len: usize, ptr: *const u8) -> Self {
        CString::from_raw(ptr as *mut c_char)
    }
}

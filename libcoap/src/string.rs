use std::ffi::CStr;
use std::marker::PhantomData;
use std::ptr::NonNull;
use libcoap_sys::{coap_delete_string, coap_new_string, coap_str_const_t, coap_string_t};
use crate::mem::OwnedRef;
use core::borrow::Borrow;

pub struct CoapString {
    inner: OwnedRef<'static, coap_string_t>,
}

pub struct CoapStringConst {
    inner: OwnedRef<'static, coap_str_const_t>,
}

pub struct CoapStrRef<'a> {
    raw_ref: coap_str_const_t,
    ref_lifetime_marker: PhantomData<&'a ()>,
}

impl<'a> CoapStrRef<'a> {
    pub fn into_raw(self) -> coap_str_const_t {
        self.raw_ref
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.raw_ref.s, self.raw_ref.length) }
    }
}

pub struct CoapStrRefMut<'a> {
    raw_ref: coap_string_t,
    ref_lifetime_marker: PhantomData<&'a ()>,
}

impl<'a> CoapStrRefMut<'a> {
    pub fn into_raw(self) -> coap_string_t {
        self.raw_ref
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.raw_ref.s, self.raw_ref.length) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.raw_ref.s, self.raw_ref.length) }
    }
}

impl CoapString {
    pub fn new(size: usize) -> Self {
        let inner = unsafe {
            let mut inner_ptr = NonNull::new(coap_new_string(size)).expect("unable to allocate CoapString");
            if !inner_ptr.is_aligned() {
                panic!("libcoap allocation is not aligned")
            }
            OwnedRef::new(inner_ptr.as_mut(), coap_delete_string)
        };

        Self {
            inner
        }
    }

    pub fn with_value(value: impl AsRef<[u8]>) -> Self {
        let value = value.as_ref();

        let mut result = CoapString::new(value.len());

        result.as_bytes_mut().copy_from_slice(value);

        result
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.inner.s, self.inner.length) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.inner.s, self.inner.length) }
    }

    fn as_raw_string(&mut self) -> &coap_string_t {
        self.inner.borrow()
    }
}

impl<T: ToCoapStrRef> From<&T> for CoapString {
    fn from(value: &T) -> Self {
        Self::with_value(value.to_coap_str_ref().as_bytes())
    }
}

pub trait ToCoapStrRef {
    fn to_coap_str_ref(&self) -> CoapStrRef;
}

impl ToCoapStrRef for CoapString {
    fn to_coap_str_ref(&self) -> CoapStrRef {
        CoapStrRef { raw_ref: coap_str_const_t { length: self.inner.length, s: self.inner.s }, ref_lifetime_marker: Default::default() }
    }
}

impl ToCoapStrRef for &[u8] {
    fn to_coap_str_ref(&self) -> CoapStrRef {
        CoapStrRef { raw_ref: coap_str_const_t { length: self.len(), s: self.as_ptr() }, ref_lifetime_marker: Default::default() }
    }
}

impl ToCoapStrRef for Box<[u8]> {
    fn to_coap_str_ref(&self) -> CoapStrRef {
        CoapStrRef { raw_ref: coap_str_const_t { length: self.len(), s: self.as_ptr() }, ref_lifetime_marker: Default::default() }
    }
}

impl ToCoapStrRef for String {
    fn to_coap_str_ref(&self) -> CoapStrRef {
        CoapStrRef { raw_ref: coap_str_const_t { length: self.len(), s: self.as_ptr() }, ref_lifetime_marker: Default::default() }
    }
}

impl ToCoapStrRef for CStr {
    fn to_coap_str_ref(&self) -> CoapStrRef {
        CoapStrRef { raw_ref: coap_str_const_t { length: self.count_bytes(), s: self.as_ptr() as *const u8 }, ref_lifetime_marker: Default::default() }
    }
}


pub trait ToCoapStrRefMut {
    fn to_coap_str_ref_mut(&mut self) -> CoapStrRefMut;
}

impl ToCoapStrRefMut for CoapString {
    fn to_coap_str_ref_mut(&mut self) -> CoapStrRefMut {
        CoapStrRefMut { raw_ref: coap_string_t { length: self.inner.length, s: self.inner.s }, ref_lifetime_marker: Default::default() }
    }
}

impl ToCoapStrRefMut for &mut [u8] {
    fn to_coap_str_ref_mut(&mut self) -> CoapStrRefMut {
        CoapStrRefMut { raw_ref: coap_string_t { length: self.len(), s: self.as_mut_ptr() }, ref_lifetime_marker: Default::default() }
    }
}

impl ToCoapStrRefMut for Box<[u8]> {
    fn to_coap_str_ref_mut(&mut self) -> CoapStrRefMut {
        CoapStrRefMut { raw_ref: coap_string_t { length: self.len(), s: self.as_mut_ptr() }, ref_lifetime_marker: Default::default() }
    }
}


impl ToCoapStrRefMut for String {
    fn to_coap_str_ref_mut(&mut self) -> CoapStrRefMut {
        CoapStrRefMut { raw_ref: coap_string_t { length: self.len(), s: self.as_mut_ptr() }, ref_lifetime_marker: Default::default() }
    }
}

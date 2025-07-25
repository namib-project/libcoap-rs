use std::ptr::NonNull;
use libcoap_sys::{coap_add_optlist_pdu, coap_delete_optlist, coap_insert_optlist, coap_new_optlist, coap_opt_iterator_t, coap_opt_length, coap_opt_t, coap_opt_value, coap_option_next, coap_option_num_t, coap_optlist_t, coap_pdu_t};
use std::borrow::BorrowMut;
use coap_message::MessageOption;
use std::marker::PhantomData;
use crate::error::{MessageConversionError, OptionParsingError};
use crate::message::pdu::Pdu;
use crate::protocol::CoapOptionType;

pub struct Opt<'a> {
    number: coap_option_num_t,
    raw_option: &'a coap_opt_t,
}

impl<'a> Opt<'a> {
    /// SAFETY: `raw_option` must point to a valid instance of `coap_opt_t`.
    pub(crate) unsafe fn new(number: coap_option_num_t, raw_option: &'a coap_opt_t) -> Result<Self, OptionParsingError> {
        // Just some sanity checks that are required to call core::slice::from_raw_parts later on.
        // We perform these checks now, because we can return an error here, while in the
        // MessageOption implementation, we do not return a Result.
        // TODO maybe use coap_opt_parse to validate the length of the option.
        unsafe {
            let opt_value = coap_opt_value(raw_option);
            // Panicking here is fine, because the return value of coap_opt_length should be
            // equivalent to size_t, which should be convertible to usize (at least for all current
            // platforms, see https://doc.rust-lang.org/core/ffi/type.c_size_t.html).
            let opt_len = usize::try_from(coap_opt_length(raw_option))
                .expect("return value of coap_opt_len could not be converted to usize");
            if opt_value.is_null() || !opt_value.is_aligned() || opt_len > isize::MAX as usize {
                return Err(OptionParsingError::MalformedOption);
            }
        }
        Ok(Self { number, raw_option })
    }
}

impl<'a> MessageOption for Opt<'a> {
    fn number(&self) -> u16 {
        self.number
    }

    fn value(&self) -> &[u8] {
        // SAFETY: By the constructor contract, raw_option contains a valid coap_opt_t, so calling
        // coap_opt_value and coap_opt_length is safe.
        // coap_opt_value may return a null value if the option is invalid, but we have checked
        // that this is not the case in the constructor.
        unsafe {
            let opt_value = coap_opt_value(self.raw_option);
            // Panicking is fine here, because coap_opt_length should always return a size_t, and if
            // C's size_t does not match usize, we can't proceed.
            let opt_len = usize::try_from(coap_opt_length(self.raw_option))
                .expect("return value of coap_opt_len could not be converted to usize");

            if opt_value.is_null() || !opt_value.is_aligned() || opt_len > isize::MAX as usize {
                unreachable!()
            }

            core::slice::from_raw_parts(opt_value, opt_len)
        }
    }
}

pub struct OptIterator<'a> {
    raw_iter: Option<coap_opt_iterator_t>,
    last_error: Option<OptionParsingError>,
    // We don't actually need the reference to the PDU here, but the raw iterator references memory
    // contained by the raw PDU, so we keep this reference to limit the lifetime of this struct
    // to some existing shared reference to the raw PDU.
    _pdu_ref_lifetime: PhantomData<&'a coap_pdu_t>,
}

impl<'a> OptIterator<'a> {
    /// # Safety
    /// raw_iter must be None or a properly initialized instance of coap_opt_iterator_t.
    ///
    /// Additionally, you must ensure that for the entire lifetime of this iterator, the underlying
    /// coap_pdu_t is treated as if the iterator owns a shared reference to it (this should already
    /// be statically enforced for safe functions, but is something to keep in mind when calling C
    /// functions).
    pub(crate) unsafe fn new(raw_iter: Option<coap_opt_iterator_t>, _pdu_ref: &'a coap_pdu_t) -> Self {
        Self {
            raw_iter,
            last_error: None,
            _pdu_ref_lifetime: Default::default(),
        }
    }

    pub fn parsing_error(&self) -> Option<&OptionParsingError> {
        self.last_error.as_ref()
    }
}

impl<'a> Iterator for OptIterator<'a> {
    type Item = Opt<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(raw_iter) = self.raw_iter.as_mut() {
            let raw_option = unsafe { coap_option_next(raw_iter) };
            let option = unsafe { raw_option.as_ref().map(|v| Opt::new(raw_iter.number, v)).transpose() };
            match option {
                Ok(v) => v,
                Err(err) => {
                    self.last_error = Some(err);
                    None
                }
            }
        } else {
            None
        }
    }
}


pub struct Optlist {
    raw_optlist: *mut coap_optlist_t,
}

impl Optlist {
    pub fn new() -> Self {
        Self {
            raw_optlist: std::ptr::null_mut()
        }
    }

    pub fn insert(&mut self, number: CoapOptionType, value: &[u8]) -> Result<(), MessageConversionError> {
        unsafe {
            let option = NonNull::new(coap_new_optlist(number.to_raw_option_num(), value.len(), value.as_ptr())).ok_or(MessageConversionError::Unknown)?;

            (coap_insert_optlist(&mut self.raw_optlist, option.as_ptr()) == 1).then_some(()).ok_or(MessageConversionError::Unknown)
        }
    }

    pub(crate) fn add_to_pdu<T: BorrowMut<coap_pdu_t>>(&mut self, pdu: &mut Pdu<T>) -> Result<(), MessageConversionError> {
        unsafe {
            (coap_add_optlist_pdu(pdu.raw_pdu.borrow_mut(), &mut self.raw_optlist) == 1).then_some(()).ok_or(MessageConversionError::Unknown)
        }
    }
}

impl Drop for Optlist {
    fn drop(&mut self) {
        // SAFETY: Function is always safe to call (even with null pointer).
        unsafe {
            coap_delete_optlist(self.raw_optlist)
        }
    }
}

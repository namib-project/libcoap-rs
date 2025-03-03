use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};
use std::ptr::NonNull;
use coap_message::{MessageOption, MinimalWritableMessage, ReadableMessage, SeekWritableMessage};
use libcoap_sys::{coap_add_data, coap_add_data_large_request, coap_add_option, coap_delete_pdu, coap_get_data, coap_insert_optlist, coap_new_optlist, coap_new_pdu, coap_opt_iterator_t, coap_opt_length, coap_opt_t, coap_opt_value, coap_option_iterator_init, coap_option_next, coap_option_num_t, coap_optlist_t, coap_pdu_get_code, coap_pdu_init, coap_pdu_set_code, coap_pdu_t};

use crate::{
    error::{MessageConversionError, OptionParsingError},
    protocol::{CoapMessageCode, CoapOptionType},
    session::CoapSession,
};
use crate::error::MessageCreationError;
use crate::mem::OwnedCoapStructRef;
use crate::protocol::{CoapMessageType, CoapRequestCode, CoapToken};
use crate::session::CoapSessionCommon;

pub struct Pdu<T: Borrow<coap_pdu_t>> {
    /// Reference to the raw PDU object that contains the actual data.
    raw_pdu: T,
    code: CoapMessageCode,
}

pub struct PduBuilder<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t> = &'static coap_pdu_t> {
    pdu: Pdu<T>,
    /// If this is a response to a previous message: The message that is responded to.
    /// Required in order to use large data responses.
    in_response_to: Option<&'r Pdu<R>>,
    session: &'r CoapSession<'r>,
    payload: Option<Box<[u8]>>,
    optlist: *mut coap_optlist_t,
}

impl<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t>> PduBuilder<'r, T, R> {
    pub fn with_request_pdu(pdu: Pdu<T>, session: &'r CoapSession<'r>) -> Result<Self, MessageConversionError> {
        Ok(Self {
            pdu,
            in_response_to: None,
            session,
            payload: None,
            optlist: std::ptr::null_mut(),
        })
    }

    pub fn with_response_pdu(pdu: Pdu<T>, in_response_to: &'r Pdu<R>, session: &'r CoapSession<'r>) -> Result<Self, MessageConversionError> {
        Ok(Self {
            pdu,
            in_response_to: Some(in_response_to),
            session,
            payload: None,
            optlist: std::ptr::null_mut(),
        })
    }

    pub fn build(self) -> Result<Pdu<T>, MessageConversionError> {
        todo!()
    }
}

impl<'a> Pdu<OwnedCoapStructRef<'static, coap_pdu_t>> {
    pub fn new(type_: CoapMessageType, code: CoapMessageCode, mid: std::ffi::c_int, max_size: usize) -> Result<Self, MessageCreationError> {
        // SAFETY: calling coap_pdu_init with valid arguments, result is either NULL (which will be
        // converted into a MessageCreationError) or should be convertible to a reference.
        // PDU lifetime may be arbitrary, as we are the ones who destruct it
        let raw_pdu = unsafe {
            OwnedCoapStructRef::new(
                NonNull::new(coap_pdu_init(type_.to_raw_pdu_type(), code.to_raw_pdu_code(), mid, max_size)).ok_or(MessageCreationError::Unknown)?.as_mut(),
                coap_delete_pdu,
            )
        };

        Ok(Self {
            raw_pdu: raw_pdu,
            code,
        })
    }

    pub fn with_request_session(type_: CoapMessageType, code: CoapRequestCode, session: &CoapSession) -> Result<Self, MessageCreationError> {
        // SAFETY: calling coap_pdu_init with valid arguments, result is either NULL (which will be
        // converted into a MessageCreationError) or should be convertible to a reference.
        // PDU lifetime may be arbitrary, as we are the ones who destruct it
        let raw_pdu = unsafe { OwnedCoapStructRef::new(NonNull::new(coap_new_pdu(type_.to_raw_pdu_type(), code.into(), session.raw_session_mut())).ok_or(MessageCreationError::Unknown)?.as_mut(), coap_delete_pdu) };

        Ok(Self {
            raw_pdu: raw_pdu,
            code: code.into(),
        })
    }
}

impl<'r, T: Borrow<coap_pdu_t>> Pdu<T> {
    /// SAFETY: Pointers referenced in raw_pdu's coap_pdu_t instance must be valid.
    unsafe fn with_raw_pdu(raw_pdu: T) -> Result<Self, MessageConversionError> {
        // SAFETY: calling coap_pdu_get_code with any valid PDU is safe.
        let code = CoapMessageCode::try_from(unsafe { coap_pdu_get_code(raw_pdu.borrow()) })?;

        // Check message size (because we can still return an error here, but can't do so in the
        // ReadableMessage trait impl).
        let mut payload_len = 0;
        let mut payload_ptr = std::ptr::null();
        if unsafe { coap_get_data(raw_pdu.borrow(), &mut payload_len, &mut payload_ptr) } == 1
            && payload_len > isize::MAX as usize
        {
            return Err(MessageConversionError::TooLarge(payload_len));
        }

        Ok(Self {
            raw_pdu,
            code,
        })
    }

    pub(crate) fn into_raw_pdu(self) -> T {
        self.raw_pdu
    }
}

impl<T: Borrow<coap_pdu_t>> ReadableMessage for Pdu<T> {
    type Code = CoapMessageCode;
    type MessageOption<'a>
        = Opt<'a>
    where
        T: 'a;
    type OptionsIter<'a>
        = OptIterator<'a>
    where
        T: 'a;

    fn code(&self) -> Self::Code {
        self.code
    }

    fn options(&self) -> Self::OptionsIter<'_> {
        let mut raw_iter: MaybeUninit<coap_opt_iterator_t> = MaybeUninit::uninit();
        // SAFETY: raw_pdu points to an initialized CoAP PDU by construction, raw_iter will be
        // initialized by coap_option_iterator_init and may therefore be uninitialized before, and
        // the filter parameter is optional may be null.
        if unsafe { coap_option_iterator_init(self.raw_pdu.borrow(), raw_iter.as_mut_ptr(), std::ptr::null()) }
            .is_null()
        {
            // If the return value is null, no options have been set.
            // SAFETY: Calling with None as raw iterator is always safe.
            unsafe { OptIterator::new(None, self.raw_pdu.borrow()) }
        } else {
            // SAFETY: If coap_option_iterator_init returns a non-null value, it has successfully
            // initialized raw_iter.
            unsafe { OptIterator::new(Some(raw_iter.assume_init()), self.raw_pdu.borrow()) }
        }
    }

    fn payload(&self) -> &[u8] {
        let mut payload_len = 0;
        let mut payload_ptr = std::ptr::null();
        if unsafe { coap_get_data(self.raw_pdu.borrow(), &mut payload_len, &mut payload_ptr) } == 0
            || payload_ptr.is_null()
        {
            &[]
        } else if payload_len > isize::MAX as usize {
            // We checked the condition above in the constructor, so it shouldn't apply here.
            // TODO also check this when creating a PDU payload.
            unreachable!()
        } else {
            unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) }
        }
    }
}

impl<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t>> MinimalWritableMessage for PduBuilder<'r, T, R> {
    type AddOptionError = MessageConversionError;
    type Code = CoapMessageCode;
    type OptionNumber = CoapOptionType;
    type SetPayloadError = MessageConversionError;
    type UnionError = MessageConversionError;

    fn set_code(&mut self, code: Self::Code) {
        unsafe { coap_pdu_set_code(self.pdu.raw_pdu.borrow_mut(), code.to_raw_pdu_code()) }
    }

    fn add_option(&mut self, number: Self::OptionNumber, value: &[u8]) -> Result<(), Self::AddOptionError> {
        unsafe {
            let option = NonNull::new(coap_new_optlist(number.to_raw_option_num(), value.len(), value.as_ptr())).ok_or(MessageConversionError::Unknown)?;

            (coap_insert_optlist(&mut self.optlist, option.as_ptr()) == 1).then_some(()).ok_or(MessageConversionError::Unknown)
        }
    }

    fn set_payload(&mut self, data: &[u8]) -> Result<(), Self::SetPayloadError> {
        let data = Vec::from(data).into_boxed_slice();
        self.payload = Some(data);
        Ok(())
    }
}

impl<'r, T: BorrowMut<coap_pdu_t>, R: Borrow<coap_pdu_t>> SeekWritableMessage for PduBuilder<'r, T, R> {}

pub struct Opt<'a> {
    number: coap_option_num_t,
    raw_option: &'a coap_opt_t,
}

impl<'a> Opt<'a> {
    /// SAFETY: `raw_option` must point to a valid instance of `coap_opt_t`.
    unsafe fn new(number: coap_option_num_t, raw_option: &'a coap_opt_t) -> Result<Self, OptionParsingError> {
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
    unsafe fn new(raw_iter: Option<coap_opt_iterator_t>, _pdu_ref: &'a coap_pdu_t) -> Self {
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
                },
            }
        } else {
            None
        }
    }
}

use std::any::Any;
use libcoap_sys::{coap_add_data, coap_add_data_large_request, coap_add_data_large_response, coap_add_option, coap_bin_const_t, coap_delete_pdu, coap_delete_string, coap_get_data, coap_new_pdu, coap_new_string, coap_opt_iterator_t, coap_option_iterator_init, coap_pdu_get_code, coap_pdu_init, coap_pdu_set_code, coap_pdu_t, coap_release_large_data_t, coap_session_t, coap_str_const_t, coap_string_t};
use std::ptr::NonNull;
use std::borrow::{Borrow, BorrowMut};
use std::ffi::{c_int, c_void, CStr};
use std::fmt::Debug;
use coap_message::{MinimalWritableMessage, ReadableMessage};
use std::mem::MaybeUninit;
use std::marker::PhantomData;
use std::time::Duration;
use crate::CoapResource;
use crate::error::{MessageConversionError, MessageCreationError, OptionParsingError};
use crate::mem::OwnedRef;
use crate::message::option_handling::{Opt, OptIterator};
use crate::message::payload::PayloadData;
use crate::protocol::{CoapContentFormat, CoapMessageCode, CoapMessageType, CoapOptionType, CoapRequestCode, CoapRequestType, CoapResponseCode, CoapResponseType, ContentFormat, ETag};
use crate::resource::UntypedCoapResource;
use crate::session::{CoapSession, CoapSessionCommon};

pub trait PduKind: 'static {
    type Code: Into<CoapMessageCode>;
    type MessageType: Into<CoapMessageType>;
}

pub struct Request;

pub struct Response;

impl PduKind for Request {
    type Code = CoapRequestCode;
    type MessageType = CoapRequestType;
}

impl PduKind for Response {
    type Code = CoapResponseCode;
    type MessageType = CoapResponseType;
}

pub struct Pdu<Kind: PduKind, RawPduRef: Borrow<coap_pdu_t>> {
    /// Reference to the raw PDU object that contains the actual data.
    raw_pdu: RawPduRef,
    code: CoapMessageCode,
    kind: PhantomData<Kind>,
}

impl<Kind: PduKind> Pdu<Kind, OwnedRef<'static, coap_pdu_t>> {
    fn new(code: CoapMessageCode, type_: CoapMessageType, session: &mut CoapSession) -> Result<Self, MessageCreationError> {

        // SAFETY: calling coap_pdu_init with valid arguments, result is either NULL (which will be
        // converted into a MessageCreationError) or should be convertible to a reference.
        // PDU lifetime may be arbitrary, as we are the ones who destruct it
        let raw_pdu = unsafe {
            OwnedRef::new(
                NonNull::new(coap_new_pdu(type_.to_raw_pdu_type(), code.to_raw_pdu_code(), session.raw_session_mut())).ok_or(MessageCreationError::Unknown)?.as_mut(),
                coap_delete_pdu,
            )
        };

        Ok(Self {
            raw_pdu,
            code,
            kind: Default::default(),
        })
    }

    fn with_mid_and_max_size(code: CoapMessageCode, type_: CoapMessageType, mid: std::ffi::c_int, max_size: usize) -> Result<Self, MessageCreationError> {

        // SAFETY: calling coap_pdu_init with valid arguments, result is either NULL (which will be
        // converted into a MessageCreationError) or should be convertible to a reference.
        // PDU lifetime may be arbitrary, as we are the ones who destruct it
        let raw_pdu = unsafe {
            OwnedRef::new(
                NonNull::new(coap_pdu_init(type_.to_raw_pdu_type(), code.to_raw_pdu_code(), mid, max_size)).ok_or(MessageCreationError::Unknown)?.as_mut(),
                coap_delete_pdu,
            )
        };

        Ok(Self {
            raw_pdu,
            code,
            kind: Default::default(),
        })
    }
}

impl Pdu<Request, OwnedRef<'static, coap_pdu_t>> {
    pub fn new_request(code: CoapRequestCode, type_: CoapRequestType, session: &mut CoapSession) -> Result<Self, MessageCreationError> {
        Self::new(code.into(), type_.into(), session)
    }

    pub fn new_request_with_mid_and_max_size(code: CoapRequestCode, type_: CoapRequestType, mid: std::ffi::c_int, max_size: usize) -> Result<Self, MessageCreationError> {
        Self::with_mid_and_max_size(code.into(), type_.into(), mid, max_size)
    }
}

// Note: There rarely is a reason to actually create a response PDU manually; in virtually all
// cases, this is done by libcoap before calling the resource handler.
// TODO: This should be mentioned in the documentation.
impl Pdu<Response, OwnedRef<'static, coap_pdu_t>> {
    pub fn new_response(code: CoapResponseCode, type_: CoapResponseType, session: &mut CoapSession) -> Result<Self, MessageCreationError> {
        Self::new(code.into(), type_.into(), session)
    }

    pub fn new_response_with_mid_and_max_size(code: CoapResponseCode, type_: CoapResponseType, mid: std::ffi::c_int, max_size: usize) -> Result<Self, MessageCreationError> {
        Self::with_mid_and_max_size(code.into(), type_.into(), mid, max_size)
    }
}

impl<K: PduKind, RawPduRef: Borrow<coap_pdu_t>> Pdu<K, RawPduRef> {
    /// SAFETY: Pointers referenced in raw_pdu's coap_pdu_t instance must be valid.
    unsafe fn with_raw_pdu(raw_pdu: RawPduRef) -> Result<Self, MessageConversionError> {
        // SAFETY: calling coap_pdu_get_code with any valid PDU is safe.
        let code = CoapMessageCode::try_from(unsafe { coap_pdu_get_code(raw_pdu.borrow()) })?;

        // Check message size (because we can still return an error here, but can't do so in the
        // ReadableMessage trait impl).
        // Payload length must not exceed isize::MAX to be convertible into a slice (see
        // core::slice::from_raw_parts).
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
            kind: Default::default(),
        })
    }

    pub(crate) fn into_raw_pdu(self) -> RawPduRef {
        self.raw_pdu
    }
}

impl<Kind: PduKind, RawPduRef: Borrow<coap_pdu_t>> ReadableMessage for Pdu<Kind, RawPduRef> {
    type Code = CoapMessageCode;
    type MessageOption<'a>
    = Opt<'a>
    where
        RawPduRef: 'a,
        Kind: 'a;
    type OptionsIter<'a>
    = OptIterator<'a>
    where
        RawPduRef: 'a,
        Kind: 'a;

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
            // This should never happen, because:
            // - We checked the condition in the constructor.
            // - If the payload has been set by a call to set_payload (or its variants), we have
            //   checked that the new value is not larger than isize::MAX during these calls.
            unreachable!()
        } else {
            unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) }
        }
    }
}

impl<Kind: PduKind, RawPduRef: BorrowMut<coap_pdu_t>> MinimalWritableMessage for Pdu<Kind, RawPduRef> {
    type Code = Kind::Code;
    type OptionNumber = CoapOptionType;
    type AddOptionError = MessageConversionError;
    type SetPayloadError = MessageConversionError;
    type UnionError = MessageConversionError;

    fn set_code(&mut self, code: Self::Code) {
        self.code = code.into();
        unsafe { coap_pdu_set_code(self.raw_pdu.borrow_mut(), self.code.to_raw_pdu_code()) }
    }

    fn add_option(&mut self, number: Self::OptionNumber, value: &[u8]) -> Result<(), Self::AddOptionError> {
        if unsafe {
            coap_add_option(self.raw_pdu.borrow_mut(), number.to_raw_option_num(), value.len(), value.as_ptr())
        } == 0 {
            Err(MessageConversionError::Unknown)
        } else {
            Ok(())
        }
    }

    fn set_payload(&mut self, data: &[u8]) -> Result<(), Self::SetPayloadError> {
        if data.len() > isize::MAX as usize {
            return Err(MessageConversionError::TooLarge(data.len()));
        }
        if unsafe {
            coap_add_data(self.raw_pdu.borrow_mut(), data.len(), data.as_ptr())
        } != 1 {
            Err(MessageConversionError::Unknown)
        } else {
            Ok(())
        }
    }
}

impl<RawPduRef: BorrowMut<coap_pdu_t>> Pdu<Request, RawPduRef> {
    fn set_payload_large_request<T: PayloadData>(&mut self, data: T, session: &CoapSession) -> Result<(), MessageConversionError>
    {
        let
            (data_len, data_ptr) = data.into_raw_ptr();
        if data_len > isize::MAX as usize {
            drop(unsafe { T::from_raw_ptr(data_len, data_ptr) });
            return Err(MessageConversionError::TooLarge(data_len));
        }
        // Create a data structure to hold information about the data's length and pointer.
        // We need to know the length of the provided data to restore (and then drop) the payload in
        // the destructor (request_data_release_func).
        // It would be nicer if we didn't have to create a new allocation/Box just to manage
        // information about a different allocation, but since we can't pass fat pointers through
        // FFI and libcoap may hold on to this data for a while, there is no easy way to handle this
        // differently.
        // Do not add release function if std::mem::needs_drop == false.
        let (data_release_func, data_release_ptr): (coap_release_large_data_t, *mut c_void) = if core::mem::needs_drop::<T>() {
            let data_info = Box::new(coap_bin_const_t { length: data_len, s: data_ptr });
            (Some(request_data_release_func::<T>), Box::into_raw(data_info) as *mut c_void)
        } else {
            (None, std::ptr::null_mut())
        };
        if unsafe {
            coap_add_data_large_request(
                session.raw_session_mut(),
                self.raw_pdu.borrow_mut(),
                data_len,
                data_ptr,
                data_release_func,
                data_release_ptr,
            )
        } != 1 {
            Err(MessageConversionError::Unknown)
        } else {
            Ok(())
        }
    }
}

impl<RawPduRef: BorrowMut<coap_pdu_t>> Pdu<Response, RawPduRef> {
    fn set_payload_large_response<T: PayloadData, D: Any + Debug, RP: Borrow<coap_pdu_t>>(
        &mut self,
        data: T,
        session: &CoapSession,
        resource: &mut CoapResource<D>,
        in_response_to: Pdu<Request, RP>,
        query: Option<String>,
        media_type: CoapContentFormat,
        max_age: Option<Duration>,
        etag: Option<ETag>,
    ) -> Result<(), MessageConversionError> {
        let
            (data_len, data_ptr) = data.into_raw_ptr();
        if data_len > isize::MAX as usize {
            drop(unsafe { T::from_raw_ptr(data_len, data_ptr) });
            return Err(MessageConversionError::TooLarge(data_len));
        }
        let max_age = max_age.map(|age| c_int::try_from(age.as_secs())
            .map_err(|_e| MessageConversionError::InvalidOptionValue(Some(CoapOptionType::MaxAge), OptionParsingError::TooLong)))
            .transpose()?
            .unwrap_or(-1);
        // Create a data structure to hold information about the data's length and pointer.
        // We need to know the length of the provided data to restore (and then drop) the payload in
        // the destructor (request_data_release_func).
        // It would be nicer if we didn't have to create a new allocation/Box just to manage
        // information about a different allocation, but since we can't pass fat pointers through
        // FFI and libcoap may hold on to this data for a while, there is no easy way to handle this
        // differently.
        // Do not add release function if std::mem::needs_drop == false.
        let (data_release_func, data_release_ptr): (coap_release_large_data_t, *mut c_void) = if core::mem::needs_drop::<T>() {
            let data_info = Box::new(coap_bin_const_t { length: data_len, s: data_ptr });
            (Some(request_data_release_func::<T>), Box::into_raw(data_info) as *mut c_void)
        } else {
            (None, std::ptr::null_mut())
        };
        let query = coap_string_t {
            
        }
        if unsafe {
            coap_add_data_large_response(
                resource.raw_resource(),
                session.raw_session_mut(),
                in_response_to.raw_pdu.borrow(),
                self.raw_pdu.borrow_mut(),
                todo!(),
                media_type.into(),
                max_age,
                etag.unwrap_or(0),
                data_len,
                data_ptr,
                data_release_func,
                data_release_ptr,
            )
        } != 1 {
            Err(MessageConversionError::Unknown)
        } else {
            Ok(())
        }
    }
}

unsafe extern "C" fn request_data_release_func<T: PayloadData>(_session: *mut coap_session_t, app_ptr: *mut ::std::os::raw::c_void) {
    unsafe {
        let data_info = Box::from_raw(app_ptr as *mut coap_bin_const_t);
        drop(T::from_raw_ptr(data_info.length, data_info.s));
    }
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * message.rs - Types related to CoAP messages.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::{ffi::c_void, mem::MaybeUninit, slice::Iter};

use num_traits::FromPrimitive;

use libcoap_sys::{
    coap_add_data, coap_add_data_large_request, coap_add_optlist_pdu, coap_add_token, coap_delete_optlist,
    coap_delete_pdu, coap_get_data, coap_insert_optlist, coap_new_optlist, coap_opt_length, coap_opt_t, coap_opt_value,
    coap_option_iterator_init, coap_option_next, coap_option_num_t, coap_optlist_t, coap_pdu_get_code,
    coap_pdu_get_mid, coap_pdu_get_token, coap_pdu_get_type, coap_pdu_init, coap_pdu_set_code, coap_pdu_set_type,
    coap_pdu_t, coap_session_t,
};

use crate::types::{decode_var_len_u16, decode_var_len_u32, encode_var_len_u16, encode_var_len_u32, encode_var_len_u8};
use crate::{
    error::{MessageConversionError, OptionValueError},
    protocol::{
        Block, CoapMatch, CoapMessageCode, CoapMessageType, CoapOptionNum, CoapOptionType, ContentFormat, ETag,
        HopLimit, MaxAge, NoResponse, Observe, ProxyScheme, ProxyUri, Size, UriHost, UriPath, UriPort, UriQuery,
    },
    request::{CoapRequest, CoapResponse},
    session::CoapSessionCommon,
    types::CoapMessageId,
};

/// Representation of a CoAP option including its value.
///
/// For an enum describing the possible option types (and their associated option numbers), see
/// [CoapOptionType], for the data type representing option numbers, see [CoapOptionNum]
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum CoapOption {
    IfMatch(CoapMatch),
    IfNoneMatch,
    UriHost(UriHost),
    UriPort(UriPort),
    UriPath(UriPath),
    UriQuery(UriQuery),
    LocationPath(UriPath),
    LocationQuery(UriQuery),
    ProxyUri(ProxyUri),
    ProxyScheme(ProxyScheme),
    ContentFormat(ContentFormat),
    Accept(ContentFormat),
    Size1(Size),
    Size2(Size),
    Block1(Block),
    Block2(Block),
    // TODO
    // OsCore
    HopLimit(HopLimit),
    NoResponse(NoResponse),
    ETag(ETag),
    MaxAge(MaxAge),
    Observe(Observe),
    Other(CoapOptionNum, Box<[u8]>),
}

impl CoapOption {
    /// Create a CoAP option from its raw representation in the C library.
    ///
    /// # Safety
    /// `opt` must be a valid pointer to a well formed coap_opt_t value as returned by
    /// [coap_option_next()].
    pub unsafe fn from_raw_opt(
        number: coap_option_num_t,
        opt: *const coap_opt_t,
    ) -> Result<CoapOption, OptionValueError> {
        let value = Vec::from(std::slice::from_raw_parts(
            coap_opt_value(opt),
            coap_opt_length(opt) as usize,
        ));
        match CoapOptionType::try_from(number) {
            Ok(opt_type) => {
                if opt_type.min_len() > value.len() {
                    return Err(OptionValueError::TooShort);
                } else if opt_type.max_len() < value.len() {
                    return Err(OptionValueError::TooLong);
                }
                match opt_type {
                    CoapOptionType::IfMatch => Ok(CoapOption::IfMatch(if value.is_empty() {
                        CoapMatch::Empty
                    } else {
                        CoapMatch::ETag(value.into_boxed_slice())
                    })),
                    CoapOptionType::UriHost => Ok(CoapOption::UriHost(String::from_utf8(value)?)),
                    CoapOptionType::ETag => Ok(CoapOption::ETag(value.into_boxed_slice())),
                    CoapOptionType::IfNoneMatch => Ok(CoapOption::IfNoneMatch),
                    CoapOptionType::UriPort => Ok(CoapOption::UriPort(decode_var_len_u16(value.as_slice()))),
                    CoapOptionType::LocationPath => Ok(CoapOption::LocationPath(String::from_utf8(value)?)),
                    CoapOptionType::UriPath => Ok(CoapOption::UriPath(String::from_utf8(value)?)),
                    CoapOptionType::ContentFormat => {
                        Ok(CoapOption::ContentFormat(decode_var_len_u16(value.as_slice())))
                    },
                    CoapOptionType::MaxAge => Ok(CoapOption::MaxAge(decode_var_len_u32(value.as_slice()))),
                    CoapOptionType::UriQuery => Ok(CoapOption::UriQuery(String::from_utf8(value)?)),
                    CoapOptionType::Accept => Ok(CoapOption::Accept(decode_var_len_u16(value.as_slice()))),
                    CoapOptionType::LocationQuery => Ok(CoapOption::LocationQuery(String::from_utf8(value)?)),
                    CoapOptionType::ProxyUri => Ok(CoapOption::ProxyUri(String::from_utf8(value)?)),
                    CoapOptionType::ProxyScheme => Ok(CoapOption::ProxyScheme(String::from_utf8(value)?)),
                    CoapOptionType::Size1 => Ok(CoapOption::Size1(decode_var_len_u32(value.as_slice()))),
                    CoapOptionType::Size2 => Ok(CoapOption::Size2(decode_var_len_u32(value.as_slice()))),
                    CoapOptionType::Block1 => Ok(CoapOption::Block1(decode_var_len_u32(value.as_slice()))),
                    CoapOptionType::Block2 => Ok(CoapOption::Block2(decode_var_len_u32(value.as_slice()))),
                    CoapOptionType::HopLimit => Ok(CoapOption::HopLimit(decode_var_len_u16(value.as_slice()))),
                    CoapOptionType::NoResponse => Ok(CoapOption::Size2(decode_var_len_u32(value.as_slice()))),
                    CoapOptionType::Observe => Ok(CoapOption::Observe(decode_var_len_u32(value.as_slice()))),
                }
            },
            _ => Ok(CoapOption::Other(number, value.into_boxed_slice())),
        }
    }

    /// Returns the option number associated with this option.
    pub fn number(&self) -> CoapOptionNum {
        match self {
            CoapOption::IfMatch(_) => CoapOptionType::IfMatch as u16,
            CoapOption::IfNoneMatch => CoapOptionType::IfNoneMatch as u16,
            CoapOption::UriHost(_) => CoapOptionType::UriHost as u16,
            CoapOption::UriPort(_) => CoapOptionType::UriPort as u16,
            CoapOption::UriPath(_) => CoapOptionType::UriPath as u16,
            CoapOption::UriQuery(_) => CoapOptionType::UriQuery as u16,
            CoapOption::LocationPath(_) => CoapOptionType::LocationPath as u16,
            CoapOption::LocationQuery(_) => CoapOptionType::LocationQuery as u16,
            CoapOption::ProxyUri(_) => CoapOptionType::ProxyUri as u16,
            CoapOption::ProxyScheme(_) => CoapOptionType::ProxyScheme as u16,
            CoapOption::ContentFormat(_) => CoapOptionType::ContentFormat as u16,
            CoapOption::Accept(_) => CoapOptionType::Accept as u16,
            CoapOption::Size1(_) => CoapOptionType::Size1 as u16,
            CoapOption::Size2(_) => CoapOptionType::Size2 as u16,
            CoapOption::Block1(_) => CoapOptionType::Block1 as u16,
            CoapOption::Block2(_) => CoapOptionType::Block2 as u16,
            CoapOption::HopLimit(_) => CoapOptionType::HopLimit as u16,
            CoapOption::NoResponse(_) => CoapOptionType::NoResponse as u16,
            CoapOption::ETag(_) => CoapOptionType::ETag as u16,
            CoapOption::MaxAge(_) => CoapOptionType::MaxAge as u16,
            CoapOption::Observe(_) => CoapOptionType::Observe as u16,
            CoapOption::Other(num, _) => *num,
        }
    }

    /// Converts the option into a `Box<[u8]>` containing the value bytes.
    pub fn into_value_bytes(self) -> Result<Box<[u8]>, OptionValueError> {
        let num = self.number();
        let bytes = match self {
            CoapOption::IfMatch(val) => match val {
                CoapMatch::ETag(tag) => tag,
                CoapMatch::Empty => Box::new([]),
            },
            CoapOption::IfNoneMatch => Box::new([]),
            CoapOption::UriHost(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::UriPort(value) => encode_var_len_u16(value),
            CoapOption::UriPath(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::UriQuery(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::LocationPath(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::LocationQuery(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::ProxyUri(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::ProxyScheme(value) => value.into_boxed_str().into_boxed_bytes(),
            CoapOption::ContentFormat(value) => encode_var_len_u16(value),
            CoapOption::Accept(value) => encode_var_len_u16(value),
            CoapOption::Size1(value) => encode_var_len_u32(value),
            CoapOption::Size2(value) => encode_var_len_u32(value),
            CoapOption::Block1(value) => encode_var_len_u32(value),
            CoapOption::Block2(value) => encode_var_len_u32(value),
            CoapOption::HopLimit(value) => encode_var_len_u16(value),
            CoapOption::NoResponse(value) => encode_var_len_u8(value),
            CoapOption::ETag(value) => value,
            CoapOption::MaxAge(value) => encode_var_len_u32(value),
            CoapOption::Observe(value) => encode_var_len_u32(value),
            CoapOption::Other(_num, data) => data,
        };
        if let Some(opt_type) = <CoapOptionType as FromPrimitive>::from_u16(num) {
            if bytes.len() < opt_type.min_len() {
                return Err(OptionValueError::TooShort);
            } else if bytes.len() > opt_type.max_len() {
                return Err(OptionValueError::TooLong);
            }
        }
        Ok(bytes)
    }

    /// Converts this option into a raw coap_optlist_t instance, suitable for addition to a raw
    /// coap_pdu_t.
    pub fn into_optlist_entry(self) -> Result<*mut coap_optlist_t, OptionValueError> {
        let num = self.number();
        let value = self.into_value_bytes()?;
        Ok(unsafe { coap_new_optlist(num, value.len(), value.as_ptr()) })
    }
}

/// Interface for CoAP messages common between requests, responses and other messages.
pub trait CoapMessageCommon {
    /// Add the supplied CoAP option to this message.
    fn add_option(&mut self, option: CoapOption) {
        self.as_message_mut().options.push(option);
    }

    /// Clear the list of options that were added to this message using [add_option()](CoapMessageCommon::add_option()).
    fn clear_options(&mut self) {
        self.as_message_mut().options.clear();
    }

    /// Returns an iterator over the options contained in this message.
    fn options_iter(&self) -> Iter<CoapOption> {
        self.as_message().options.iter()
    }

    /// Returns the CoAP message type (confirmable, non-confirmable, acknowledgement, rst) of this message.
    fn type_(&self) -> CoapMessageType {
        self.as_message().type_
    }

    /// Sets the CoAP message type (confirmable, non-confirmable, acknowledgement, rst) of this message.
    fn set_type_(&mut self, type_: CoapMessageType) {
        self.as_message_mut().type_ = type_;
    }

    /// Returns the message code of this message.
    /// To determine whether the message is a request or response, use [CoapMessageCode::try_from()]
    /// and match for the enum variants.
    fn code(&self) -> CoapMessageCode {
        self.as_message().code
    }

    /// Sets the message code of this message.
    fn set_code(&mut self, code: CoapMessageCode) {
        self.as_message_mut().code = code;
    }

    /// Returns the CoAP message ID for this message.
    fn mid(&self) -> Option<CoapMessageId> {
        self.as_message().mid
    }

    /// Sets the CoAP message ID for this message.
    fn set_mid(&mut self, mid: Option<CoapMessageId>) {
        self.as_message_mut().mid = mid;
    }

    /// Returns a reference to the data/body of this message.
    fn data(&self) -> Option<&[u8]> {
        self.as_message().data.as_ref().map(|v| v.as_ref())
    }

    /// Sets the data/body of this message.
    fn set_data<D: Into<Box<[u8]>>>(&mut self, data: Option<D>) {
        self.as_message_mut().data = data.map(Into::into);
    }

    /// Returns the message token.
    fn token(&self) -> Option<&[u8]> {
        self.as_message().token.as_ref().map(|v| v.as_ref())
    }

    /// Sets the message token.
    ///
    /// Note that [CoapClientSession::send_request()](crate::session::CoapClientSession::send_request()) will automatically set the token to a random
    /// value if you don't.
    fn set_token<D: Into<Box<[u8]>>>(&mut self, token: Option<D>) {
        self.as_message_mut().token = token.map(Into::into);
    }

    /// Returns a reference to this message.
    fn as_message(&self) -> &CoapMessage;
    /// Returns a mutable reference to this message.
    fn as_message_mut(&mut self) -> &mut CoapMessage;
}

/// Representation of a CoAP message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapMessage {
    /// CoAP message type (CON, NON, ACK, RST).
    type_: CoapMessageType,
    /// CoAP message code (e.g. 2.00 Content or 4.04 Not Found)
    code: CoapMessageCode,
    /// ID of this message – unique to each message sent over this session.
    mid: Option<CoapMessageId>,
    /// List of CoAP options associated with this message.
    options: Vec<CoapOption>,
    /// CoAP message token – used for request-response-matching.
    token: Option<Box<[u8]>>,
    /// Message body of this message.
    data: Option<Box<[u8]>>,
}

impl CoapMessage {
    /// Creates a new CoAP message with the given type and code.
    pub fn new(type_: CoapMessageType, code: CoapMessageCode) -> CoapMessage {
        CoapMessage {
            type_,
            code,
            mid: None,
            options: Vec::new(),
            token: None,
            data: None,
        }
    }

    /// Parses the given raw coap_pdu_t into a CoapMessage.
    ///
    /// # Safety
    /// raw_pdu must point to a valid instance of coap_pdu_t.
    pub unsafe fn from_raw_pdu(raw_pdu: *const coap_pdu_t) -> Result<CoapMessage, MessageConversionError> {
        let mut option_iter = MaybeUninit::zeroed();
        coap_option_iterator_init(raw_pdu, option_iter.as_mut_ptr(), std::ptr::null());
        let mut option_iter = option_iter.assume_init();
        let mut options = Vec::new();
        while let Some(read_option) = coap_option_next(&mut option_iter).as_ref() {
            options.push(CoapOption::from_raw_opt(option_iter.number, read_option).map_err(|e| {
                MessageConversionError::InvalidOptionValue(CoapOptionType::try_from(option_iter.number).ok(), e)
            })?);
        }
        let mut len: usize = 0;
        let mut data = std::ptr::null();
        coap_get_data(raw_pdu, &mut len, &mut data);
        let data = match len {
            0 => None,
            len => Some(Vec::from(std::slice::from_raw_parts(data, len)).into_boxed_slice()),
        };
        let raw_token = coap_pdu_get_token(raw_pdu);
        let token = Vec::from(std::slice::from_raw_parts(raw_token.s, raw_token.length));
        Ok(CoapMessage {
            type_: coap_pdu_get_type(raw_pdu).into(),
            code: coap_pdu_get_code(raw_pdu).try_into().unwrap(),
            mid: Some(coap_pdu_get_mid(raw_pdu)),
            options,
            token: Some(token.into_boxed_slice()),
            data,
        })
    }

    /// Converts this message into a raw PDU suitable for sending using the raw [coap_send()](libcoap_sys::coap_send())
    /// function.
    ///
    /// The caller is responsible for freeing the returned PDU, either by calling [coap_send()](libcoap_sys::coap_send()) or
    /// [coap_delete_pdu()].
    pub fn into_raw_pdu<'a, S: CoapSessionCommon<'a> + ?Sized>(
        mut self,
        session: &S,
    ) -> Result<*mut coap_pdu_t, MessageConversionError> {
        let message = self.as_message_mut();

        // SAFETY: all values are valid, cannot cause UB.
        let pdu = unsafe {
            coap_pdu_init(
                message.type_.to_raw_pdu_type(),
                message.code.to_raw_pdu_code(),
                message.mid.ok_or(MessageConversionError::MissingMessageId)?,
                session.max_pdu_size(),
            )
        };
        if pdu.is_null() {
            return Err(MessageConversionError::Unknown);
        }
        // SAFETY: We just checked that pdu is a valid pointer.
        unsafe {
            let result = self.apply_to_raw_pdu(pdu, session);
            if result.is_err() {
                coap_delete_pdu(pdu);
            }
            result
        }
    }

    /// Applies this message to the given raw PDU.
    ///
    /// Note that existing parameters of the PDU are not explicitly removed. However, because this
    /// function calls [coap_add_token()](libcoap_sys::coap_add_token()), any pre-added options and
    /// data will probably be destroyed.
    ///
    /// If you don't have a raw pdu instance, use [CoapMessage::into_raw_pdu()] instead of this
    /// function.
    ///
    /// # Panics
    /// Panics if the provided `raw_pdu` is a null pointer.
    ///
    /// # Safety
    /// raw_pdu must point to a valid mutable instance of coap_pdu_t.
    pub unsafe fn apply_to_raw_pdu<'a, S: CoapSessionCommon<'a> + ?Sized>(
        mut self,
        raw_pdu: *mut coap_pdu_t,
        session: &S,
    ) -> Result<*mut coap_pdu_t, MessageConversionError> {
        assert!(!raw_pdu.is_null(), "attempted to apply CoapMessage to null pointer");
        coap_pdu_set_type(raw_pdu, self.type_.to_raw_pdu_type());
        coap_pdu_set_code(raw_pdu, self.code.to_raw_pdu_code());
        let message = self.as_message_mut();
        let token: &[u8] = message.token.as_ref().ok_or(MessageConversionError::MissingToken)?;
        if coap_add_token(raw_pdu, token.len(), token.as_ptr()) == 0 {
            return Err(MessageConversionError::Unknown);
        }
        let mut optlist = None;
        let option_iter = std::mem::take(&mut message.options).into_iter();
        for option in option_iter {
            let optnum = option.number();
            let entry = option
                .into_optlist_entry()
                .map_err(|e| MessageConversionError::InvalidOptionValue(CoapOptionType::try_from(optnum).ok(), e))?;
            if entry.is_null() {
                if let Some(optlist) = optlist {
                    coap_delete_optlist(optlist);
                    return Err(MessageConversionError::Unknown);
                }
            }
            match optlist {
                None => {
                    optlist = Some(entry);
                },
                Some(mut optlist) => {
                    coap_insert_optlist(&mut optlist, entry);
                },
            }
        }
        if let Some(mut optlist) = optlist {
            let optlist_add_success = coap_add_optlist_pdu(raw_pdu, &mut optlist);
            coap_delete_optlist(optlist);
            if optlist_add_success == 0 {
                return Err(MessageConversionError::Unknown);
            }
        }
        if let Some(data) = message.data.take() {
            match message.code {
                CoapMessageCode::Empty => return Err(MessageConversionError::DataInEmptyMessage),
                CoapMessageCode::Request(_) => {
                    let len = data.len();
                    let box_ptr = Box::into_raw(data);
                    coap_add_data_large_request(
                        session.raw_session_mut(),
                        raw_pdu,
                        len,
                        box_ptr as *mut u8,
                        Some(large_data_cleanup_handler),
                        box_ptr as *mut c_void,
                    );
                },
                CoapMessageCode::Response(_) => {
                    // TODO blockwise transfer here as well.
                    // (for some reason libcoap needs the request PDU here?)
                    let data: &[u8] = data.as_ref();
                    if coap_add_data(raw_pdu, data.len(), data.as_ptr()) == 0 {
                        return Err(MessageConversionError::Unknown);
                    }
                },
            }
        }
        Ok(raw_pdu)
    }
}

impl CoapMessageCommon for CoapMessage {
    fn as_message(&self) -> &CoapMessage {
        self
    }

    fn as_message_mut(&mut self) -> &mut CoapMessage {
        self
    }
}

impl From<CoapRequest> for CoapMessage {
    fn from(val: CoapRequest) -> Self {
        val.into_message()
    }
}

impl From<CoapResponse> for CoapMessage {
    fn from(val: CoapResponse) -> Self {
        val.into_message()
    }
}

/// Handler provided to libcoap to cleanup large message bodies.
unsafe extern "C" fn large_data_cleanup_handler(_session: *mut coap_session_t, app_ptr: *mut c_void) {
    std::mem::drop(Box::from_raw(app_ptr as *mut u8));
}

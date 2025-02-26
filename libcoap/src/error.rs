// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * error.rs - CoAP error types.
 */

//! Error types

use std::{convert::Infallible, ffi::NulError, fmt::Debug, string::FromUtf8Error, sync::PoisonError};

use coap_message::{error::RenderableOnMinimal, MinimalWritableMessage};
use libcoap_sys::coap_pdu_code_t;
use thiserror::Error;

use crate::protocol::{CoapMessageType, CoapOptionType};

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum EndpointCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP endpoint creation error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ContextConfigurationError {
    /// Unknown error inside of libcoap
    #[error("CoAP context configuration error: unknown error in call to libcoap")]
    Unknown,
    #[error(
        "CoAP context configuration error: attempted to set encryption context while one has already been configured for this encryption variant"
    )]
    CryptoContextAlreadySet,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP message creation error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum IoProcessError {
    /// Unknown error inside of libcoap
    #[error("CoAP IO error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum SessionGetAppDataError {
    /// Stored application data type differs from requested type
    #[error("CoAP application data retrieval error: wrong type")]
    WrongType,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum OptionCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP option creation error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum SessionCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP session creation error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum UnknownOptionError {
    /// Unknown error inside of libcoap
    #[error("CoAP option conversion error: unknown option")]
    Unknown,
}

#[derive(Error, Debug)]
pub enum RngError {
    /// Unknown error inside of libcoap
    #[error("CoAP RNG error: unknown error in call to libcoap")]
    Unknown,
    /// RNG mutex is poisoned (panic in another thread while calling RNG function).
    #[error("CoAP RNG configuration error: global RNG mutex is poisoned")]
    GlobalMutexPoisonError,
}

impl<T> From<PoisonError<T>> for RngError {
    fn from(_value: PoisonError<T>) -> Self {
        RngError::GlobalMutexPoisonError
    }
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum OptionParsingError {
    /// Option is malformed and could not be parsed.
    #[error("CoAP option is malformed")]
    MalformedOption,
    /// Provided value for option is too short.
    #[error("CoAP option has invalid value: too short")]
    TooShort,
    /// Provided value for option is too long.
    #[error("CoAP option has invalid value: too long")]
    TooLong,
    /// A string value could not be converted to UTF-8.
    #[error("CoAP option has invalid value: invalid string")]
    StringConversion(#[from] FromUtf8Error),
    /// URI encoded in message could not be parsed.
    #[error("CoAP option has invalid value: invalid URI")]
    UriParsing(#[from] UriParsingError),
    /// Option has an illegal value.
    #[error("CoAP option has invalid value")]
    IllegalValue,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum UriParsingError {
    /// Unknown error inside of libcoap
    #[error("CoAP option creation error: unknown error in call to libcoap")]
    Unknown,
    /// URI does not have a valid scheme for libcoap (coap, coaps, coap+tcp, coaps+tcp, http, https).
    #[error("URI scheme {} is not a valid CoAP scheme known to libcoap", .0)]
    NotACoapScheme(String),
    /// Provided URI contains a null byte.
    #[error("Provided URI contains a null byte")]
    ContainsNullByte(#[from] NulError),
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum MessageConversionError {
    /// Value of an option is invalid.
    #[error("CoAP message parsing error: invalid option value for {:?}", .0)]
    InvalidOptionValue(Option<CoapOptionType>, #[source] OptionParsingError),
    /// Message payload is too large.
    #[error("CoAP message parsing error: message payload has size {} and is therefore too large for a &[u8]", .0)]
    TooLarge(usize),
    /// Message has an option that is specific for another message type (i.e., request option in
    /// response message).
    #[error("CoAP message conversion error: option of type {:?} invalid for message type", .0)]
    InvalidOptionForMessageType(CoapOptionType),
    /// Non-repeatable option was repeated.
    #[error("CoAP message conversion error: non-repeatable option of type {:?} repeated", .0)]
    NonRepeatableOptionRepeated(CoapOptionType),
    /// Provided URI has invalid scheme.
    #[error("CoAP message conversion error: provided uri does not have scheme valid for CoAP")]
    NotACoapUri(UriParsingError),
    /// Invalid message code.
    #[error("CoAP message conversion error: invalid message code")]
    InvalidMessageCode(#[from] MessageCodeError),
    /// A message with code 0.00 (Empty) contains data.
    #[error("CoAP message conversion error: empty message contains data")]
    DataInEmptyMessage,
    /// Message has no token.
    #[error("CoAP message conversion error: token missing")]
    MissingToken,
    /// Message has no ID.
    #[error("CoAP message conversion error: message id missing")]
    MissingMessageId,
    /// Two (or more) options were combined which must not be combined (e.g., Proxy-Scheme and
    /// Proxy-URI).
    #[error("CoAP message conversion error: options {:?} and {:?} cannot be combined", .0, .1)]
    InvalidOptionCombination(CoapOptionType, CoapOptionType),
    /// A critical option (as defined in [RFC 7252](https://datatracker.ietf.org/doc/html/rfc7252#section-5.4.1)
    /// was not recognized).
    #[error("CoAP option identified as critical but not recognized")]
    CriticalOptionUnrecognized,
    /// Unknown error inside of libcoap.
    #[error("unknown CoAP message conversion error")]
    Unknown,
}

impl RenderableOnMinimal for MessageConversionError {
    type Error<IE: RenderableOnMinimal + Debug> = IE;

    fn render<M: MinimalWritableMessage>(self, message: &mut M) -> Result<(), Self::Error<M::UnionError>> {
        todo!()
    }
}

impl From<Infallible> for MessageConversionError {
    fn from(_value: Infallible) -> Self {
        unreachable!()
    }
}

impl From<UriParsingError> for MessageConversionError {
    fn from(v: UriParsingError) -> Self {
        MessageConversionError::NotACoapUri(v)
    }
}

// TODO: This makes coap_pdu_code_t part of this library's public interface, which might be a
//       stability issue (libcoap-sys makes no stability guarantees regarding the underlying type
//       of coap_pdu_code_t.
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageCodeError {
    /// Provided message code for request was not a request code.
    #[error("CoAP message code conversion error: {} is not a known request code", .0)]
    NotARequestCode(coap_pdu_code_t),
    /// Provided message code for response was not a response code.
    #[error("CoAP message code conversion error: {} is not a known response code", .0)]
    NotAResponseCode(coap_pdu_code_t),
}

impl MessageCodeError {
    pub fn new_non_request_code(value: u8) -> Self {
        Self::NotARequestCode(value as coap_pdu_code_t)
    }

    pub fn new_non_response_code(value: u8) -> Self {
        Self::NotAResponseCode(value as coap_pdu_code_t)
    }
}

impl RenderableOnMinimal for MessageCodeError {
    type Error<IE: RenderableOnMinimal + Debug> = IE;

    fn render<M: MinimalWritableMessage>(self, message: &mut M) -> Result<(), Self::Error<M::UnionError>> {
        todo!()
    }
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageTypeError {
    /// Message type cannot be used for this message code (e.g., ACK for request).
    #[error("message type {:?} cannot be used for this message code", .0)]
    InvalidForMessageCode(CoapMessageType),
}

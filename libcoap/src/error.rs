// SPDX-License-Identifier: BSD-2-Clause
/*
 * error.rs - CoAP error types.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Error types

use std::{ffi::NulError, string::FromUtf8Error, sync::PoisonError};

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
pub enum OptionValueError {
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
    #[error("CoAP message conversion error: invalid option value for {:?}", .0)]
    InvalidOptionValue(Option<CoapOptionType>, #[source] OptionValueError),
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

impl From<UriParsingError> for MessageConversionError {
    fn from(v: UriParsingError) -> Self {
        MessageConversionError::NotACoapUri(v)
    }
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageCodeError {
    /// Provided message code for request was not a request code.
    #[error("CoAP message code conversion error: not a request code")]
    NotARequestCode,
    /// Provided message code for response was not a response code.
    #[error("CoAP message code conversion error: not a response code")]
    NotAResponseCode,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageTypeError {
    /// Message type cannot be used for this message code (e.g., ACK for request).
    #[error("message type {:?} cannot be used for this message code", .0)]
    InvalidForMessageCode(CoapMessageType),
}

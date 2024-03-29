// SPDX-License-Identifier: BSD-2-Clause
/*
 * error.rs - CoAP error types.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

//! Error types

use std::string::FromUtf8Error;

use thiserror::Error;

use crate::protocol::{CoapMessageType, CoapOptionType};

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum EndpointCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP endpoint creation error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ContextCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP context creation error: unknown error in call to libcoap")]
    Unknown,
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
    /// Option has an illegal value.
    #[error("CoAP option has invalid value")]
    IllegalValue,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum UriParsingError {
    /// URI does not have a valid scheme for libcoap (coap, coaps, coap+tcp, coaps+tcp, http, https).
    #[error("URL does not have scheme valid for libcoap")]
    NotACoapScheme,
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
    /// URI is invalid (most likely a Proxy URI cannot be parsed as a valid URL).
    #[error("CoAP message conversion error: invalid uri (malformed proxy URL?)")]
    InvalidUri(url::ParseError),
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

impl From<url::ParseError> for MessageConversionError {
    fn from(v: url::ParseError) -> Self {
        MessageConversionError::InvalidUri(v)
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

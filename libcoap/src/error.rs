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

use std::{ffi::NulError, string::FromUtf8Error, sync::PoisonError};

use thiserror::Error;

use crate::protocol::{CoapMessageType, CoapOptionType};

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MulticastGroupJoinError {
    /// Unknown error inside of libcoap
    #[error("CoAP join multicast group error: unknown error in call to libcoap")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum EndpointCreationError {
    /// Unknown error inside of libcoap
    #[error("CoAP endpoint creation error: unknown error in call to libcoap")]
    Unknown,
}

#[cfg(feature = "oscore")]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum OscoreConfigCreationError {
    /// Unknown error inside of libcoap, propably due to missing/invalid entries in your oscore
    /// config
    #[error("Oscore config creation error: unknown error in call to libcoap, propably due to missing/invalid entries in your oscore config")]
    Unknown,
}

#[cfg(feature = "oscore")]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum OscoreServerCreationError {
    /// Oscore config seems to be invalid, make sure to use it only onces
    #[error("Oscore server creation error: oscore config seems tot be invalid, make sure to use it only onces")]
    OscoreConfigInvalid,
    /// Unknown error inside of libcoap
    #[error("Oscore server creation error: unknown error in call to libcoap")]
    Unknown,
}

#[cfg(feature = "oscore")]
#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum OscoreRecipientError {
    /// Method is called on a context without appropriate oscore information
    #[error("Oscore recipient error: context it missing appropriate oscore information")]
    NoOscoreContext,
    /// Tried adding duplicate recipient to context
    #[error("Oscore recipient error: tried adding duplicate recipient to context")]
    DuplicateId,
    /// Tried removing a recipient that is not assosiated with the context
    #[error("Oscore recipient error: tried removing a recipient that is not assosiated with the context")]
    NotFound,
    /// Unknown error inside of libcoap, adding/removing a recipient failed
    #[error("Oscore recipient error: unknown error in call to libcoap, adding/removing the recipient failed")]
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
    /// Oscore config seems to be invalid, make sure to use it only onces
    #[cfg(feature = "oscore")]
    #[error("CoAP session creation error: oscore config seems tot be invalid, make sure to use it only onces")]
    OscoreConfigInvalid,
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

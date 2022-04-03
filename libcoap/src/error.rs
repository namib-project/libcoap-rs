// SPDX-License-Identifier: BSD-2-Clause
/*
 * crypto.rs - CoAP error types.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::string::FromUtf8Error;

use thiserror::Error;

use crate::protocol::{CoapMessageType, CoapOptionType};

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum EndpointCreationError {
    #[error("CoAP endpoint creation error: unknown")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ContextCreationError {
    #[error("CoAP context creation error: unknown")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageCreationError {
    #[error("CoAP message creation error: unknown")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum IoProcessError {
    #[error("CoAP IO error: unknown")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum SessionGetAppDataError {
    #[error("CoAP application data retrieval error: wrong type")]
    WrongType,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum OptionCreationError {
    #[error("CoAP option creation error: unknown")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum SessionCreationError {
    #[error("CoAP session creation error: unknown")]
    Unknown,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum UnknownOptionError {
    #[error("CoAP option conversion error: unknown option")]
    Unknown,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum OptionValueError {
    #[error("CoAP option has invalid value: too short")]
    TooShort,
    #[error("CoAP option has invalid value: too long")]
    TooLong,
    #[error("CoAP option has invalid value: invalid string")]
    StringConversion(#[from] FromUtf8Error),
    #[error("CoAP option has invalid value")]
    IllegalValue,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum UriParsingError {
    #[error("URL does not have scheme valid for CoAP")]
    NotACoapScheme,
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum MessageConversionError {
    #[error("CoAP message conversion error: invalid option value for {:?}", .0)]
    InvalidOptionValue(Option<CoapOptionType>, #[source] OptionValueError),
    #[error("CoAP message conversion error: option of type {:?} invalid for message type", .0)]
    InvalidOptionForMessageType(CoapOptionType),
    #[error("CoAP message conversion error: non-repeatable option of type {:?} repeated", .0)]
    NonRepeatableOptionRepeated(CoapOptionType),
    #[error("CoAP message conversion error: provided uri does not have scheme valid for CoAP")]
    NotACoapUri(UriParsingError),
    #[error("CoAP message conversion error: invalid uri (malformed proxy URL?)")]
    InvalidUri(url::ParseError),
    #[error("CoAP message conversion error: invalid message code")]
    InvalidMessageCode(#[from] MessageCodeError),
    #[error("CoAP message conversion error: empty message contains data")]
    DataInEmptyMessage,
    #[error("CoAP message conversion error: token missing")]
    MissingToken,
    #[error("CoAP message conversion error: message id missing")]
    MissingMessageId,
    #[error("CoAP message conversion error: options {:?} and {:?} cannot be combined", .0, .1)]
    InvalidOptionCombination(CoapOptionType, CoapOptionType),
    #[error("CoAP option identified as critical but not recognized")]
    CriticalOptionUnrecognized,
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
    #[error("CoAP message code conversion error: not a request code")]
    NotARequestCode,
    #[error("CoAP message code conversion error: not a response code")]
    NotAResponseCode,
}

#[derive(Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageTypeError {
    #[error("message type {:?} cannot be used for this message code", .0)]
    InvalidForMessageCode(CoapMessageType),
}

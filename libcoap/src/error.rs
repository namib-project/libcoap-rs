use std::{string::FromUtf8Error};

use crate::protocol::CoapOptionType;

#[derive(Debug)]
pub enum CoapError {
    EndpointCreation(EndpointCreationError),
    ContextCreation(ContextCreationError),
}

#[derive(Debug)]
pub enum EndpointCreationError {
    Unknown,
}

#[derive(Debug)]
pub enum ContextCreationError {
    Unknown,
}

#[derive(Debug)]
pub enum MessageCreationError {
    Unknown,
}

#[derive(Debug)]
pub enum IoProcessError {
    Unknown,
}

#[derive(Debug)]
pub enum SessionGetAppDataError {
    WrongType,
}

#[derive(Debug)]
pub enum OptionCreationError {
    Unknown,
}

#[derive(Debug)]
pub enum SessionCreationError {
    Unknown,
}

#[derive(Debug)]
pub enum UnknownOptionError {
    Unknown,
}

#[derive(Debug)]
pub enum OptionValueError {
    TooShort,
    TooLong,
    StringConversion(FromUtf8Error),
    UrlParsing(url::ParseError),
    NotACoapUrl(UriParsingError),
    IllegalValue,
}

impl From<FromUtf8Error> for OptionValueError {
    fn from(val: FromUtf8Error) -> Self {
        OptionValueError::StringConversion(val)
    }
}

impl From<url::ParseError> for OptionValueError {
    fn from(val: url::ParseError) -> Self {
        OptionValueError::UrlParsing(val)
    }
}

#[derive(Debug)]
pub enum UriParsingError {
    NotACoapScheme,
}

#[derive(Debug)]
pub enum MessageConversionError {
    InvalidOptionValue(OptionValueError),
    InvalidOptionForMessageType(CoapOptionType),
    NonRepeatableOptionRepeated(CoapOptionType),
    InvalidMessageCode(MessageCodeConversionError),
    DataInEmptyMessage,
    MissingToken,
    MissingMessageId,
    InvalidOptionCombination(CoapOptionType, CoapOptionType),
    CriticalOptionUnrecognized,
    Unknown,
}

impl From<OptionValueError> for MessageConversionError {
    fn from(err: OptionValueError) -> Self {
        MessageConversionError::InvalidOptionValue(err)
    }
}

impl From<UriParsingError> for MessageConversionError {
    fn from(v: UriParsingError) -> Self {
        MessageConversionError::InvalidOptionValue(OptionValueError::NotACoapUrl(v))
    }
}

impl From<url::ParseError> for MessageConversionError {
    fn from(v: url::ParseError) -> Self {
        MessageConversionError::InvalidOptionValue(OptionValueError::UrlParsing(v))
    }
}

#[derive(Debug)]
pub enum MessageCodeConversionError {
    NotARequestCode,
    NotAResponseCode,
    EmptyMessageCode,
}

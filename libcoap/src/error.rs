use std::{str::Utf8Error, string::FromUtf8Error};

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
    IllegalValue,
}

impl From<FromUtf8Error> for OptionValueError {
    fn from(val: FromUtf8Error) -> Self {
        OptionValueError::StringConversion(val)
    }
}

#[derive(Debug)]
pub enum UriParsingError {
    NotACoapScheme,
}

#[derive(Debug)]
pub enum MessageConversionError {
    InvalidOptionValue(OptionValueError),
    InvalidMessageCode(MessageCodeConversionError),
    Unknown,
}

impl From<OptionValueError> for MessageConversionError {
    fn from(err: OptionValueError) -> Self {
        MessageConversionError::InvalidOptionValue(err)
    }
}

#[derive(Debug)]
pub enum MessageCodeConversionError {
    NotARequestCode,
    NotAResponseCode,
}

#[derive(Debug)]
#[cfg(feature = "nightly")]
pub enum ResourceTypecastingError {
    WrongUserDataType,
}

//! Various types that are specified and defined in the CoAP standard and its extensions.

use std::{
    ffi::CStr,
    fmt::{Display, Formatter},
};

use libcoap_sys::{
    coap_option_num_t, coap_pdu_code_t, coap_pdu_type_t,
    coap_pdu_type_t::{COAP_MESSAGE_ACK, COAP_MESSAGE_CON, COAP_MESSAGE_NON, COAP_MESSAGE_RST},
    coap_request_t, coap_response_phrase, COAP_MEDIATYPE_ANY, COAP_MEDIATYPE_APPLICATION_CBOR,
    COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT, COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0,
    COAP_MEDIATYPE_APPLICATION_COSE_KEY, COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET, COAP_MEDIATYPE_APPLICATION_COSE_MAC,
    COAP_MEDIATYPE_APPLICATION_COSE_MAC0, COAP_MEDIATYPE_APPLICATION_COSE_SIGN, COAP_MEDIATYPE_APPLICATION_COSE_SIGN1,
    COAP_MEDIATYPE_APPLICATION_CWT, COAP_MEDIATYPE_APPLICATION_DOTS_CBOR, COAP_MEDIATYPE_APPLICATION_EXI,
    COAP_MEDIATYPE_APPLICATION_JSON, COAP_MEDIATYPE_APPLICATION_LINK_FORMAT, COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
    COAP_MEDIATYPE_APPLICATION_RDF_XML, COAP_MEDIATYPE_APPLICATION_SENML_CBOR, COAP_MEDIATYPE_APPLICATION_SENML_EXI,
    COAP_MEDIATYPE_APPLICATION_SENML_JSON, COAP_MEDIATYPE_APPLICATION_SENML_XML,
    COAP_MEDIATYPE_APPLICATION_SENSML_CBOR, COAP_MEDIATYPE_APPLICATION_SENSML_EXI,
    COAP_MEDIATYPE_APPLICATION_SENSML_JSON, COAP_MEDIATYPE_APPLICATION_SENSML_XML, COAP_MEDIATYPE_APPLICATION_XML,
    COAP_MEDIATYPE_TEXT_PLAIN, COAP_OPTION_ACCEPT, COAP_OPTION_BLOCK1, COAP_OPTION_BLOCK2, COAP_OPTION_CONTENT_FORMAT,
    COAP_OPTION_ETAG, COAP_OPTION_HOP_LIMIT, COAP_OPTION_IF_MATCH, COAP_OPTION_IF_NONE_MATCH,
    COAP_OPTION_LOCATION_PATH, COAP_OPTION_LOCATION_QUERY, COAP_OPTION_MAXAGE, COAP_OPTION_NORESPONSE,
    COAP_OPTION_OBSERVE, COAP_OPTION_PROXY_SCHEME, COAP_OPTION_PROXY_URI, COAP_OPTION_SIZE1, COAP_OPTION_SIZE2,
    COAP_OPTION_URI_HOST, COAP_OPTION_URI_PATH, COAP_OPTION_URI_PORT, COAP_OPTION_URI_QUERY,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::error::{MessageCodeError, UnknownOptionError};

pub type ETag = Box<[u8]>;
pub type MaxAge = u32;
pub type LocationPath = String;
pub type LocationQuery = String;
pub type UriHost = String;
pub type UriPort = u16;
pub type UriPath = String;
pub type UriQuery = String;
pub type ContentFormat = u16;
pub type ProxyUri = String;
pub type ProxyScheme = String;
pub type Size = u32;
pub type Block = u32;
pub type HopLimit = u16;
pub type NoResponse = u8;
pub type Observe = u32;

pub type CoapOptionNum = coap_option_num_t;
pub type CoapToken = Box<[u8]>;

/// Representation of a CoAP match expression supplied in the If-Match option, see
/// [RFC 7252, Section 5.10.8.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.1).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum CoapMatch {
    ETag(ETag),
    Empty,
}

/// CoAP option types as defined in [RFC 7252, Section 5.10](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10)
/// and later CoAP extensions.
///
/// The enum value correspons to the appropriate option number and can be retrieved using
/// `[value] as u16` or [to_raw_option_num()](CoapOptionType::to_raw_option_num()).
///
/// See <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#option-numbers> for a
/// list of option numbers registered with the IANA.
#[repr(u16)]
#[non_exhaustive]
#[derive(FromPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CoapOptionType {
    /// If-Match option ([RFC 7252, Section 5.10.8.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.1)).
    IfMatch = COAP_OPTION_IF_MATCH as u16,
    /// Uri-Host option ([RFC 7252, Section 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)).
    UriHost = COAP_OPTION_URI_HOST as u16,
    /// ETag option ([RFC 7252, Section 5.10.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.6)).
    ETag = COAP_OPTION_ETAG as u16,
    /// If-None-Match option ([RFC 7252, Section 5.10.8.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.2)).
    IfNoneMatch = COAP_OPTION_IF_NONE_MATCH as u16,
    /// Uri-Port option ([RFC 7252, Section 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)).
    UriPort = COAP_OPTION_URI_PORT as u16,
    /// Location-Path option ([RFC 7252, Section 5.10.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.7)).
    LocationPath = COAP_OPTION_LOCATION_PATH as u16,
    /// Uri-Path option ([RFC 7252, Section 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)).
    UriPath = COAP_OPTION_URI_PATH as u16,
    /// Content-Format option ([RFC 7252, Section 5.10.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.3)).
    ContentFormat = COAP_OPTION_CONTENT_FORMAT as u16,
    /// Max-Age option ([RFC 7252, Section 5.10.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.5)).
    MaxAge = COAP_OPTION_MAXAGE as u16,
    /// Uri-Query option ([RFC 7252, Section 5.10.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.1)).
    UriQuery = COAP_OPTION_URI_QUERY as u16,
    /// Accept option ([RFC 7252, Section 5.10.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.4)).
    Accept = COAP_OPTION_ACCEPT as u16,
    /// Location-Query option ([RFC 7252, Section 5.10.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.7)).
    LocationQuery = COAP_OPTION_LOCATION_QUERY as u16,
    /// Proxy-Uri option ([RFC 7252, Section 5.10.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.2)).
    ProxyUri = COAP_OPTION_PROXY_URI as u16,
    /// Proxy-Scheme option ([RFC 7252, Section 5.10.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.2)).
    ProxyScheme = COAP_OPTION_PROXY_SCHEME as u16,
    /// Size1 option ([RFC 7959, Section 4](https://datatracker.ietf.org/doc/html/rfc7959#section-4)).
    Size1 = COAP_OPTION_SIZE1 as u16,
    /// Size2 option ([RFC 7959, Section 4](https://datatracker.ietf.org/doc/html/rfc7959#section-4)).
    Size2 = COAP_OPTION_SIZE2 as u16,
    /// Block1 option ([RFC 7959, Section 2.1](https://datatracker.ietf.org/doc/html/rfc7959#section-2.1)).
    Block1 = COAP_OPTION_BLOCK1 as u16,
    /// Block2 option ([RFC 7959, Section 2.1](https://datatracker.ietf.org/doc/html/rfc7959#section-2.1)).
    Block2 = COAP_OPTION_BLOCK2 as u16,
    /// Hop-Limit option ([RFC 8768, Section 3](https://datatracker.ietf.org/doc/html/rfc8768#section-3)).
    HopLimit = COAP_OPTION_HOP_LIMIT as u16,
    /// No-Response option ([RFC 7967, Section 2](https://datatracker.ietf.org/doc/html/rfc7967#section-2)).
    NoResponse = COAP_OPTION_NORESPONSE as u16,
    /// Observe option ([RFC 7641, Section 2](https://datatracker.ietf.org/doc/html/rfc7641#section-2)).
    Observe = COAP_OPTION_OBSERVE as u16,
    // TODO
    //OsCore = COAP_OPTION_OSCORE as u16,
}

impl CoapOptionType {
    /// Returns the option number this type belongs to.
    pub fn to_raw_option_num(self) -> coap_option_num_t {
        self as u16
    }

    /// Returns the maximum size in bytes that a value of this option type should have.
    pub fn max_len(&self) -> usize {
        match self {
            CoapOptionType::IfMatch => 8,
            CoapOptionType::UriHost => 255,
            CoapOptionType::ETag => 8,
            CoapOptionType::IfNoneMatch => 0,
            CoapOptionType::UriPort => 2,
            CoapOptionType::LocationPath => 255,
            CoapOptionType::UriPath => 255,
            CoapOptionType::ContentFormat => 2,
            CoapOptionType::MaxAge => 4,
            CoapOptionType::UriQuery => 255,
            CoapOptionType::Accept => 2,
            CoapOptionType::LocationQuery => 255,
            CoapOptionType::ProxyUri => 1034,
            CoapOptionType::ProxyScheme => 255,
            CoapOptionType::Size1 => 4,
            CoapOptionType::Size2 => 4,
            //CoapOptionType::OsCore => 3,
            CoapOptionType::Block1 => 3,
            CoapOptionType::Block2 => 3,
            CoapOptionType::HopLimit => 1,
            CoapOptionType::NoResponse => 1,
            CoapOptionType::Observe => 3,
        }
    }

    /// Returns the minimum size in bytes that a value of this option type should have.
    pub fn min_len(&self) -> usize {
        match self {
            CoapOptionType::IfMatch => 0,
            CoapOptionType::UriHost => 1,
            CoapOptionType::ETag => 1,
            CoapOptionType::IfNoneMatch => 0,
            CoapOptionType::UriPort => 0,
            CoapOptionType::LocationPath => 0,
            CoapOptionType::UriPath => 0,
            CoapOptionType::ContentFormat => 0,
            CoapOptionType::MaxAge => 0,
            CoapOptionType::UriQuery => 0,
            CoapOptionType::Accept => 0,
            CoapOptionType::LocationQuery => 0,
            CoapOptionType::ProxyUri => 1,
            CoapOptionType::ProxyScheme => 1,
            CoapOptionType::Size1 => 0,
            CoapOptionType::Size2 => 0,
            //CoapOptionType::OsCore => {},
            CoapOptionType::Block1 => 0,
            CoapOptionType::Block2 => 0,
            CoapOptionType::HopLimit => 1,
            CoapOptionType::NoResponse => 0,
            CoapOptionType::Observe => 0,
        }
    }
}

impl TryFrom<coap_option_num_t> for CoapOptionType {
    type Error = UnknownOptionError;

    fn try_from(num: coap_option_num_t) -> Result<Self, Self::Error> {
        <CoapOptionType as FromPrimitive>::from_u16(num).ok_or(UnknownOptionError::Unknown)
    }
}

/// Various content formats that can be used for CoAP requests.
///
/// To get the corresponding numeric value, use `[value] as u16`.
///
/// See <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats> for
/// values that are currently registered with the IANA.
#[repr(u16)]
#[derive(Copy, Clone, FromPrimitive, Eq, PartialEq, Hash, Debug)]
#[non_exhaustive]
pub enum CoapContentFormat {
    Any = COAP_MEDIATYPE_ANY as u16,
    Cbor = COAP_MEDIATYPE_APPLICATION_CBOR as u16,
    DotsCbor = COAP_MEDIATYPE_APPLICATION_DOTS_CBOR as u16,
    SenMlCbor = COAP_MEDIATYPE_APPLICATION_SENML_CBOR as u16,
    SenMlExi = COAP_MEDIATYPE_APPLICATION_SENML_EXI as u16,
    CoseEncrypt = COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT as u16,
    CoseEncrypt0 = COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0 as u16,
    CoseKey = COAP_MEDIATYPE_APPLICATION_COSE_KEY as u16,
    CoseKeySet = COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET as u16,
    CoseMac = COAP_MEDIATYPE_APPLICATION_COSE_MAC as u16,
    CoseMac0 = COAP_MEDIATYPE_APPLICATION_COSE_MAC0 as u16,
    CoseSign = COAP_MEDIATYPE_APPLICATION_COSE_SIGN as u16,
    CoseSign1 = COAP_MEDIATYPE_APPLICATION_COSE_SIGN1 as u16,
    Cwt = COAP_MEDIATYPE_APPLICATION_CWT as u16,
    Exi = COAP_MEDIATYPE_APPLICATION_EXI as u16,
    Json = COAP_MEDIATYPE_APPLICATION_JSON as u16,
    LinkFormat = COAP_MEDIATYPE_APPLICATION_LINK_FORMAT as u16,
    OctetStream = COAP_MEDIATYPE_APPLICATION_OCTET_STREAM as u16,
    RdfXml = COAP_MEDIATYPE_APPLICATION_RDF_XML as u16,
    SenMlJson = COAP_MEDIATYPE_APPLICATION_SENML_JSON as u16,
    SenMlXml = COAP_MEDIATYPE_APPLICATION_SENML_XML as u16,
    SensMlCbor = COAP_MEDIATYPE_APPLICATION_SENSML_CBOR as u16,
    SensMlExi = COAP_MEDIATYPE_APPLICATION_SENSML_EXI as u16,
    SensMlJson = COAP_MEDIATYPE_APPLICATION_SENSML_JSON as u16,
    SensMlXml = COAP_MEDIATYPE_APPLICATION_SENSML_XML as u16,
    ApplicationXml = COAP_MEDIATYPE_APPLICATION_XML as u16,
    TextPlain = COAP_MEDIATYPE_TEXT_PLAIN as u16,
    Other,
}

impl From<ContentFormat> for CoapContentFormat {
    fn from(value: u16) -> Self {
        <CoapContentFormat as FromPrimitive>::from_u16(value).unwrap_or(CoapContentFormat::Other)
    }
}

/// Representation of a CoAP message code.
/// Can be a request code, a response code, or the empty message code.
///
/// The numeric value (that can also be obtained with [to_raw_request()](CoapRequestCode::to_raw_pdu_code()))
/// corresponds to the values defined in <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#codes>.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CoapMessageCode {
    Empty,
    Request(CoapRequestCode),
    Response(CoapResponseCode),
}

impl CoapMessageCode {
    /// Returns the corresponding raw code for this message code, which can be added to a raw
    /// [coap_pdu_t](libcoap_sys::coap_pdu_t).
    pub fn to_raw_pdu_code(self) -> coap_pdu_code_t {
        match self {
            CoapMessageCode::Empty => coap_pdu_code_t::COAP_EMPTY_CODE,
            CoapMessageCode::Request(req) => req.to_raw_pdu_code(),
            CoapMessageCode::Response(rsp) => rsp.to_raw_pdu_code(),
        }
    }
}

impl From<CoapRequestCode> for CoapMessageCode {
    fn from(code: CoapRequestCode) -> Self {
        CoapMessageCode::Request(code)
    }
}

impl From<CoapResponseCode> for CoapMessageCode {
    fn from(code: CoapResponseCode) -> Self {
        CoapMessageCode::Response(code)
    }
}

impl TryFrom<coap_pdu_code_t> for CoapMessageCode {
    type Error = MessageCodeError;

    fn try_from(code: coap_pdu_code_t) -> Result<Self, Self::Error> {
        match code {
            coap_pdu_code_t::COAP_EMPTY_CODE => Ok(CoapMessageCode::Empty),
            code => CoapRequestCode::try_from(code)
                .map(CoapMessageCode::Request)
                .or_else(|_| CoapResponseCode::try_from(code).map(CoapMessageCode::Response)),
        }
    }
}

/// Representation of a CoAP request/method code.
///
/// See <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#method-codes> for the
/// values currently registered with the IANA.
#[repr(u8)]
#[non_exhaustive]
#[derive(FromPrimitive, Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub enum CoapRequestCode {
    Get = coap_pdu_code_t::COAP_REQUEST_CODE_GET as u8,
    Put = coap_pdu_code_t::COAP_REQUEST_CODE_PUT as u8,
    Delete = coap_pdu_code_t::COAP_REQUEST_CODE_DELETE as u8,
    Post = coap_pdu_code_t::COAP_REQUEST_CODE_POST as u8,
    Fetch = coap_pdu_code_t::COAP_REQUEST_CODE_FETCH as u8,
    IPatch = coap_pdu_code_t::COAP_REQUEST_CODE_IPATCH as u8,
    Patch = coap_pdu_code_t::COAP_REQUEST_CODE_PATCH as u8,
}

impl CoapRequestCode {
    /// Returns the [coap_request_t](libcoap_sys::coap_request_t) corresponding to this request code.
    ///
    /// Note that this is *not* the code that should be set inside of a [coap_pdu_t](libcoap_sys::coap_pdu_t),
    /// but a value used internally by the libcoap C library. See [to_raw_pdu_code()](CoapRequestCode::to_raw_pdu_code())
    /// for the standardized value used in messages.
    pub fn to_raw_request(self) -> coap_request_t {
        match self {
            CoapRequestCode::Get => coap_request_t::COAP_REQUEST_GET,
            CoapRequestCode::Put => coap_request_t::COAP_REQUEST_PUT,
            CoapRequestCode::Delete => coap_request_t::COAP_REQUEST_FETCH,
            CoapRequestCode::Post => coap_request_t::COAP_REQUEST_POST,
            CoapRequestCode::Fetch => coap_request_t::COAP_REQUEST_FETCH,
            CoapRequestCode::IPatch => coap_request_t::COAP_REQUEST_IPATCH,
            CoapRequestCode::Patch => coap_request_t::COAP_REQUEST_PATCH,
        }
    }

    /// Returns the raw [coap_pdu_code_t](libcoap_sys::coap_pdu_code_t) corresponding to this
    /// request code.
    pub fn to_raw_pdu_code(self) -> coap_pdu_code_t {
        match self {
            CoapRequestCode::Get => coap_pdu_code_t::COAP_REQUEST_CODE_GET,
            CoapRequestCode::Put => coap_pdu_code_t::COAP_REQUEST_CODE_PUT,
            CoapRequestCode::Delete => coap_pdu_code_t::COAP_REQUEST_CODE_FETCH,
            CoapRequestCode::Post => coap_pdu_code_t::COAP_REQUEST_CODE_POST,
            CoapRequestCode::Fetch => coap_pdu_code_t::COAP_REQUEST_CODE_FETCH,
            CoapRequestCode::IPatch => coap_pdu_code_t::COAP_REQUEST_CODE_IPATCH,
            CoapRequestCode::Patch => coap_pdu_code_t::COAP_REQUEST_CODE_PATCH,
        }
    }
}

impl From<coap_request_t> for CoapRequestCode {
    fn from(req: coap_request_t) -> Self {
        match req {
            coap_request_t::COAP_REQUEST_GET => CoapRequestCode::Get,
            coap_request_t::COAP_REQUEST_POST => CoapRequestCode::Post,
            coap_request_t::COAP_REQUEST_PUT => CoapRequestCode::Put,
            coap_request_t::COAP_REQUEST_DELETE => CoapRequestCode::Delete,
            coap_request_t::COAP_REQUEST_FETCH => CoapRequestCode::Fetch,
            coap_request_t::COAP_REQUEST_PATCH => CoapRequestCode::Patch,
            coap_request_t::COAP_REQUEST_IPATCH => CoapRequestCode::IPatch,
            _ => panic!("unknown request type"),
        }
    }
}

impl TryFrom<coap_pdu_code_t> for CoapRequestCode {
    type Error = MessageCodeError;

    fn try_from(req: coap_pdu_code_t) -> Result<Self, Self::Error> {
        <CoapRequestCode as FromPrimitive>::from_u32(req as u32).ok_or(MessageCodeError::NotARequestCode)
    }
}

/// Representation of a CoAP response code.
///
/// See <https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#response-codes> for
/// the possible values currently registered with the IANA.
#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, FromPrimitive, Debug, Eq, PartialEq, Hash)]
pub enum CoapResponseCode {
    Content = coap_pdu_code_t::COAP_RESPONSE_CODE_CONTENT as u8,
    BadGateway = coap_pdu_code_t::COAP_RESPONSE_CODE_BAD_GATEWAY as u8,
    Continue = coap_pdu_code_t::COAP_RESPONSE_CODE_CONTINUE as u8,
    Conflict = coap_pdu_code_t::COAP_RESPONSE_CODE_CONFLICT as u8,
    BadRequest = coap_pdu_code_t::COAP_RESPONSE_CODE_BAD_REQUEST as u8,
    BadOption = coap_pdu_code_t::COAP_RESPONSE_CODE_BAD_OPTION as u8,
    Changed = coap_pdu_code_t::COAP_RESPONSE_CODE_CHANGED as u8,
    Created = coap_pdu_code_t::COAP_RESPONSE_CODE_CREATED as u8,
    Deleted = coap_pdu_code_t::COAP_RESPONSE_CODE_DELETED as u8,
    Forbidden = coap_pdu_code_t::COAP_RESPONSE_CODE_FORBIDDEN as u8,
    GatewayTimeout = coap_pdu_code_t::COAP_RESPONSE_CODE_GATEWAY_TIMEOUT as u8,
    HopLimitReached = coap_pdu_code_t::COAP_RESPONSE_CODE_HOP_LIMIT_REACHED as u8,
    Incomplete = coap_pdu_code_t::COAP_RESPONSE_CODE_INCOMPLETE as u8,
    InternalError = coap_pdu_code_t::COAP_RESPONSE_CODE_INTERNAL_ERROR as u8,
    NotAcceptable = coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_ACCEPTABLE as u8,
    NotAllowed = coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_ALLOWED as u8,
    NotFound = coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_FOUND as u8,
    NotImplemented = coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_IMPLEMENTED as u8,
    PreconditionFailed = coap_pdu_code_t::COAP_RESPONSE_CODE_PRECONDITION_FAILED as u8,
    ProxyingNotSupported = coap_pdu_code_t::COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED as u8,
    RequestTooLarge = coap_pdu_code_t::COAP_RESPONSE_CODE_REQUEST_TOO_LARGE as u8,
    ServiceUnavailable = coap_pdu_code_t::COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE as u8,
    TooManyRequests = coap_pdu_code_t::COAP_RESPONSE_CODE_TOO_MANY_REQUESTS as u8,
    Unauthorized = coap_pdu_code_t::COAP_RESPONSE_CODE_UNAUTHORIZED as u8,
    Unprocessable = coap_pdu_code_t::COAP_RESPONSE_CODE_UNPROCESSABLE as u8,
    UnsupportedContentFormat = coap_pdu_code_t::COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT as u8,
    Valid = coap_pdu_code_t::COAP_RESPONSE_CODE_VALID as u8,
}

impl CoapResponseCode {
    /// Returns the raw [coap_pdu_code_t](libcoap_sys::coap_pdu_code_t) corresponding to this
    /// request code.
    pub fn to_raw_pdu_code(self) -> coap_pdu_code_t {
        match self {
            CoapResponseCode::Content => coap_pdu_code_t::COAP_RESPONSE_CODE_CONTENT,
            CoapResponseCode::BadGateway => coap_pdu_code_t::COAP_RESPONSE_CODE_BAD_GATEWAY,
            CoapResponseCode::Continue => coap_pdu_code_t::COAP_RESPONSE_CODE_CONTINUE,
            CoapResponseCode::Conflict => coap_pdu_code_t::COAP_RESPONSE_CODE_CONFLICT,
            CoapResponseCode::BadRequest => coap_pdu_code_t::COAP_RESPONSE_CODE_BAD_REQUEST,
            CoapResponseCode::BadOption => coap_pdu_code_t::COAP_RESPONSE_CODE_BAD_OPTION,
            CoapResponseCode::Changed => coap_pdu_code_t::COAP_RESPONSE_CODE_CHANGED,
            CoapResponseCode::Created => coap_pdu_code_t::COAP_RESPONSE_CODE_CREATED,
            CoapResponseCode::Deleted => coap_pdu_code_t::COAP_RESPONSE_CODE_DELETED,
            CoapResponseCode::Forbidden => coap_pdu_code_t::COAP_RESPONSE_CODE_FORBIDDEN,
            CoapResponseCode::GatewayTimeout => coap_pdu_code_t::COAP_RESPONSE_CODE_GATEWAY_TIMEOUT,
            CoapResponseCode::HopLimitReached => coap_pdu_code_t::COAP_RESPONSE_CODE_HOP_LIMIT_REACHED,
            CoapResponseCode::Incomplete => coap_pdu_code_t::COAP_RESPONSE_CODE_INCOMPLETE,
            CoapResponseCode::InternalError => coap_pdu_code_t::COAP_RESPONSE_CODE_INTERNAL_ERROR,
            CoapResponseCode::NotAcceptable => coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_ACCEPTABLE,
            CoapResponseCode::NotAllowed => coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_ALLOWED,
            CoapResponseCode::NotFound => coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_FOUND,
            CoapResponseCode::NotImplemented => coap_pdu_code_t::COAP_RESPONSE_CODE_NOT_IMPLEMENTED,
            CoapResponseCode::PreconditionFailed => coap_pdu_code_t::COAP_RESPONSE_CODE_PRECONDITION_FAILED,
            CoapResponseCode::ProxyingNotSupported => coap_pdu_code_t::COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED,
            CoapResponseCode::RequestTooLarge => coap_pdu_code_t::COAP_RESPONSE_CODE_REQUEST_TOO_LARGE,
            CoapResponseCode::ServiceUnavailable => coap_pdu_code_t::COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE,
            CoapResponseCode::TooManyRequests => coap_pdu_code_t::COAP_RESPONSE_CODE_TOO_MANY_REQUESTS,
            CoapResponseCode::Unauthorized => coap_pdu_code_t::COAP_RESPONSE_CODE_UNAUTHORIZED,
            CoapResponseCode::Unprocessable => coap_pdu_code_t::COAP_RESPONSE_CODE_UNPROCESSABLE,
            CoapResponseCode::UnsupportedContentFormat => {
                coap_pdu_code_t::COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT
            },
            CoapResponseCode::Valid => coap_pdu_code_t::COAP_RESPONSE_CODE_VALID,
        }
    }
}

impl Display for CoapResponseCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let response_phrase = unsafe {
            let raw_phrase = coap_response_phrase(*self as u8);
            if raw_phrase.is_null() {
                "unknown response code"
            } else {
                CStr::from_ptr(raw_phrase)
                    .to_str()
                    .unwrap_or("unable to retrieve phrase for response code")
            }
        };

        write!(f, "{}", response_phrase)
    }
}

impl TryFrom<coap_pdu_code_t> for CoapResponseCode {
    type Error = MessageCodeError;

    fn try_from(value: coap_pdu_code_t) -> Result<Self, Self::Error> {
        <CoapResponseCode as FromPrimitive>::from_u32(value as u32).ok_or(MessageCodeError::NotAResponseCode)
    }
}

/// CoAP message types as defined in [RFC 7252, Section 3](https://datatracker.ietf.org/doc/html/rfc7252#section-3)
/// and described in [RFC 7252, Section 4.2 and 4.3](https://datatracker.ietf.org/doc/html/rfc7252#section-4.2).
#[repr(u8)]
#[derive(Copy, Clone, Hash, Eq, PartialEq, FromPrimitive, Debug)]
pub enum CoapMessageType {
    /// Confirmable message, i.e. a message whose reception should be confirmed by the peer.
    Con = COAP_MESSAGE_CON as u8,
    /// Non-confirmable message, i.e. a message whose reception should not be confirmed by the peer.
    Non = COAP_MESSAGE_NON as u8,
    /// Acknowledgement for a previous message.
    Ack = COAP_MESSAGE_ACK as u8,
    /// Non-acknowledgement for a previous message.
    Rst = COAP_MESSAGE_RST as u8,
}

impl CoapMessageType {
    /// Returns the corresponding raw [coap_pdu_type_t](libcoap_sys::coap_pdu_type_t) instance for
    /// this message type.
    pub fn to_raw_pdu_type(&self) -> coap_pdu_type_t {
        match self {
            CoapMessageType::Con => COAP_MESSAGE_CON,
            CoapMessageType::Non => COAP_MESSAGE_NON,
            CoapMessageType::Ack => COAP_MESSAGE_ACK,
            CoapMessageType::Rst => COAP_MESSAGE_RST,
        }
    }
}

impl From<coap_pdu_type_t> for CoapMessageType {
    fn from(raw_type: coap_pdu_type_t) -> Self {
        num_traits::FromPrimitive::from_u32(raw_type as u32).expect("unknown PDU type")
    }
}

fn convert_to_fixed_size_slice(n: usize, val: &[u8]) -> Box<[u8]> {
    if val.len() > n {
        panic!("supplied slice too short");
    }
    let mut buffer: Vec<u8> = vec![0; n];
    let (_, target_buffer) = buffer.split_at_mut(n - val.len());
    target_buffer.copy_from_slice(val);
    buffer.truncate(n);
    buffer.into_boxed_slice()
}

pub(crate) fn decode_var_len_u32(val: &[u8]) -> u32 {
    u32::from_be_bytes(convert_to_fixed_size_slice(4, val)[..4].try_into().unwrap())
}

pub(crate) fn encode_var_len_u32(val: u32) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub(crate) fn decode_var_len_u64(val: &[u8]) -> u64 {
    u64::from_be_bytes(convert_to_fixed_size_slice(8, val)[..8].try_into().unwrap())
}

pub(crate) fn encode_var_len_u64(val: u64) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub(crate) fn decode_var_len_u16(val: &[u8]) -> u16 {
    u16::from_be_bytes(convert_to_fixed_size_slice(2, val)[..2].try_into().unwrap())
}

pub(crate) fn encode_var_len_u16(val: u16) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub(crate) fn decode_var_len_u8(val: &[u8]) -> u16 {
    u16::from_be_bytes(convert_to_fixed_size_slice(1, val)[..1].try_into().unwrap())
}

pub(crate) fn encode_var_len_u8(val: u8) -> Box<[u8]> {
    Vec::from([val]).into_boxed_slice()
}

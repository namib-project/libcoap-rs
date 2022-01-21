

use libcoap_sys::{
    coap_option_num_t, coap_pdu_code_t, coap_pdu_type_t,
    coap_pdu_type_t::{COAP_MESSAGE_ACK, COAP_MESSAGE_CON, COAP_MESSAGE_NON, COAP_MESSAGE_RST},
    coap_proto_t,
    coap_proto_t::{COAP_PROTO_DTLS, COAP_PROTO_NONE, COAP_PROTO_TCP, COAP_PROTO_TLS, COAP_PROTO_UDP},
    coap_request_t, COAP_MEDIATYPE_ANY, COAP_MEDIATYPE_APPLICATION_CBOR,
    COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT, COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0,
    COAP_MEDIATYPE_APPLICATION_COSE_KEY, COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET, COAP_MEDIATYPE_APPLICATION_COSE_MAC,
    COAP_MEDIATYPE_APPLICATION_COSE_MAC0, COAP_MEDIATYPE_APPLICATION_COSE_SIGN, COAP_MEDIATYPE_APPLICATION_COSE_SIGN1,
    COAP_MEDIATYPE_APPLICATION_CWT, COAP_MEDIATYPE_APPLICATION_DOTS_CBOR, COAP_MEDIATYPE_APPLICATION_EXI,
    COAP_MEDIATYPE_APPLICATION_JSON, COAP_MEDIATYPE_APPLICATION_LINK_FORMAT, COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
    COAP_MEDIATYPE_APPLICATION_RDF_XML, COAP_MEDIATYPE_APPLICATION_SENML_CBOR, COAP_MEDIATYPE_APPLICATION_SENML_EXI,
    COAP_MEDIATYPE_APPLICATION_SENML_JSON, COAP_MEDIATYPE_APPLICATION_SENML_XML,
    COAP_MEDIATYPE_APPLICATION_SENSML_CBOR, COAP_MEDIATYPE_APPLICATION_SENSML_EXI,
    COAP_MEDIATYPE_APPLICATION_SENSML_JSON, COAP_MEDIATYPE_APPLICATION_SENSML_XML, COAP_MEDIATYPE_APPLICATION_XML,
    COAP_MEDIATYPE_TEXT_PLAIN, COAP_OPTION_ACCEPT, COAP_OPTION_BLOCK1, COAP_OPTION_BLOCK2, COAP_OPTION_CONTENT_FORMAT, COAP_OPTION_ETAG, COAP_OPTION_HOP_LIMIT, COAP_OPTION_IF_MATCH, COAP_OPTION_IF_NONE_MATCH,
    COAP_OPTION_LOCATION_PATH, COAP_OPTION_LOCATION_QUERY, COAP_OPTION_MAXAGE, COAP_OPTION_NORESPONSE,
    COAP_OPTION_OBSERVE, COAP_OPTION_PROXY_SCHEME, COAP_OPTION_PROXY_URI, COAP_OPTION_SIZE1,
    COAP_OPTION_SIZE2, COAP_OPTION_URI_HOST, COAP_OPTION_URI_PATH, COAP_OPTION_URI_PORT, COAP_OPTION_URI_QUERY,
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::{
    error::{
        MessageCodeConversionError, UnknownOptionError,
    },
};

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

pub type CoapOptionNum = u16;
pub type CoapToken = Box<[u8]>;

#[derive(Clone)]
pub enum CoapMatch {
    ETag(ETag),
    Empty,
}

#[repr(u16)]
#[non_exhaustive]
#[derive(FromPrimitive, Copy, Clone, Debug)]
pub enum CoapOptionType {
    IfMatch = COAP_OPTION_IF_MATCH as u16,
    UriHost = COAP_OPTION_URI_HOST as u16,
    ETag = COAP_OPTION_ETAG as u16,
    IfNoneMatch = COAP_OPTION_IF_NONE_MATCH as u16,
    UriPort = COAP_OPTION_URI_PORT as u16,
    LocationPath = COAP_OPTION_LOCATION_PATH as u16,
    UriPath = COAP_OPTION_URI_PATH as u16,
    ContentFormat = COAP_OPTION_CONTENT_FORMAT as u16,
    MaxAge = COAP_OPTION_MAXAGE as u16,
    UriQuery = COAP_OPTION_URI_QUERY as u16,
    Accept = COAP_OPTION_ACCEPT as u16,
    LocationQuery = COAP_OPTION_LOCATION_QUERY as u16,
    ProxyUri = COAP_OPTION_PROXY_URI as u16,
    ProxyScheme = COAP_OPTION_PROXY_SCHEME as u16,
    Size1 = COAP_OPTION_SIZE1 as u16,
    Size2 = COAP_OPTION_SIZE2 as u16,
    // TODO
    //OsCore = COAP_OPTION_OSCORE as u16,
    Block1 = COAP_OPTION_BLOCK1 as u16,
    Block2 = COAP_OPTION_BLOCK2 as u16,
    HopLimit = COAP_OPTION_HOP_LIMIT as u16,
    NoResponse = COAP_OPTION_NORESPONSE as u16,
    Observe = COAP_OPTION_OBSERVE as u16,
}

impl CoapOptionType {
    pub fn to_raw_option_num(self) -> coap_option_num_t {
        coap_option_num_t::from(self as u16)
    }

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

#[repr(u16)]
#[derive(Copy, Clone, FromPrimitive)]
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

#[repr(u32)]
#[non_exhaustive]
#[derive(Copy, Clone, FromPrimitive)]
pub enum CoapProtocol {
    None = COAP_PROTO_NONE as u32,
    Udp = COAP_PROTO_UDP as u32,
    Dtls = COAP_PROTO_DTLS as u32,
    Tcp = COAP_PROTO_TCP as u32,
    Tls = COAP_PROTO_TLS as u32,
}

impl From<coap_proto_t> for CoapProtocol {
    fn from(raw_proto: coap_proto_t) -> Self {
        <CoapProtocol as FromPrimitive>::from_u32(raw_proto as u32).expect("unknown protocol")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CoapMessageCode {
    Empty,
    Request(CoapRequestCode),
    Response(CoapResponseCode),
}

impl CoapMessageCode {
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
    // TODO
    type Error = MessageCodeConversionError;

    fn try_from(code: coap_pdu_code_t) -> Result<Self, Self::Error> {
        match code {
            coap_pdu_code_t::COAP_EMPTY_CODE => Ok(CoapMessageCode::Empty),
            code => CoapRequestCode::try_from_raw_pdu_code(code)
                .map(|v| CoapMessageCode::Request(v))
                .or_else(|_| CoapResponseCode::try_from_raw_pdu_code(code).map(|v| CoapMessageCode::Response(v))),
        }
    }
}

#[repr(u8)]
#[non_exhaustive]
#[derive(FromPrimitive, Clone, Copy, Eq, PartialEq, Debug)]
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

    pub fn try_from_raw_pdu_code(req: coap_pdu_code_t) -> Result<CoapRequestCode, MessageCodeConversionError> {
        <CoapRequestCode as FromPrimitive>::from_u32(req as u32).ok_or(MessageCodeConversionError::NotARequestCode)
    }

    pub fn from_raw_request(req: coap_request_t) -> CoapRequestCode {
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

impl From<coap_request_t> for CoapRequestCode {
    fn from(req: coap_request_t) -> Self {
        CoapRequestCode::from_raw_request(req)
    }
}

impl TryFrom<coap_pdu_code_t> for CoapRequestCode {
    type Error = MessageCodeConversionError;

    fn try_from(req: coap_pdu_code_t) -> Result<Self, Self::Error> {
        CoapRequestCode::try_from_raw_pdu_code(req)
    }
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Clone, Copy, FromPrimitive, Debug, Eq, PartialEq)]
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

    pub fn try_from_raw_pdu_code(rsp: coap_pdu_code_t) -> Result<CoapResponseCode, MessageCodeConversionError> {
        <CoapResponseCode as FromPrimitive>::from_u32(rsp as u32).ok_or(MessageCodeConversionError::NotAResponseCode)
    }
}

impl TryFrom<coap_pdu_code_t> for CoapResponseCode {
    type Error = MessageCodeConversionError;

    fn try_from(value: coap_pdu_code_t) -> Result<Self, Self::Error> {
        CoapResponseCode::try_from_raw_pdu_code(value)
    }
}

#[repr(u8)]
#[derive(Copy, Clone, FromPrimitive)]
pub enum CoapMessageType {
    Con = COAP_MESSAGE_CON as u8,
    Non = COAP_MESSAGE_NON as u8,
    Ack = COAP_MESSAGE_ACK as u8,
    Rst = COAP_MESSAGE_RST as u8,
}

impl CoapMessageType {
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
    return buffer.into_boxed_slice();
}

pub fn decode_var_len_u32(val: &[u8]) -> u32 {
    u32::from_be_bytes(convert_to_fixed_size_slice(4, val)[..4].try_into().unwrap())
}

pub fn encode_var_len_u32(val: u32) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub fn decode_var_len_u64(val: &[u8]) -> u64 {
    u64::from_be_bytes(convert_to_fixed_size_slice(8, val)[..8].try_into().unwrap())
}

pub fn encode_var_len_u64(val: u64) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub fn decode_var_len_u16(val: &[u8]) -> u16 {
    u16::from_be_bytes(convert_to_fixed_size_slice(2, val)[..2].try_into().unwrap())
}

pub fn encode_var_len_u16(val: u16) -> Box<[u8]> {
    // I really hope that rust accounts for endianness here.
    let bytes_to_discard = val.leading_zeros() / 8;
    let mut ret_val = Vec::from(val.to_be_bytes());
    ret_val.drain(..bytes_to_discard as usize);
    ret_val.into_boxed_slice()
}

pub fn decode_var_len_u8(val: &[u8]) -> u16 {
    u16::from_be_bytes(convert_to_fixed_size_slice(1, val)[..1].try_into().unwrap())
}

pub fn encode_var_len_u8(val: u8) -> Box<[u8]> {
    Vec::from([val]).into_boxed_slice()
}

use std::{collections::HashMap, fmt::format};

use libcoap_sys::{coap_option, coap_option_num_t, coap_option_t};
use rand::Rng;
use url::Url;

use crate::{
    error::{MessageConversionError, OptionValueError},
    message::{CoapMessage, CoapOption},
    protocol::{
        CoapContentFormat, CoapMatch, CoapMessageCode, CoapMessageType, CoapOptionType, CoapRequestCode,
        CoapResponseCode, CoapToken, ETag, MaxAge,
    },
    session::{CoapClientSession, CoapSession},
    types::{CoapMessageId, CoapUri, CoapUriHost},
};

#[derive(Clone)]
pub enum CoapRequestUri {
    Request(CoapUri),
    Proxy(CoapUri),
}

impl CoapRequestUri {
    pub fn new_request_uri(uri: CoapUri) -> Result<CoapRequestUri, OptionValueError> {
        if uri.scheme().is_some() || uri.port().is_some() && !uri.host().is_some() {
            return Err(OptionValueError::IllegalValue);
        }
        if let Some(iter) = uri.path_iter() {
            if iter.filter(|p| p.len() > 255).count() > 0 {
                return Err(OptionValueError::TooLong);
            }
        }
        if let Some(iter) = uri.query_iter() {
            if iter.filter(|p| p.len() > 255).count() > 0 {
                return Err(OptionValueError::TooLong);
            }
        }
        Ok(CoapRequestUri::Request(uri))
    }

    pub fn new_proxy_uri(uri: CoapUri) -> Result<CoapRequestUri, OptionValueError> {
        if uri.scheme().is_none() || uri.host().is_none() {
            return Err(OptionValueError::IllegalValue);
        }
        if CoapRequestUri::generate_proxy_uri_string(&uri).len() > 1034 {
            return Err(OptionValueError::TooLong);
        }
        Ok(CoapRequestUri::Proxy(uri))
    }

    fn generate_proxy_uri_string(uri: &CoapUri) -> String {
        let mut proxy_uri_string = format!(
            "{}://{}",
            uri.scheme().unwrap().to_string().as_str(),
            uri.host().unwrap().to_string().as_str()
        );
        if let Some(port) = uri.port() {
            proxy_uri_string.push_str(format!(":{}", port).as_str());
        }
        if let Some(path) = uri.path_iter() {
            path.for_each(|path_component| {
                proxy_uri_string.push_str(format!("/{}", path_component).as_str());
            });
        }
        if let Some(query) = uri.query_iter() {
            let mut separator_char = '?';
            query.for_each(|query_option| {
                proxy_uri_string.push_str(format!("{}{}", separator_char, query_option).as_str());
                separator_char = '&';
            });
        }
        proxy_uri_string
    }

    pub fn to_options(mut self) -> Vec<CoapOption> {
        let mut options = Vec::new();
        match self {
            CoapRequestUri::Request(mut uri) => {
                if let Some(host) = uri.host() {
                    options.push(CoapOption::UriHost(host.to_string()))
                }
                if let Some(port) = uri.port() {
                    options.push(CoapOption::UriPort(port))
                }
                if let Some(path) = uri.drain_path_iter() {
                    path.for_each(|path_component| options.push(CoapOption::UriPath(path_component)));
                }
                if let Some(query) = uri.drain_query_iter() {
                    query.for_each(|query_option| options.push(CoapOption::UriQuery(query_option)));
                }
            },
            CoapRequestUri::Proxy(uri) => {
                options.push(CoapOption::ProxyUri(CoapRequestUri::generate_proxy_uri_string(&uri)))
            },
        }
        options
    }
}

impl TryFrom<CoapUri> for CoapRequestUri {
    type Error = OptionValueError;

    fn try_from(value: CoapUri) -> Result<Self, Self::Error> {
        CoapRequestUri::new_request_uri(value)
    }
}

#[derive(Clone)]
pub struct CoapResponseLocation(CoapUri);

impl CoapResponseLocation {
    pub fn new_response_location(uri: CoapUri) -> Result<CoapResponseLocation, OptionValueError> {
        if uri.scheme().is_some() || uri.host().is_some() || uri.port().is_some() {
            return Err(OptionValueError::IllegalValue);
        }
        Ok(CoapResponseLocation(uri))
    }

    pub fn into_options(mut self) -> Vec<CoapOption> {
        let mut options = Vec::new();
        let mut uri = self.0;
        if let Some(path) = uri.drain_path_iter() {
            path.for_each(|path_component| options.push(CoapOption::LocationPath(path_component)));
        }
        if let Some(query) = uri.drain_query_iter() {
            query.for_each(|query_option| options.push(CoapOption::LocationQuery(query_option)));
        }
        options
    }
}

impl TryFrom<CoapUri> for CoapResponseLocation {
    type Error = OptionValueError;

    fn try_from(value: CoapUri) -> Result<Self, Self::Error> {
        CoapResponseLocation::new_response_location(value)
    }
}

pub struct CoapRequestHandle {}

pub struct CoapRequest {
    pdu: CoapMessage,
    uri: Option<CoapRequestUri>,
    accept: Option<CoapContentFormat>,
    max_age: Option<MaxAge>,
    etag: Option<ETag>,
    if_match: Option<CoapMatch>,
}

impl CoapRequest {
    pub fn new(session: &CoapSession, code: CoapRequestCode) -> CoapRequest {
        let mut token: Vec<u8> = vec![0; 8];
        rand::thread_rng().fill(&mut token[0..8]);
        CoapRequest {
            pdu: CoapMessage::new(
                session.next_message_id(),
                CoapMessageType::Con,
                code.into(),
                token.into_boxed_slice(),
                session.max_pdu_size(),
            ),
            uri: None,
            accept: None,
            max_age: None,
            etag: None,
            if_match: None,
        }
    }

    pub fn accept(&self) -> Option<CoapContentFormat> {
        self.accept
    }

    pub fn set_accept(&mut self, accept: Option<CoapContentFormat>) {
        self.accept = accept
    }

    pub fn max_age(&self) -> Option<MaxAge> {
        self.max_age
    }

    pub fn set_max_age(&mut self, max_age: Option<MaxAge>) {
        self.max_age = max_age
    }

    pub fn etag(&self) -> Option<&ETag> {
        self.etag.as_ref()
    }

    pub fn set_etag(&mut self, etag: Option<ETag>) {
        self.etag = etag
    }

    pub fn if_match(&self) -> Option<&CoapMatch> {
        self.if_match.as_ref()
    }

    pub fn set_if_match(&mut self, if_match: Option<CoapMatch>) {
        self.if_match = if_match
    }

    pub fn type_(&self) -> CoapMessageType {
        self.pdu.type_()
    }

    pub fn set_type_(&mut self, type_: CoapMessageType) {
        self.pdu.set_type_(type_)
    }

    pub fn code(&self) -> CoapMessageCode {
        self.pdu.code()
    }

    pub fn set_code(&mut self, code: CoapRequestCode) {
        self.pdu.set_code(CoapMessageCode::Request(code))
    }

    pub fn uri(&self) -> Option<&CoapRequestUri> {
        self.uri.as_ref()
    }

    pub fn set_uri<U: Into<CoapRequestUri>>(&mut self, uri: Option<U>) {
        self.uri = uri.map(|v| v.into())
    }

    pub fn data(&self) -> Option<&Box<[u8]>> {
        self.pdu.data()
    }

    pub fn set_data<D: Into<Box<[u8]>>>(&mut self, data: Option<D>) {
        self.pdu.set_data(data);
    }

    pub fn token(&self) -> &Box<[u8]> {
        self.pdu.token()
    }

    pub fn set_token<D: Into<Box<[u8]>>>(&mut self, token: D) {
        self.pdu.set_token(token)
    }

    pub fn from_pdu(pdu: CoapMessage) -> Result<CoapRequest, MessageConversionError> {
        let mut host = None;
        let mut port = None;
        let mut path = Vec::new();
        let mut query = Vec::new();
        for option in pdu.options_iter() {
            match option {
                CoapOption::IfMatch(_) => {},
                CoapOption::IfNoneMatch => {},
                CoapOption::UriHost(value) => {
                    host = Some(value.clone());
                },
                CoapOption::UriPort(uri_port) => port = Some(uri_port.clone()),
                CoapOption::UriPath(value) => path.push(value.clone()),
                CoapOption::UriQuery(value) => query.push(value.clone()),
                CoapOption::LocationPath(_) => {},
                CoapOption::LocationQuery(_) => {},
                CoapOption::ProxyUri(_) => {},
                CoapOption::ProxyScheme(_) => {},
                CoapOption::ContentFormat(_) => {},
                CoapOption::Accept(_) => {},
                CoapOption::Size1(_) => {},
                CoapOption::Size2(_) => {},
                CoapOption::Block1(_) => {},
                CoapOption::Block2(_) => {},
                CoapOption::HopLimit(_) => {},
                CoapOption::NoResponse(_) => {},
                CoapOption::ETag(_) => {},
                CoapOption::MaxAge(_) => {},
                CoapOption::Other(_, _) => {},
                CoapOption::Observe(_) => {},
            }
        }
        Ok(CoapRequest {
            pdu,
            uri: Some(CoapRequestUri::Request(CoapUri::new(
                None,
                host.map(|v| CoapUriHost::Name(v)),
                port,
                if path.is_empty() { None } else { Some(path) },
                if query.is_empty() { None } else { Some(query) },
            ))),
            accept: None,
            max_age: None,
            etag: None,
            if_match: None,
        })
    }

    pub fn into_pdu(mut self) -> Result<CoapMessage, MessageConversionError> {
        if let Some(req_uri) = self.uri {
            req_uri.to_options().into_iter().for_each(|v| self.pdu.add_option(v));
        }
        Ok(self.pdu)
    }
}

pub struct CoapResponse {
    pdu: CoapMessage,
    content_format: Option<CoapContentFormat>,
    etag: Option<ETag>,
    location: Option<CoapResponseLocation>,
}

impl CoapResponse {
    pub fn new(
        session: &CoapSession,
        type_: CoapMessageType,
        code: CoapResponseCode,
        token: CoapToken,
    ) -> CoapResponse {
        CoapResponse {
            pdu: CoapMessage::new(
                session.next_message_id(),
                type_,
                code.into(),
                token,
                session.max_pdu_size(),
            ),
            content_format: None,
            etag: None,
            location: None,
        }
    }

    pub fn type_(&self) -> CoapMessageType {
        self.pdu.type_()
    }

    pub fn set_type_(&mut self, type_: CoapMessageType) {
        self.pdu.set_type_(type_)
    }

    pub fn data(&self) -> Option<&Box<[u8]>> {
        self.pdu.data()
    }

    pub fn set_data<D: Into<Box<[u8]>>>(&mut self, data: Option<D>) {
        self.pdu.set_data(data);
    }

    pub fn code(&self) -> CoapMessageCode {
        self.pdu.code()
    }

    pub fn set_code(&mut self, code: CoapResponseCode) {
        self.pdu.set_code(CoapMessageCode::Response(code))
    }

    pub fn into_pdu(mut self) -> Result<CoapMessage, MessageConversionError> {
        Ok(self.pdu)
    }

    pub fn from_pdu(pdu: CoapMessage) -> Result<CoapResponse, MessageConversionError> {
        Ok(CoapResponse {
            pdu,
            content_format: None,
            etag: None,
            location: None,
        })
    }
}

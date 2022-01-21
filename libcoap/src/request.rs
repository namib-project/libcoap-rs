use std::{str::FromStr};



use url::Url;

use crate::{
    error::{MessageConversionError, OptionValueError},
    message::{CoapMessage, CoapMessageCommon, CoapOption},
    protocol::{
        CoapMatch, CoapMessageType, CoapOptionType, CoapRequestCode,
        CoapResponseCode, ContentFormat, ETag, HopLimit, MaxAge, NoResponse, Observe,
    },
    types::{CoapUri, CoapUriHost, CoapUriScheme},
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

    pub fn into_options(self) -> Vec<CoapOption> {
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

    pub fn into_options(self) -> Vec<CoapOption> {
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
    accept: Option<ContentFormat>,
    etag: Option<Vec<ETag>>,
    if_match: Option<Vec<CoapMatch>>,
    content_format: Option<ContentFormat>,
    if_none_match: bool,
    hop_limit: Option<HopLimit>,
    no_response: Option<NoResponse>,
    observe: Option<Observe>,
}

impl CoapRequest {
    pub fn new(type_: CoapMessageType, code: CoapRequestCode) -> CoapRequest {
        CoapRequest {
            pdu: CoapMessage::new(type_, code.into()),
            uri: None,
            accept: None,
            etag: None,
            if_match: None,
            content_format: None,
            if_none_match: false,
            hop_limit: None,
            no_response: None,
            observe: None,
        }
    }

    pub fn accept(&self) -> Option<ContentFormat> {
        self.accept
    }

    pub fn set_accept(&mut self, accept: Option<ContentFormat>) {
        self.accept = accept
    }

    pub fn etag(&self) -> Option<&Vec<ETag>> {
        self.etag.as_ref()
    }

    pub fn set_etag(&mut self, etag: Option<Vec<ETag>>) {
        self.etag = etag
    }

    pub fn if_match(&self) -> Option<&Vec<CoapMatch>> {
        self.if_match.as_ref()
    }

    pub fn set_if_match(&mut self, if_match: Option<Vec<CoapMatch>>) {
        self.if_match = if_match
    }

    pub fn content_format(&self) -> Option<ContentFormat> {
        self.content_format
    }

    pub fn set_content_format(&mut self, content_format: Option<ContentFormat>) {
        self.content_format = content_format;
    }

    pub fn if_none_match(&self) -> bool {
        self.if_none_match
    }

    pub fn set_if_none_match(&mut self, if_none_match: bool) {
        self.if_none_match = if_none_match
    }

    pub fn hop_limit(&self) -> Option<HopLimit> {
        self.hop_limit
    }

    pub fn set_hop_limit(&mut self, hop_limit: Option<HopLimit>) {
        self.hop_limit = hop_limit;
    }

    pub fn no_response(&self) -> Option<NoResponse> {
        self.no_response
    }

    pub fn set_no_response(&mut self, no_response: Option<NoResponse>) {
        self.no_response = no_response;
    }

    pub fn observe(&self) -> Option<Observe> {
        self.observe
    }

    pub fn set_observe(&mut self, observe: Option<Observe>) {
        self.observe = observe;
    }

    pub fn uri(&self) -> Option<&CoapRequestUri> {
        self.uri.as_ref()
    }

    pub fn set_uri<U: Into<CoapRequestUri>>(&mut self, uri: Option<U>) {
        self.uri = uri.map(|v| v.into())
    }

    pub fn from_pdu(mut pdu: CoapMessage) -> Result<CoapRequest, MessageConversionError> {
        let mut host = None;
        let mut port = None;
        let mut path = None;
        let mut query = None;
        let mut proxy_scheme = None;
        let mut proxy_uri = None;
        let mut content_format = None;
        let mut etag = None;
        let mut if_match = None;
        let mut if_none_match = false;
        let mut accept = None;
        let mut hop_limit = None;
        let mut no_response = None;
        let mut observe = None;
        let mut additional_opts = Vec::new();
        for option in pdu.options_iter() {
            match option {
                CoapOption::IfMatch(value) => {
                    if if_match.is_none() {
                        if_match = Some(Vec::new());
                    }
                    if_match.as_mut().unwrap().push(value.clone());
                },
                CoapOption::IfNoneMatch => {
                    if if_none_match {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::IfNoneMatch,
                        ));
                    }
                    if_none_match = true;
                },
                CoapOption::UriHost(value) => {
                    if host.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::UriHost,
                        ));
                    }
                    host = Some(value.clone());
                },
                CoapOption::UriPort(value) => {
                    if port.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::UriPort,
                        ));
                    }
                    port = Some(value.clone());
                },
                CoapOption::UriPath(value) => {
                    if path.is_none() {
                        path = Some(Vec::new());
                    }
                    path.as_mut().unwrap().push(value.clone());
                },
                CoapOption::UriQuery(value) => {
                    if query.is_none() {
                        query = Some(Vec::new());
                    }
                    query.as_mut().unwrap().push(value.clone());
                },
                CoapOption::LocationPath(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::LocationPath,
                    ))
                },
                CoapOption::LocationQuery(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::LocationQuery,
                    ))
                },
                CoapOption::ProxyUri(uri) => {
                    if proxy_uri.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ProxyUri,
                        ));
                    }
                    proxy_uri = Some(uri.clone())
                },
                CoapOption::ProxyScheme(scheme) => {
                    if proxy_scheme.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ProxyScheme,
                        ));
                    }
                    proxy_scheme = Some(CoapUriScheme::from_str(scheme)?)
                },
                CoapOption::ContentFormat(cformat) => {
                    if content_format.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ContentFormat,
                        ));
                    }
                    content_format = Some(cformat.clone())
                },
                CoapOption::Accept(value) => {
                    if accept.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Accept,
                        ));
                    }
                    accept = Some(value.clone());
                },
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::Size1(_) => {},
                CoapOption::Size2(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Size2,
                    ))
                },
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::Block1(_) => {},
                CoapOption::Block2(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Block2,
                    ))
                },
                CoapOption::HopLimit(value) => {
                    if hop_limit.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::HopLimit,
                        ));
                    }
                    hop_limit = Some(value.clone());
                },
                CoapOption::NoResponse(value) => {
                    if no_response.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::NoResponse,
                        ));
                    }
                    no_response = Some(value.clone());
                },
                CoapOption::ETag(value) => {
                    if etag.is_none() {
                        etag = Some(Vec::new());
                    }
                    etag.as_mut().unwrap().push(value.clone());
                },
                CoapOption::MaxAge(_value) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::MaxAge,
                    ));
                },
                CoapOption::Observe(value) => {
                    if observe.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::MaxAge,
                        ));
                    }
                    observe = Some(value.clone());
                },
                // TODO maybe we can save some copies here if we use into_iter for the options instead.
                CoapOption::Other(n, v) => {
                    additional_opts.push(CoapOption::Other(*n, v.clone()));
                },
            }
        }
        pdu.clear_options();
        for opt in additional_opts {
            (&mut pdu).add_option(opt);
        }
        if proxy_scheme.is_some() && proxy_uri.is_some() {
            return Err(MessageConversionError::InvalidOptionCombination(
                CoapOptionType::ProxyScheme,
                CoapOptionType::ProxyUri,
            ));
        }
        let uri = if let Some(proxy_uri) = proxy_uri {
            Some(CoapUri::try_from_url(Url::parse(&proxy_uri)?)?)
        } else {
            Some(CoapUri::new(
                proxy_scheme,
                host.map(|v| CoapUriHost::from_str(v.as_str()).unwrap()),
                port,
                path,
                query,
            ))
        }
        .map(|uri| {
            if uri.scheme().is_some() {
                CoapRequestUri::new_proxy_uri(uri)
            } else {
                CoapRequestUri::new_request_uri(uri)
            }
        });
        let uri = if let Some(uri) = uri { Some(uri?) } else { None };
        Ok(CoapRequest {
            pdu,
            uri,
            accept,
            etag,
            if_match,
            content_format,
            if_none_match,
            hop_limit,
            no_response,
            observe,
        })
    }

    pub fn into_pdu(mut self) -> Result<CoapMessage, MessageConversionError> {
        if let Some(req_uri) = self.uri {
            req_uri.into_options().into_iter().for_each(|v| self.pdu.add_option(v));
        }
        if let Some(accept) = self.accept {
            self.pdu.add_option(CoapOption::Accept(accept))
        }
        if let Some(etags) = self.etag {
            for etag in etags {
                self.pdu.add_option(CoapOption::ETag(etag));
            }
        }
        if let Some(if_match) = self.if_match {
            for match_expr in if_match {
                self.pdu.add_option(CoapOption::IfMatch(match_expr));
            }
        }
        if let Some(content_format) = self.content_format {
            self.pdu.add_option(CoapOption::ContentFormat(content_format));
        }
        if self.if_none_match {
            self.pdu.add_option(CoapOption::IfNoneMatch);
        }
        if let Some(hop_limit) = self.hop_limit {
            self.pdu.add_option(CoapOption::HopLimit(hop_limit));
        }
        if let Some(no_response) = self.no_response {
            self.pdu.add_option(CoapOption::NoResponse(no_response));
        }
        if let Some(observe) = self.observe {
            self.pdu.add_option(CoapOption::Observe(observe));
        }
        Ok(self.pdu)
    }
}

impl CoapMessageCommon for CoapRequest {
    fn as_message(&self) -> &CoapMessage {
        &self.pdu
    }

    fn as_message_mut(&mut self) -> &mut CoapMessage {
        &mut self.pdu
    }
}

pub struct CoapResponse {
    pdu: CoapMessage,
    content_format: Option<ContentFormat>,
    max_age: Option<MaxAge>,
    etag: Option<ETag>,
    location: Option<CoapResponseLocation>,
    observe: Option<Observe>,
}

impl CoapResponse {
    pub fn new(type_: CoapMessageType, code: CoapResponseCode) -> CoapResponse {
        CoapResponse {
            pdu: CoapMessage::new(type_, code.into()),
            content_format: None,
            max_age: None,
            etag: None,
            location: None,
            observe: None,
        }
    }

    pub fn max_age(&self) -> Option<MaxAge> {
        self.max_age
    }

    pub fn set_max_age(&mut self, max_age: Option<MaxAge>) {
        self.max_age = max_age
    }

    pub fn content_format(&self) -> Option<ContentFormat> {
        self.content_format
    }

    pub fn set_content_format(&mut self, content_format: Option<ContentFormat>) {
        self.content_format = content_format;
    }

    pub fn etag(&self) -> Option<&ETag> {
        self.etag.as_ref()
    }

    pub fn set_etag(&mut self, etag: Option<ETag>) {
        self.etag = etag
    }

    pub fn observe(&self) -> Option<Observe> {
        self.observe
    }

    pub fn set_observe(&mut self, observe: Option<Observe>) {
        self.observe = observe;
    }

    pub fn location(&self) -> Option<&CoapResponseLocation> {
        self.location.as_ref()
    }

    pub fn set_location<U: Into<CoapResponseLocation>>(&mut self, uri: Option<U>) {
        self.location = uri.map(Into::into)
    }

    pub fn into_pdu(mut self) -> Result<CoapMessage, MessageConversionError> {
        if let Some(loc) = self.location {
            loc.into_options().into_iter().for_each(|v| self.pdu.add_option(v));
        }
        if let Some(max_age) = self.max_age {
            self.pdu.add_option(CoapOption::MaxAge(max_age));
        }
        if let Some(content_format) = self.content_format {
            self.pdu.add_option(CoapOption::ContentFormat(content_format));
        }
        if let Some(etag) = self.etag {
            self.pdu.add_option(CoapOption::ETag(etag));
        }
        if let Some(observe) = self.observe {
            self.pdu.add_option(CoapOption::Observe(observe));
        }
        Ok(self.pdu)
    }

    pub fn from_pdu(pdu: CoapMessage) -> Result<CoapResponse, MessageConversionError> {
        let mut location_path = None;
        let mut location_query = None;
        let mut max_age = None;
        let mut etag = None;
        let mut observe = None;
        let mut content_format = None;
        let mut additional_opts = Vec::new();
        for option in pdu.options_iter() {
            match option {
                CoapOption::LocationPath(value) => {
                    if location_path.is_none() {
                        location_path = Some(Vec::new());
                    }
                    location_path.as_mut().unwrap().push(value.clone());
                },
                CoapOption::LocationQuery(value) => {
                    if location_query.is_none() {
                        location_query = Some(Vec::new());
                    }
                    location_query.as_mut().unwrap().push(value.clone());
                },
                CoapOption::ETag(value) => {
                    if etag.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ETag,
                        ));
                    }
                    etag = Some(value.clone());
                },
                CoapOption::MaxAge(value) => {
                    if max_age.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::MaxAge,
                        ));
                    }
                    max_age = Some(value.clone());
                },
                CoapOption::Observe(value) => {
                    if observe.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Observe,
                        ));
                    }
                    observe = Some(value.clone())
                },
                CoapOption::IfMatch(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::IfMatch,
                    ));
                },
                CoapOption::IfNoneMatch => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::IfNoneMatch,
                    ));
                },
                CoapOption::UriHost(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriHost,
                    ));
                },
                CoapOption::UriPort(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriPort,
                    ));
                },
                CoapOption::UriPath(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriPath,
                    ));
                },
                CoapOption::UriQuery(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriQuery,
                    ));
                },
                CoapOption::ProxyUri(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::ProxyUri,
                    ));
                },
                CoapOption::ProxyScheme(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::ProxyScheme,
                    ));
                },
                CoapOption::ContentFormat(value) => {
                    if content_format.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ContentFormat,
                        ));
                    }
                    content_format = Some(value.clone())
                },
                CoapOption::Accept(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Accept,
                    ));
                },
                CoapOption::Size1(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Size1,
                    ));
                },
                CoapOption::Size2(_) => {},
                CoapOption::Block1(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Block1,
                    ));
                },
                CoapOption::Block2(_) => {},
                CoapOption::HopLimit(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::HopLimit,
                    ));
                },
                CoapOption::NoResponse(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::NoResponse,
                    ));
                },
                CoapOption::Other(n, v) => additional_opts.push(CoapOption::Other(*n, v.clone())),
            }
        }
        let location = if location_path.is_some() || location_query.is_some() {
            Some(CoapResponseLocation::new_response_location(CoapUri::new(
                None,
                None,
                None,
                location_path,
                location_query,
            ))?)
        } else {
            None
        };
        Ok(CoapResponse {
            pdu,
            content_format,
            max_age,
            etag,
            location,
            observe,
        })
    }
}

impl CoapMessageCommon for CoapResponse {
    fn as_message(&self) -> &CoapMessage {
        &self.pdu
    }

    fn as_message_mut(&mut self) -> &mut CoapMessage {
        &mut self.pdu
    }
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * request.rs - Types wrapping messages into requests and responses.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::str::FromStr;

use url::Url;

use crate::{
    error::{MessageConversionError, MessageTypeError, OptionValueError},
    message::{CoapMessage, CoapMessageCommon, CoapOption},
    protocol::{
        CoapMatch, CoapMessageCode, CoapMessageType, CoapOptionType, CoapRequestCode, CoapResponseCode, ContentFormat,
        ETag, HopLimit, MaxAge, NoResponse, Observe,
    },
    types::{CoapUri, CoapUriHost, CoapUriScheme},
};

/// Internal representation of a CoAP URI that can be used for requests
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
enum CoapRequestUri {
    Request(CoapUri),
    Proxy(CoapUri),
}

impl CoapRequestUri {
    /// Creates a new request URI from the given CoapUri, returning an OptionValueError if the URI
    /// contains invalid values for request URIs.
    pub fn new_request_uri(uri: CoapUri) -> Result<CoapRequestUri, OptionValueError> {
        if uri.scheme().is_some() || uri.port().is_some() && uri.host().is_none() {
            return Err(OptionValueError::IllegalValue);
        }
        if uri
            .path_iter()
            .unwrap_or(vec![].iter())
            .chain(uri.query_iter().unwrap_or(vec![].iter()))
            .any(|x| x.len() > 255)
        {
            return Err(OptionValueError::TooShort);
        }
        Ok(CoapRequestUri::Request(uri))
    }

    /// Creates a new request proxy URI from the given CoapUri, returning an OptionValueError if
    /// the URI contains invalid values for proxy URIs.
    pub fn new_proxy_uri(uri: CoapUri) -> Result<CoapRequestUri, OptionValueError> {
        if uri.scheme().is_none() || uri.host().is_none() {
            return Err(OptionValueError::IllegalValue);
        }
        if CoapRequestUri::generate_proxy_uri_string(&uri).len() > 1034 {
            return Err(OptionValueError::TooLong);
        }
        Ok(CoapRequestUri::Proxy(uri))
    }

    /// Generate a proxy URI string corresponding to this request URI.
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

    /// Converts this request URI into a `Vec<CoapOption>` that can be added to a message.
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
                    options.extend(path.map(CoapOption::UriPath))
                }
                if let Some(query) = uri.drain_query_iter() {
                    options.extend(query.map(CoapOption::UriQuery))
                }
            }
            CoapRequestUri::Proxy(uri) => {
                options.push(CoapOption::ProxyUri(CoapRequestUri::generate_proxy_uri_string(&uri)))
            }
        }
        options
    }

    /// Returns an immutable reference to the underlying URI.
    pub fn as_uri(&self) -> &CoapUri {
        match self {
            CoapRequestUri::Request(uri) => uri,
            CoapRequestUri::Proxy(uri) => uri,
        }
    }
}

impl TryFrom<CoapUri> for CoapRequestUri {
    type Error = OptionValueError;

    fn try_from(value: CoapUri) -> Result<Self, Self::Error> {
        CoapRequestUri::new_request_uri(value)
    }
}

/// Internal representation of a CoAP URI that can be used as a response location.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CoapResponseLocation(CoapUri);

impl CoapResponseLocation {
    /// Creates a new response location from the given CoapUri, returning an OptionValueError if
    /// the URI contains invalid values for response locations.
    pub fn new_response_location(uri: CoapUri) -> Result<CoapResponseLocation, OptionValueError> {
        if uri.scheme().is_some() || uri.host().is_some() || uri.port().is_some() {
            return Err(OptionValueError::IllegalValue);
        }
        Ok(CoapResponseLocation(uri))
    }

    /// Converts this response location into a `Vec<CoapOption>` that can be added to a message.
    pub fn into_options(self) -> Vec<CoapOption> {
        let mut options = Vec::new();
        let mut uri = self.0;
        if let Some(path) = uri.drain_path_iter() {
            options.extend(path.map(CoapOption::LocationPath));
        }
        if let Some(query) = uri.drain_query_iter() {
            options.extend(query.map(CoapOption::LocationQuery));
        }
        options
    }

    /// Returns an immutable reference to the underlying URI.
    pub fn as_uri(&self) -> &CoapUri {
        &self.0
    }
}

impl TryFrom<CoapUri> for CoapResponseLocation {
    type Error = OptionValueError;

    fn try_from(value: CoapUri) -> Result<Self, Self::Error> {
        CoapResponseLocation::new_response_location(value)
    }
}

/// Representation of a CoAP request message.
///
/// This struct wraps around the more direct CoapMessage and allows easier definition of typical
/// options used in requests.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
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
    /// Creates a new CoAP request with the given message type and code.
    ///
    /// Returns an error if the given message type is not allowed for CoAP requests (the only
    /// allowed message types are [CoapMessageType::Con] and [CoapMessageType::Non]).
    pub fn new(type_: CoapMessageType, code: CoapRequestCode) -> Result<CoapRequest, MessageTypeError> {
        match type_ {
            CoapMessageType::Con | CoapMessageType::Non => {}
            v => return Err(MessageTypeError::InvalidForMessageCode(v)),
        }
        Ok(CoapRequest {
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
        })
    }

    /// Returns the "Accept" option value for this request.
    pub fn accept(&self) -> Option<ContentFormat> {
        self.accept
    }

    /// Sets the "Accept" option value for this request.
    ///
    /// This option indicates the acceptable content formats for the response.
    ///
    /// See [RFC 7252, Section 5.10.4](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.4)
    /// for more information.
    pub fn set_accept(&mut self, accept: Option<ContentFormat>) {
        self.accept = accept
    }

    /// Returns the "ETag" option value for this request.
    pub fn etag(&self) -> Option<&Vec<ETag>> {
        self.etag.as_ref()
    }

    /// Sets the "ETag" option value for this request.
    ///
    /// This option can be used to request a specific representation of the requested resource.
    ///
    /// The server may send an ETag value alongside a response, which the client can then set here
    /// to request the given representation.
    ///
    /// See [RFC 7252, Section 5.10.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.6)
    /// for more information.
    pub fn set_etag(&mut self, etag: Option<Vec<ETag>>) {
        self.etag = etag
    }

    /// Returns the "If-Match" option value for this request.
    pub fn if_match(&self) -> Option<&Vec<CoapMatch>> {
        self.if_match.as_ref()
    }

    /// Sets the "If-Match" option value for this request.
    ///
    /// This option indicates a match expression that must be fulfilled in order to perform the
    /// request.
    ///
    /// See [RFC 7252, Section 5.10.8.1](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.1)
    /// for more information.
    pub fn set_if_match(&mut self, if_match: Option<Vec<CoapMatch>>) {
        self.if_match = if_match
    }

    /// Returns the "Content-Format" option value for this request.
    pub fn content_format(&self) -> Option<ContentFormat> {
        self.content_format
    }

    /// Sets the "Content-Format" option value for this request.
    ///
    /// This option indicates the content format of the body of this message. It is not to be
    /// confused with the "Accept" option, which indicates the format that the body of the response
    /// to this message should have.
    ///
    /// See [RFC 7252, Section 5.10.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.3)
    /// for more information.
    pub fn set_content_format(&mut self, content_format: Option<ContentFormat>) {
        self.content_format = content_format;
    }

    /// Returns the "If-None-Match" option value of this request.
    pub fn if_none_match(&self) -> bool {
        self.if_none_match
    }

    /// Sets the "If-None-Match" option value for this request.
    ///
    /// This option indicates that no match expression may be fulfilled in order for this request
    /// to be fulfilled.
    ///
    /// It is usually nonsensical to set this value to `true` if an If-Match-Expression has been set.
    ///
    /// See [RFC 7252, Section 5.10.8.2](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.8.2)
    /// for more information.
    pub fn set_if_none_match(&mut self, if_none_match: bool) {
        self.if_none_match = if_none_match
    }

    /// Returns the "Hop-Limit" option value of this request.
    pub fn hop_limit(&self) -> Option<HopLimit> {
        self.hop_limit
    }

    /// Sets the "Hop-Limit" option value for this request.
    ///
    /// This option is mainly used to prevent proxying loops and specifies the maximum number of
    /// proxies that the request may pass.
    ///
    /// This option is defined in [RFC 8768](https://datatracker.ietf.org/doc/html/rfc8768) and is
    /// not part of the main CoAP spec. Some peers may therefore not support this option.
    pub fn set_hop_limit(&mut self, hop_limit: Option<HopLimit>) {
        self.hop_limit = hop_limit;
    }

    /// Returns the "No-Response" option value for this request.
    pub fn no_response(&self) -> Option<NoResponse> {
        self.no_response
    }

    /// Sets the "No-Response" option value for this request.
    ///
    /// This option indicates that the client performing this request does not wish to receive a
    /// response for this request.
    ///
    /// This option is defined in [RFC 7967](https://datatracker.ietf.org/doc/html/rfc7967) and is
    /// not part of the main CoAP spec. Some peers may therefore not support this option.
    pub fn set_no_response(&mut self, no_response: Option<NoResponse>) {
        self.no_response = no_response;
    }

    /// Returns the "Observe" option value for this request.
    pub fn observe(&self) -> Option<Observe> {
        self.observe
    }

    /// Sets the "Observe" option value for this request.
    ///
    /// This option indicates that the client performing this request wishes to be notified of
    /// changes to the requested resource.
    ///
    /// This option is defined in [RFC 7641](https://datatracker.ietf.org/doc/html/rfc7641) and is
    /// not part of the main CoAP spec. Some peers may therefore not support this option.
    pub fn set_observe(&mut self, observe: Option<Observe>) {
        self.observe = observe;
    }

    /// Returns the CoAP URI that is requested (either a normal request URI or a proxy URI)
    pub fn uri(&self) -> Option<&CoapUri> {
        self.uri.as_ref().map(|v| v.as_uri())
    }

    /// Sets the URI requested in this request.
    ///
    /// The request URI must not have a scheme defined, and path segments, query segments and the
    /// host itself each have to be smaller than 255 characters.
    ///
    /// If the URI has an invalid format, an [OptionValueError] is returned.
    ///
    /// This method overrides any previously set proxy URI.
    pub fn set_uri<U: Into<CoapUri>>(&mut self, uri: Option<U>) -> Result<(), OptionValueError> {
        let uri = uri.map(|v| v.into());
        if let Some(uri) = uri {
            self.uri = Some(CoapRequestUri::new_request_uri(uri)?)
        }
        Ok(())
    }

    /// Sets the proxy URI requested in this request.
    ///
    /// The proxy URI must be an absolute URL with a schema valid for CoAP proxying (CoAP(s) or
    /// HTTP(s)),
    /// The proxy URI must not be longer than 1023 characters.
    ///
    /// If the URI has an invalid format, an [OptionValueError] is returned.
    ///
    /// This method overrides any previously set request URI.
    pub fn set_proxy_uri<U: Into<CoapUri>>(&mut self, uri: Option<U>) -> Result<(), OptionValueError> {
        let uri = uri.map(|v| v.into());
        if let Some(uri) = uri {
            self.uri = Some(CoapRequestUri::new_proxy_uri(uri)?)
        }
        Ok(())
    }

    /// Parses the given [CoapMessage] into a CoapRequest.
    ///
    /// Returns a [MessageConversionError] if the provided PDU cannot be parsed into a request.
    pub fn from_message(mut pdu: CoapMessage) -> Result<CoapRequest, MessageConversionError> {
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
                }
                CoapOption::IfNoneMatch => {
                    if if_none_match {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::IfNoneMatch,
                        ));
                    }
                    if_none_match = true;
                }
                CoapOption::UriHost(value) => {
                    if host.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::UriHost,
                        ));
                    }
                    host = Some(value.clone());
                }
                CoapOption::UriPort(value) => {
                    if port.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::UriPort,
                        ));
                    }
                    port = Some(*value);
                }
                CoapOption::UriPath(value) => {
                    if path.is_none() {
                        path = Some(Vec::new());
                    }
                    path.as_mut().unwrap().push(value.clone());
                }
                CoapOption::UriQuery(value) => {
                    if query.is_none() {
                        query = Some(Vec::new());
                    }
                    query.as_mut().unwrap().push(value.clone());
                }
                CoapOption::LocationPath(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::LocationPath,
                    ))
                }
                CoapOption::LocationQuery(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::LocationQuery,
                    ))
                }
                CoapOption::ProxyUri(uri) => {
                    if proxy_uri.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ProxyUri,
                        ));
                    }
                    proxy_uri = Some(uri.clone())
                }
                CoapOption::ProxyScheme(scheme) => {
                    if proxy_scheme.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ProxyScheme,
                        ));
                    }
                    proxy_scheme = Some(CoapUriScheme::from_str(scheme)?)
                }
                CoapOption::ContentFormat(cformat) => {
                    if content_format.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ContentFormat,
                        ));
                    }
                    content_format = Some(*cformat)
                }
                CoapOption::Accept(value) => {
                    if accept.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Accept,
                        ));
                    }
                    accept = Some(*value);
                }
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::Size1(_) => {}
                CoapOption::Size2(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Size2,
                    ))
                }
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::Block1(_) => {}
                CoapOption::Block2(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Block2,
                    ))
                }
                CoapOption::HopLimit(value) => {
                    if hop_limit.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::HopLimit,
                        ));
                    }
                    hop_limit = Some(*value);
                }
                CoapOption::NoResponse(value) => {
                    if no_response.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::NoResponse,
                        ));
                    }
                    no_response = Some(*value);
                }
                CoapOption::ETag(value) => {
                    if etag.is_none() {
                        etag = Some(Vec::new());
                    }
                    etag.as_mut().unwrap().push(value.clone());
                }
                CoapOption::MaxAge(_value) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::MaxAge,
                    ));
                }
                CoapOption::Observe(value) => {
                    if observe.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::MaxAge,
                        ));
                    }
                    observe = Some(*value);
                }
                // TODO maybe we can save some copies here if we use into_iter for the options instead.
                CoapOption::Other(n, v) => {
                    additional_opts.push(CoapOption::Other(*n, v.clone()));
                }
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

    /// Converts this request into a [CoapMessage] that can be sent over a [CoapSession](crate::session::CoapSession).
    pub fn into_message(mut self) -> CoapMessage {
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
        self.pdu
    }
}

impl CoapMessageCommon for CoapRequest {
    /// Sets the message code of this request.
    ///
    /// # Panics
    /// Panics if the provided message code is not a request code.
    fn set_code(&mut self, code: CoapMessageCode) {
        match code {
            CoapMessageCode::Request(req) => self.pdu.set_code(CoapMessageCode::Request(req)),
            CoapMessageCode::Response(_) | CoapMessageCode::Empty => {
                panic!("attempted to set message code of request to value that is not a request code")
            }
        }
    }

    fn as_message(&self) -> &CoapMessage {
        &self.pdu
    }

    fn as_message_mut(&mut self) -> &mut CoapMessage {
        &mut self.pdu
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CoapResponse {
    pdu: CoapMessage,
    content_format: Option<ContentFormat>,
    max_age: Option<MaxAge>,
    etag: Option<ETag>,
    location: Option<CoapResponseLocation>,
    observe: Option<Observe>,
}

impl CoapResponse {
    /// Creates a new CoAP response with the given message type and code.
    ///
    /// Returns an error if the given message type is not allowed for CoAP responses (the allowed
    /// message types are [CoapMessageType::Con] and [CoapMessageType::Non] and [CoapMessageType::Ack]).
    pub fn new(type_: CoapMessageType, code: CoapResponseCode) -> Result<CoapResponse, MessageTypeError> {
        match type_ {
            CoapMessageType::Con | CoapMessageType::Non | CoapMessageType::Ack => {}
            v => return Err(MessageTypeError::InvalidForMessageCode(v)),
        }
        Ok(CoapResponse {
            pdu: CoapMessage::new(type_, code.into()),
            content_format: None,
            max_age: None,
            etag: None,
            location: None,
            observe: None,
        })
    }

    /// Returns the "Max-Age" option value for this response.
    pub fn max_age(&self) -> Option<MaxAge> {
        self.max_age
    }

    /// Sets the "Max-Age" option value for this response.
    ///
    /// This option indicates the maximum time a response may be cached (in seconds).
    ///
    /// See [RFC 7252, Section 5.10.5](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.5)
    /// for more information.
    pub fn set_max_age(&mut self, max_age: Option<MaxAge>) {
        self.max_age = max_age
    }

    /// Returns the "Content-Format" option value for this request.
    pub fn content_format(&self) -> Option<ContentFormat> {
        self.content_format
    }

    /// Sets the "Content-Format" option value for this response.
    ///
    /// This option indicates the content format of the body of this message.
    ///
    /// See [RFC 7252, Section 5.10.3](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.3)
    /// for more information.
    pub fn set_content_format(&mut self, content_format: Option<ContentFormat>) {
        self.content_format = content_format;
    }

    /// Returns the "ETag" option value for this request.
    pub fn etag(&self) -> Option<&ETag> {
        self.etag.as_ref()
    }

    /// Sets the "ETag" option value for this response.
    ///
    /// This option can be used by clients to request a specific representation of the requested
    /// resource.
    ///
    /// The server may send an ETag value alongside a response, which the client can then set here
    /// to request the given representation.
    ///
    /// See [RFC 7252, Section 5.10.6](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.6)
    /// for more information.
    pub fn set_etag(&mut self, etag: Option<ETag>) {
        self.etag = etag
    }

    /// Returns the "Observe" option value for this request.
    pub fn observe(&self) -> Option<Observe> {
        self.observe
    }

    /// Sets the "Observe" option value for this response.
    ///
    /// This option indicates that this response is a notification for a previously requested
    /// resource observation.
    ///
    /// This option is defined in [RFC 7641](https://datatracker.ietf.org/doc/html/rfc7641) and is
    /// not part of the main CoAP spec. Some peers may therefore not support this option.
    pub fn set_observe(&mut self, observe: Option<Observe>) {
        self.observe = observe;
    }

    /// Returns the "Location" option value for this request.
    pub fn location(&self) -> Option<&CoapResponseLocation> {
        self.location.as_ref()
    }

    /// Sets the "Location-Path" and "Location-Query" option values for this response.
    ///
    /// These options indicate a relative URI for a resource created in response of a POST or PUT
    /// request.
    ///
    /// The supplied URI must be relative to the requested path and must therefore also not contain
    /// a scheme, host or port. Also, each path component must be smaller than 255 characters.
    ///
    /// If an invalid URI is provided, an [OptionValueError] is returned
    ///
    /// See [RFC 7252, Section 5.10.7](https://datatracker.ietf.org/doc/html/rfc7252#section-5.10.7)
    /// for more information.
    pub fn set_location<U: Into<CoapUri>>(&mut self, uri: Option<U>) -> Result<(), OptionValueError> {
        let uri = uri.map(|v| v.into());
        if let Some(uri) = uri {
            self.location = Some(CoapResponseLocation::new_response_location(uri)?)
        }
        Ok(())
    }

    /// Converts this request into a [CoapMessage] that can be sent over a [CoapSession](crate::session::CoapSession).
    pub fn into_message(mut self) -> CoapMessage {
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
        self.pdu
    }

    /// Parses the given [CoapMessage] into a CoapResponse.
    ///
    /// Returns a [MessageConversionError] if the provided PDU cannot be parsed into a response.
    pub fn from_message(pdu: CoapMessage) -> Result<CoapResponse, MessageConversionError> {
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
                }
                CoapOption::LocationQuery(value) => {
                    if location_query.is_none() {
                        location_query = Some(Vec::new());
                    }
                    location_query.as_mut().unwrap().push(value.clone());
                }
                CoapOption::ETag(value) => {
                    if etag.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ETag,
                        ));
                    }
                    etag = Some(value.clone());
                }
                CoapOption::MaxAge(value) => {
                    if max_age.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::MaxAge,
                        ));
                    }
                    max_age = Some(*value);
                }
                CoapOption::Observe(value) => {
                    if observe.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Observe,
                        ));
                    }
                    observe = Some(*value)
                }
                CoapOption::IfMatch(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::IfMatch,
                    ));
                }
                CoapOption::IfNoneMatch => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::IfNoneMatch,
                    ));
                }
                CoapOption::UriHost(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriHost,
                    ));
                }
                CoapOption::UriPort(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriPort,
                    ));
                }
                CoapOption::UriPath(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriPath,
                    ));
                }
                CoapOption::UriQuery(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::UriQuery,
                    ));
                }
                CoapOption::ProxyUri(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::ProxyUri,
                    ));
                }
                CoapOption::ProxyScheme(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::ProxyScheme,
                    ));
                }
                CoapOption::ContentFormat(value) => {
                    if content_format.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::ContentFormat,
                        ));
                    }
                    content_format = Some(*value)
                }
                CoapOption::Accept(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Accept,
                    ));
                }
                CoapOption::Size1(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Size1,
                    ));
                }
                CoapOption::Size2(_) => {}
                CoapOption::Block1(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Block1,
                    ));
                }
                CoapOption::Block2(_) => {}
                CoapOption::HopLimit(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::HopLimit,
                    ));
                }
                CoapOption::NoResponse(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::NoResponse,
                    ));
                }
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
    fn set_code(&mut self, code: CoapMessageCode) {
        match code {
            CoapMessageCode::Response(req) => self.pdu.set_code(CoapMessageCode::Response(req)),
            CoapMessageCode::Request(_) | CoapMessageCode::Empty => {
                panic!("attempted to set message code of response to value that is not a response code")
            }
        }
    }

    fn as_message(&self) -> &CoapMessage {
        &self.pdu
    }

    fn as_message_mut(&mut self) -> &mut CoapMessage {
        &mut self.pdu
    }
}

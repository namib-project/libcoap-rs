// SPDX-License-Identifier: BSD-2-Clause
/*
 * request.rs - Types wrapping messages into requests.
 * This file is part of the libcoap-rs crate, see the README and LICENSE files for
 * more information and terms of use.
 * Copyright © 2021-2023 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::str::FromStr;

use crate::{
    error::{MessageConversionError, MessageTypeError, OptionValueError},
    message::{construct_path_string, construct_query_string, CoapMessage, CoapMessageCommon, CoapOption},
    protocol::{
        CoapMatch, CoapMessageCode, CoapMessageType, CoapOptionType, CoapRequestCode, ContentFormat, ETag, HopLimit,
        NoResponse, Observe,
    },
    session::CoapSessionCommon,
    types::{CoapUri, CoapUriScheme},
};

/// Representation of a CoAP request message.
///
/// This struct wraps around the more direct [CoapMessage] and allows easier definition of typical
/// options used in requests.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoapRequest {
    pdu: CoapMessage,
    uri: CoapUri,
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
    /// allowed message types are [CoapMessageType::Con] and [CoapMessageType::Non]) or the request
    /// URI is malformed.
    pub fn new(type_: CoapMessageType, code: CoapRequestCode, uri: CoapUri) -> Result<CoapRequest, MessageTypeError> {
        match type_ {
            CoapMessageType::Con | CoapMessageType::Non => {},
            v => return Err(MessageTypeError::InvalidForMessageCode(v)),
        }
        Ok(CoapRequest {
            pdu: CoapMessage::new(type_, code.into()),
            uri,
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

    /// Returns the CoAP URI that is requested.
    pub fn uri(&self) -> &CoapUri {
        &self.uri
    }

    /// Parses the given [CoapMessage] into a CoapRequest.
    ///
    /// Returns a [MessageConversionError] if the provided PDU cannot be parsed into a request.
    pub fn from_message<'a>(
        mut pdu: CoapMessage,
        session: &impl CoapSessionCommon<'a>,
    ) -> Result<CoapRequest, MessageConversionError> {
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
                    host = Some(value.clone().into_bytes());
                },
                CoapOption::UriPort(value) => {
                    if port.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::UriPort,
                        ));
                    }
                    port = Some(*value);
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
                    ));
                },
                CoapOption::LocationQuery(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::LocationQuery,
                    ));
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
                    content_format = Some(*cformat)
                },
                CoapOption::Accept(value) => {
                    if accept.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Accept,
                        ));
                    }
                    accept = Some(*value);
                },
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::Size1(_) => {},
                CoapOption::Size2(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Size2,
                    ));
                },
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::Block1(_) => {},
                CoapOption::Block2(_) => {
                    return Err(MessageConversionError::InvalidOptionForMessageType(
                        CoapOptionType::Block2,
                    ));
                },
                // libcoap handles blockwise transfer for us (for now).
                CoapOption::QBlock1(_) => {},
                CoapOption::QBlock2(_) => {},
                CoapOption::HopLimit(value) => {
                    if hop_limit.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::HopLimit,
                        ));
                    }
                    hop_limit = Some(*value);
                },
                CoapOption::NoResponse(value) => {
                    if no_response.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::NoResponse,
                        ));
                    }
                    no_response = Some(*value);
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
                    observe = Some(*value);
                },
                // Handling of echo options is automatically done by libcoap (see man coap_send)
                CoapOption::Echo(_) => {},
                // Handling of request tag options is automatically done by libcoap (see man
                // coap_send)
                CoapOption::RTag(_) => {},
                // OSCORE is currently not supported, and even if it should probably be handled by
                // libcoap, so I'm unsure whether we have to expose this.
                CoapOption::Oscore(_v) => {},
                // TODO maybe we can save some copies here if we use into_iter for the options instead.
                CoapOption::Other(n, v) => {
                    additional_opts.push(CoapOption::Other(*n, v.clone()));
                },
            }
        }
        pdu.clear_options();
        for opt in additional_opts {
            pdu.add_option(opt);
        }
        if proxy_scheme.is_some() && proxy_uri.is_some() {
            return Err(MessageConversionError::InvalidOptionCombination(
                CoapOptionType::ProxyScheme,
                CoapOptionType::ProxyUri,
            ));
        }
        let uri = if let Some(v) = proxy_uri {
            CoapUri::try_from_str_proxy(v.as_str())
        } else {
            let path_str = path.map(construct_path_string);
            let query_str = query.map(construct_query_string);

            match proxy_scheme {
                Some(scheme) => CoapUri::new_proxy(
                    scheme,
                    host.as_deref().unwrap_or(&[]),
                    port.unwrap_or(0),
                    path_str.as_ref().map(|v| v.as_bytes()),
                    query_str.as_ref().map(|v| v.as_bytes()),
                ),
                None => CoapUri::new(
                    session.proto().into(),
                    host.as_deref().unwrap_or(&[]),
                    port.unwrap_or(0),
                    path_str.as_ref().map(|v| v.as_bytes()),
                    query_str.as_ref().map(|v| v.as_bytes()),
                ),
            }
        }
        .map_err(|e| MessageConversionError::InvalidOptionValue(None, OptionValueError::UriParsing(e)))?;

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
        if self.uri.is_proxy() {
            self.pdu.add_option(CoapOption::ProxyScheme(
                self.uri.scheme().expect("Parsed CoAP URI must have scheme").to_string(),
            ))
        }
        self.uri.into_options().into_iter().for_each(|v| self.pdu.add_option(v));
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
    fn set_code<C: Into<CoapMessageCode>>(&mut self, code: C) {
        match code.into() {
            CoapMessageCode::Request(req) => self.pdu.set_code(CoapMessageCode::Request(req)),
            CoapMessageCode::Response(_) | CoapMessageCode::Empty => {
                panic!("attempted to set message code of request to value that is not a request code")
            },
        }
    }

    fn as_message(&self) -> &CoapMessage {
        &self.pdu
    }

    fn as_message_mut(&mut self) -> &mut CoapMessage {
        &mut self.pdu
    }
}

// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * message/response.rs - Types wrapping messages into responses.
 */

use crate::{
    error::{MessageConversionError, MessageTypeError, OptionValueError},
    message::{construct_path_string, construct_query_string, CoapMessage, CoapMessageCommon, CoapOption},
    protocol::{
        CoapMessageCode, CoapMessageType, CoapOptionType, CoapResponseCode, ContentFormat, ETag, Echo, MaxAge, Observe,
    },
    types::CoapUri,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CoapResponse {
    pdu: CoapMessage,
    content_format: Option<ContentFormat>,
    max_age: Option<MaxAge>,
    etag: Option<ETag>,
    echo: Option<Echo>,
    location: Option<CoapUri>,
    observe: Option<Observe>,
}

impl CoapResponse {
    /// Creates a new CoAP response with the given message type and code.
    ///
    /// Returns an error if the given message type is not allowed for CoAP responses (the allowed
    /// message types are [CoapMessageType::Con] and [CoapMessageType::Non] and [CoapMessageType::Ack]).
    pub fn new(type_: CoapMessageType, code: CoapResponseCode) -> Result<CoapResponse, MessageTypeError> {
        match type_ {
            CoapMessageType::Con | CoapMessageType::Non | CoapMessageType::Ack => {},
            v => return Err(MessageTypeError::InvalidForMessageCode(v)),
        }
        Ok(CoapResponse {
            pdu: CoapMessage::new(type_, code.into()),
            content_format: None,
            max_age: None,
            etag: None,
            echo: None,
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

    /// Returns the "Echo" option value for this request.
    pub fn echo(&self) -> Option<&Echo> {
        self.echo.as_ref()
    }

    /// Sets the "Echo" option value for this response.
    ///
    /// This option can be used by servers to ensure that a request is recent.
    ///
    /// The client should include the provided option value in its next request.
    ///
    /// As handling echo options on the client side is done automatically by libcoap, this option
    /// is not accessible in [CoapRequest], see `man coap_send` for more information.
    ///
    /// See [RFC 9175, Section 2.2](https://datatracker.ietf.org/doc/html/rfc9175#section-2.2)
    /// for more information.
    pub fn set_echo(&mut self, echo: Option<Echo>) {
        self.echo = echo
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
    pub fn location(&self) -> Option<&CoapUri> {
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
        let uri = uri.map(Into::into);
        if let Some(uri) = uri {
            self.location = Some(uri)
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
        let mut echo = None;
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
                    max_age = Some(*value);
                },
                CoapOption::Observe(value) => {
                    if observe.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Observe,
                        ));
                    }
                    observe = Some(*value)
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
                    content_format = Some(*value)
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
                CoapOption::QBlock1(_) => {},
                CoapOption::QBlock2(_) => {},
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

                // Handling of echo options is automatically done by libcoap (see man coap_send)
                CoapOption::Echo(v) => {
                    if echo.is_some() {
                        return Err(MessageConversionError::NonRepeatableOptionRepeated(
                            CoapOptionType::Echo,
                        ));
                    }
                    echo = Some(v.clone());
                },
                // Handling of request tag options is automatically done by libcoap (see man
                // coap_send)
                CoapOption::RTag(_) => {},
                // OSCORE is currently not supported, and even if it should probably be handled by
                // libcoap, so I'm unsure whether we have to expose this.
                CoapOption::Oscore(_) => {},
                CoapOption::Other(n, v) => additional_opts.push(CoapOption::Other(*n, v.clone())),
            }
        }
        let location = if location_path.is_some() || location_query.is_some() {
            let path_str = location_path.map(construct_path_string);
            let query_str = location_query.map(construct_query_string);
            Some(CoapUri::new_relative(
                path_str.as_ref().map(|v| v.as_bytes()),
                query_str.as_ref().map(|v| v.as_bytes()),
            )?)
        } else {
            None
        };
        Ok(CoapResponse {
            pdu,
            content_format,
            max_age,
            etag,
            echo,
            location,
            observe,
        })
    }
}

impl CoapMessageCommon for CoapResponse {
    /// Sets the message code of this response.
    ///
    /// # Panics
    ///
    /// Panics if the provided message code is not a response code.
    fn set_code<C: Into<CoapMessageCode>>(&mut self, code: C) {
        match code.into() {
            CoapMessageCode::Response(req) => self.pdu.set_code(CoapMessageCode::Response(req)),
            CoapMessageCode::Request(_) | CoapMessageCode::Empty => {
                panic!("attempted to set message code of response to value that is not a response code")
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

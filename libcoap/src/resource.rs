// SPDX-License-Identifier: BSD-2-Clause
/*
 * resource.rs - Types relating to CoAP resource management.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */
use std::{
    any::Any,
    cell::RefCell,
    ffi::c_void,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    mem::ManuallyDrop,
    ops::Deref,
    rc::{Rc, Weak},
};

use libcoap_sys::{
    coap_delete_resource, coap_new_str_const, coap_pdu_t, coap_pdu_type_t::COAP_MESSAGE_RST,
    coap_register_request_handler, coap_resource_get_uri_path, coap_resource_get_userdata, coap_resource_init,
    coap_resource_set_userdata, coap_resource_t, coap_send_rst, coap_session_t, coap_string_t,
};

use crate::message::CoapMessageCommon;
use crate::protocol::CoapMessageCode;
use crate::protocol::CoapMessageType;
use crate::session::CoapSessionCommon;

use crate::{
    error::MessageConversionError,
    message::CoapMessage,
    protocol::CoapRequestCode,
    request::{CoapRequest, CoapResponse},
    session::CoapServerSession,
    types::CoapAppDataRef,
};

// Trait aliases are experimental
//trait CoapMethodHandlerFn<D> = FnMut(&D, &mut CoapSession, &CoapRequestMessage, &mut CoapResponseMessage);

// Some macro wizardry to statically wrap request handlers.
/// Create a CoapRequestHandler using the provided function.
///
/// This macro cannot be used if the intended handler function does not have a 'static lifetime,
/// i.e. if the handler function is a closure.
/// In these cases, use [CoapRequestHandler::new()] instead.
#[macro_export]
macro_rules! resource_handler {
    ($f:ident, $t:path) => {{
        #[allow(clippy::unnecessary_mut_passed)] // We don't know whether the function needs a mutable reference or not.
        unsafe extern "C" fn _coap_method_handler_wrapper<D: Any + ?Sized + Debug>(
            resource: *mut coap_resource_t,
            session: *mut coap_session_t,
            incoming_pdu: *const coap_pdu_t,
            query: *const coap_string_t,
            response_pdu: *mut coap_pdu_t,
        ) {
            let handler_data =
                prepare_resource_handler_data::<$t>(resource, session, incoming_pdu, query, response_pdu);
            if let Ok((user_data, mut resource, mut session, incoming_pdu, outgoing_pdu)) = handler_data {
                ($f::<D>)(
                    user_data.as_ref(),
                    &mut resource,
                    &mut session.borrow_mut(),
                    &incoming_pdu,
                    outgoing_pdu,
                )
            }
        }
        unsafe { CoapRequestHandler::<$t>::from_raw_handler(_coap_method_handler_wrapper::<$t>) }
    }};
}

/// Converts the raw parameters provided to a request handler into the appropriate wrapped types.
///
/// If an error occurs while parsing the resource data, this function will send an RST message to the
/// client and return a [MessageConversionError].
///
/// This function is not intended for public use, the only reason it is public is that the
/// [resource_handler!] macro requires this function.
///
/// # Safety
/// The provided pointers must all be valid and point to the appropriate data structures.
#[inline]
pub unsafe fn prepare_resource_handler_data<D: Any + ?Sized + Debug>(
    raw_resource: *mut coap_resource_t,
    raw_session: *mut coap_session_t,
    raw_incoming_pdu: *const coap_pdu_t,
    _raw_query: *const coap_string_t,
    raw_response_pdu: *mut coap_pdu_t,
) -> Result<
    (
        Rc<D>,
        CoapResource<D>,
        CoapAppDataRef<CoapServerSession>,
        CoapRequest,
        CoapResponse,
    ),
    MessageConversionError,
> {
    let resource_tmp = Weak::from_raw(coap_resource_get_userdata(raw_resource) as *const RefCell<CoapResourceInner<D>>);
    let resource = CoapResource::from(
        Weak::clone(&resource_tmp)
            .upgrade()
            .expect("CoAP resource method handler called after resource was destroyed"),
    );
    let session = CoapServerSession::restore_from_raw(raw_session);
    coap_resource_set_userdata(raw_resource, Weak::into_raw(resource_tmp) as *mut c_void);
    let request = CoapMessage::from_raw_pdu(raw_incoming_pdu).and_then(CoapRequest::from_message);
    let response = CoapMessage::from_raw_pdu(raw_response_pdu).and_then(CoapResponse::from_message);
    match (request, response) {
        (Ok(request), Ok(response)) => Ok((resource.user_data(), resource, session, request, response)),
        (v1, v2) => {
            coap_send_rst(raw_session, raw_incoming_pdu, COAP_MESSAGE_RST);
            Err(v1.and(v2).err().unwrap())
        },
    }
}

/// Trait with functions relating to [CoapResource]s with an unknown data type.
pub trait UntypedCoapResource: Any + Debug {
    /// Returns the uri_path this resource responds to.
    fn uri_path(&self) -> &str;
    /// Provides a reference to this resource as an [Any] trait object.
    ///
    /// You can use the resulting [Any] reference to downcast the resource to its appropriate
    /// concrete type (if you wish to e.g. change the application data).
    ///
    /// If you use unstable Rust, you can use trait upcasting instead (`[value] as Any`).
    fn as_any(&self) -> &dyn Any;
    /// Attempts to regain exclusive ownership of the inner resource in order to drop it.
    ///
    /// This function is used by the [CoapContext](crate::context::CoapContext) on cleanup to
    /// reclaim resources before dropping the context itself. *You should not use this function*.
    ///
    /// # Panics
    /// Panics if the inner resource instance associated with this resource cannot be exclusively
    /// dropped, i.e. because the underlying [Rc] is used elsewhere.
    fn drop_inner_exclusive(self);
    /// Returns the raw resource associated with this CoapResource.
    ///
    /// # Safety
    /// You must not do anything with this resource that could interfere with this instance.
    /// Most notably, you must not...
    /// - ...free the returned value using [coap_delete_resource](libcoap_sys::coap_delete_resource)
    /// - ...associate the raw resource with a CoAP context, because if the context is dropped, so
    ///   will the resource.
    /// - ...modify the application-specific data.
    unsafe fn raw_resource(&self) -> *mut coap_resource_t;
}

/// Representation of a CoapResource that can be requested from a server.
#[derive(Debug)]
pub struct CoapResource<D: Any + ?Sized + Debug> {
    inner: ManuallyDrop<Rc<RefCell<CoapResourceInner<D>>>>,
}

/// Container for resource handlers for various CoAP methods.
#[derive(Debug)]
struct CoapResourceHandlers<D: Any + ?Sized + Debug> {
    get: Option<CoapRequestHandler<D>>,
    put: Option<CoapRequestHandler<D>>,
    delete: Option<CoapRequestHandler<D>>,
    post: Option<CoapRequestHandler<D>>,
    fetch: Option<CoapRequestHandler<D>>,
    ipatch: Option<CoapRequestHandler<D>>,
    patch: Option<CoapRequestHandler<D>>,
}

impl<D: Any + ?Sized + Debug> Default for CoapResourceHandlers<D> {
    fn default() -> Self {
        CoapResourceHandlers {
            get: None,
            put: None,
            delete: None,
            post: None,
            fetch: None,
            ipatch: None,
            patch: None,
        }
    }
}

impl<D: Any + ?Sized + Debug> CoapResourceHandlers<D> {
    #[inline]
    fn handler(&self, code: CoapRequestCode) -> Option<&CoapRequestHandler<D>> {
        match code {
            CoapRequestCode::Get => self.get.as_ref(),
            CoapRequestCode::Put => self.put.as_ref(),
            CoapRequestCode::Delete => self.delete.as_ref(),
            CoapRequestCode::Post => self.post.as_ref(),
            CoapRequestCode::Fetch => self.fetch.as_ref(),
            CoapRequestCode::IPatch => self.ipatch.as_ref(),
            CoapRequestCode::Patch => self.patch.as_ref(),
        }
    }

    #[inline]
    fn handler_mut(&mut self, code: CoapRequestCode) -> Option<&mut CoapRequestHandler<D>> {
        match code {
            CoapRequestCode::Get => self.get.as_mut(),
            CoapRequestCode::Put => self.put.as_mut(),
            CoapRequestCode::Delete => self.delete.as_mut(),
            CoapRequestCode::Post => self.post.as_mut(),
            CoapRequestCode::Fetch => self.fetch.as_mut(),
            CoapRequestCode::IPatch => self.ipatch.as_mut(),
            CoapRequestCode::Patch => self.patch.as_mut(),
        }
    }

    #[inline]
    fn handler_ref(&self, code: CoapRequestCode) -> &Option<CoapRequestHandler<D>> {
        match code {
            CoapRequestCode::Get => &self.get,
            CoapRequestCode::Put => &self.put,
            CoapRequestCode::Delete => &self.delete,
            CoapRequestCode::Post => &self.post,
            CoapRequestCode::Fetch => &self.fetch,
            CoapRequestCode::IPatch => &self.ipatch,
            CoapRequestCode::Patch => &self.patch,
        }
    }

    #[inline]
    fn handler_ref_mut(&mut self, code: CoapRequestCode) -> &mut Option<CoapRequestHandler<D>> {
        match code {
            CoapRequestCode::Get => &mut self.get,
            CoapRequestCode::Put => &mut self.put,
            CoapRequestCode::Delete => &mut self.delete,
            CoapRequestCode::Post => &mut self.post,
            CoapRequestCode::Fetch => &mut self.fetch,
            CoapRequestCode::IPatch => &mut self.ipatch,
            CoapRequestCode::Patch => &mut self.patch,
        }
    }
}

/// Inner part of a [CoapResource], which is referenced inside the raw resource and might be
/// referenced multiple times, e.g. outside and inside of a resource handler.
#[derive(Debug)]
pub(crate) struct CoapResourceInner<D: Any + ?Sized + Debug> {
    raw_resource: *mut coap_resource_t,
    user_data: Rc<D>,
    handlers: CoapResourceHandlers<D>,
}

impl<D: Any + ?Sized + Debug> CoapResource<D> {
    /// Creates a new CoapResource for the given `uri_path`.
    ///
    /// Handlers that are associated with this resource have to be able to take a reference to the
    /// provided `user_data` value as their first value.
    pub fn new<C: Into<Rc<D>>>(uri_path: &str, user_data: C) -> CoapResource<D> {
        let inner = unsafe {
            let uri_path = coap_new_str_const(uri_path.as_ptr(), uri_path.len());
            let raw_resource = coap_resource_init(uri_path, 0);
            let inner = Rc::new(RefCell::new(CoapResourceInner {
                raw_resource,
                user_data: user_data.into(),
                handlers: CoapResourceHandlers::default(),
            }));
            coap_resource_set_userdata(raw_resource, Weak::into_raw(Rc::downgrade(&inner)) as *mut c_void);
            inner
        };
        Self::from(inner)
    }

    /// Returns the user data associated with this resource.
    pub fn user_data(&self) -> Rc<D> {
        RefCell::borrow(self.inner.as_ref()).user_data.clone()
    }

    /// Restores a resource from its raw [coap_resource_t](libcoap_sys::coap_resource_t).
    ///
    /// # Safety
    /// The supplied pointer must point to a valid [coap_resource_t](libcoap_sys::coap_resource_t)
    /// instance that has a `Rc<RefCell<CoapResourceInner<D>>>` as its user data.
    pub unsafe fn restore_from_raw(raw_resource: *mut coap_resource_t) -> CoapResource<D> {
        let resource_tmp =
            Weak::from_raw(coap_resource_get_userdata(raw_resource) as *const RefCell<CoapResourceInner<D>>);
        let resource = CoapResource::from(
            Weak::clone(&resource_tmp)
                .upgrade()
                .expect("attempted to restore dropped resource from raw resource"),
        );
        coap_resource_set_userdata(raw_resource, Weak::into_raw(resource_tmp) as *mut c_void);
        resource
    }

    /// Sets the handler function for a given method code.
    pub fn set_method_handler<H: Into<CoapRequestHandler<D>>>(&self, code: CoapRequestCode, handler: Option<H>) {
        let mut inner = RefCell::borrow_mut(self.inner.as_ref());
        *inner.handlers.handler_ref_mut(code) = handler.map(|v| v.into());
        unsafe {
            coap_register_request_handler(
                inner.raw_resource,
                code.to_raw_request(),
                inner.handlers.handler(code).map(|h| h.raw_handler),
            );
        }
    }

    fn call_dynamic_handler(
        &self,
        data: &D,
        session: &mut CoapServerSession,
        req_message: &CoapRequest,
        mut rsp_message: CoapResponse,
    ) {
        let mut inner = RefCell::borrow_mut(self.inner.as_ref());
        let req_code = match req_message.code() {
            CoapMessageCode::Request(req_code) => req_code,
            _ => {
                rsp_message.set_type_(CoapMessageType::Rst);
                // TODO some better error handling
                session.send(rsp_message).expect("error while sending RST packet");
                return;
            },
        };
        (inner
            .handlers
            .handler_mut(req_code)
            .expect("attempted to call dynamic handler for method that has no handler set")
            .dynamic_handler_function
            .as_mut()
            .expect("attempted to call dynamic handler for method that has no dynamic handler set"))(
            data,
            self,
            session,
            req_message,
            rsp_message,
        );
    }
}

impl<D: Any + ?Sized + Debug> UntypedCoapResource for CoapResource<D> {
    fn uri_path(&self) -> &str {
        unsafe {
            let raw_path = coap_resource_get_uri_path(RefCell::borrow(self.inner.as_ref()).raw_resource);
            return std::str::from_utf8_unchecked(std::slice::from_raw_parts((*raw_path).s, (*raw_path).length));
        }
    }

    fn as_any(&self) -> &dyn Any {
        self as &(dyn Any)
    }

    fn drop_inner_exclusive(mut self) {
        let inner_container = Rc::clone(self.inner.deref());
        // SAFETY: We are dropping ourself in here anyways.
        unsafe {
            ManuallyDrop::drop(&mut self.inner);
        }
        if Rc::try_unwrap(inner_container).is_err() {
            panic!("attempted to drop resource exclusively while not having exclusive access");
        }
    }

    unsafe fn raw_resource(&self) -> *mut coap_resource_t {
        RefCell::borrow_mut(&self.inner).raw_resource
    }
}

impl<D: Any + ?Sized + Debug> From<Rc<RefCell<CoapResourceInner<D>>>> for CoapResource<D> {
    fn from(raw_cell: Rc<RefCell<CoapResourceInner<D>>>) -> Self {
        CoapResource {
            inner: ManuallyDrop::new(raw_cell),
        }
    }
}

impl<D: Any + ?Sized + Debug> Drop for CoapResourceInner<D> {
    fn drop(&mut self) {
        // SAFETY: We set the user data on creation of the inner resource, so it cannot be invalid.
        std::mem::drop(unsafe {
            Weak::from_raw(coap_resource_get_userdata(self.raw_resource) as *const RefCell<CoapResourceInner<D>>)
        });
        // SAFETY: First argument is ignored, second argument is guaranteed to exist while the inner
        // resource exists.
        unsafe { coap_delete_resource(std::ptr::null_mut(), self.raw_resource) };
    }
}

pub struct CoapRequestHandler<D: Any + ?Sized + Debug> {
    raw_handler: unsafe extern "C" fn(
        resource: *mut coap_resource_t,
        session: *mut coap_session_t,
        incoming_pdu: *const coap_pdu_t,
        query: *const coap_string_t,
        response_pdu: *mut coap_pdu_t,
    ),
    dynamic_handler_function:
        Option<Box<dyn FnMut(&D, &CoapResource<D>, &mut CoapServerSession, &CoapRequest, CoapResponse)>>,
    __handler_data_type: PhantomData<D>,
}

impl<D: 'static + ?Sized + Debug> CoapRequestHandler<D> {
    /// Creates a new CoapResourceHandler with the given function as the handler function to call.
    pub fn new<F: 'static + FnMut(&D, &CoapResource<D>, &mut CoapServerSession, &CoapRequest, CoapResponse)>(
        handler: F,
    ) -> CoapRequestHandler<D> {
        let mut wrapped_handler = resource_handler!(coap_resource_handler_dynamic_wrapper, D);
        wrapped_handler.dynamic_handler_function = Some(Box::new(handler));
        wrapped_handler
    }

    /// Creates a new request handler using the given raw handler function.
    ///
    /// The handler function provided here is called directly by libcoap.
    ///
    /// # Safety
    /// The handler function must not modify the user data value inside of the provided raw resource
    /// in a way that would break normal handler functions. Also, neither the resource nor the
    /// session may be freed by calling `coap_delete_resource` or `coap_session_release`.
    pub unsafe fn from_raw_handler(
        raw_handler: unsafe extern "C" fn(
            resource: *mut coap_resource_t,
            session: *mut coap_session_t,
            incoming_pdu: *const coap_pdu_t,
            query: *const coap_string_t,
            response_pdu: *mut coap_pdu_t,
        ),
    ) -> CoapRequestHandler<D> {
        let handler_fn: Option<
            Box<dyn for<'a> FnMut(&'a D, &CoapResource<D>, &mut CoapServerSession, &CoapRequest, CoapResponse)>,
        > = None;
        CoapRequestHandler {
            raw_handler,
            dynamic_handler_function: handler_fn,
            __handler_data_type: PhantomData,
        }
    }
}

impl<
        D: 'static + ?Sized + Debug,
        F: 'static + FnMut(&D, &CoapResource<D>, &mut CoapServerSession, &CoapRequest, CoapResponse),
    > From<F> for CoapRequestHandler<D>
{
    fn from(f: F) -> Self {
        CoapRequestHandler::new(f)
    }
}

impl<D: 'static + ?Sized + Debug> Debug for CoapRequestHandler<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoapRequestHandler").finish()
    }
}

fn coap_resource_handler_dynamic_wrapper<D: Any + ?Sized + Debug>(
    data: &D,
    resource: &CoapResource<D>,
    session: &mut CoapServerSession,
    req_message: &CoapRequest,
    rsp_message: CoapResponse,
) {
    resource.call_dynamic_handler(data, session, req_message, rsp_message);
}

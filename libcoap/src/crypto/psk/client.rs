use crate::crypto::psk::key::PskKey;
use crate::error::SessionCreationError;
use crate::session::CoapClientSession;
use crate::types::CoapAddress;
use crate::CoapContext;
use libcoap_sys::{
    coap_dtls_cpsk_info_t, coap_dtls_cpsk_t, coap_new_client_session_psk2, coap_proto_t, coap_session_t,
    coap_str_const_t, COAP_DTLS_CPSK_SETUP_VERSION,
};
use std::cell::RefCell;
use std::ffi::{c_char, c_void, CString, NulError};
use std::fmt::Debug;
use std::ptr::NonNull;
use std::rc::{Rc, Weak};

#[derive(Debug)]
pub struct ClientPskContextBuilder<'a> {
    ctx: ClientPskContextInner<'a>,
}

impl<'a> ClientPskContextBuilder<'a> {
    pub fn new(psk: PskKey<'a>) -> Self {
        Self {
            ctx: ClientPskContextInner {
                raw_cfg: Box::new(coap_dtls_cpsk_t {
                    version: COAP_DTLS_CPSK_SETUP_VERSION as u8,
                    reserved: Default::default(),
                    #[cfg(dtls_ec_jpake_support)]
                    ec_jpake: 0,
                    #[cfg(dtls_cid_support)]
                    use_cid: 0,
                    validate_ih_call_back: None,
                    ih_call_back_arg: std::ptr::null_mut(),
                    client_sni: std::ptr::null_mut(),
                    psk_info: psk.into_raw_cpsk_info(),
                }),
                key_provider: None,
                provided_keys: Vec::new(),
                client_sni: None,
            },
        }
    }

    pub fn key_provider(mut self, key_provider: Box<dyn ClientPskHintKeyProvider<'a>>) -> Self {
        self.ctx.key_provider = Some(key_provider);
        self.ctx.raw_cfg.validate_ih_call_back = Some(dtls_psk_client_ih_callback);
        self
    }

    pub fn build(self) -> ClientPskContext<'a> {
        let ctx = Rc::new(RefCell::new(self.ctx));
        {
            let mut ctx_borrow = ctx.borrow_mut();
            if ctx_borrow.raw_cfg.validate_ih_call_back.is_some() {
                ctx_borrow.raw_cfg.ih_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void;
            }
        }
        ClientPskContext { inner: ctx }
    }
}
impl ClientPskContextBuilder<'_> {
    #[cfg(dtls_ec_jpake_support)]
    pub fn ec_jpake(mut self, ec_jpake: bool) -> Self {
        self.ctx.raw_cfg.ec_jpake = ec_jpake.then_some(1).unwrap_or(0);
        self
    }

    #[cfg(dtls_cid_support)]
    pub fn use_cid(mut self, use_cid: bool) -> Self {
        self.ctx.raw_cfg.use_cid = use_cid.then_some(1).unwrap_or(0);
        self
    }

    pub fn client_sni<T: Into<Vec<u8>>>(mut self, client_sni: T) -> Result<Self, NulError> {
        // For some reason, client_sni is not immutable here.
        // While I don't see any reason why libcoap would modify the string, it is not strictly
        // forbidden for it to do so, so simply using CString::into_raw() is not an option (as it
        // does not allow modifications to client_sni that change the length).
        let sni = CString::new(client_sni.into())?
            .into_bytes_with_nul()
            .into_boxed_slice();
        self.ctx.client_sni = Some(sni);
        self.ctx.raw_cfg.client_sni = self.ctx.client_sni.as_mut().unwrap().as_mut_ptr() as *mut c_char;
        Ok(self)
    }
}

#[derive(Clone, Debug)]
pub struct ClientPskContext<'a> {
    inner: Rc<RefCell<ClientPskContextInner<'a>>>,
}

impl ClientPskContext<'_> {
    /// Returns a pointer to the PSK to use for a given `identity_hint` and `session`, or
    /// [`std::ptr::null()`] if the provided identity hint and/or session are unacceptable.
    ///
    /// The returned pointer is guaranteed to remain valid as long as the underlying
    /// [`ClientPskContextInner`] is not dropped.
    /// As the [`ClientPskContext`] is also stored in the [`CoapClientSession`] instance, this
    /// implies that the pointer is valid for at least as long as the session is.
    ///
    /// After the underlying [`ClientPskContextInner`] is dropped, the returned pointer will no
    /// longer be valid and should no longer be dereferenced.
    fn ih_callback(
        &self,
        identity_hint: Option<&[u8]>,
        session: &CoapClientSession<'_>,
    ) -> *const coap_dtls_cpsk_info_t {
        let mut inner = (*self.inner).borrow_mut();
        let key = inner
            .key_provider
            .as_ref()
            .unwrap()
            .key_for_identity_hint(identity_hint, session);

        if let Some(key) = key {
            let boxed_key_info = Box::new(key.into_raw_cpsk_info());
            let boxed_key_ptr = Box::into_raw(boxed_key_info);
            // TODO remove these entries prematurely if the underlying session is removed (would
            //      require modifications to the client session drop handler).
            inner.provided_keys.push(boxed_key_ptr);
            boxed_key_ptr
        } else {
            std::ptr::null()
        }
    }

    /// SAFETY: This ClientPskContext must outlive the returned coap_session_t.
    pub(crate) unsafe fn create_raw_session(
        &self,
        ctx: &mut CoapContext<'_>,
        addr: &CoapAddress,
        proto: coap_proto_t,
    ) -> Result<NonNull<coap_session_t>, SessionCreationError> {
        // SAFETY: self.raw_context is guaranteed to be valid, local_if can be null,
        // raw_cfg is of valid format (as constructed by the builder).
        {
            let mut inner = (*self.inner).borrow_mut();
            NonNull::new(unsafe {
                coap_new_client_session_psk2(
                    ctx.as_mut_raw_context(),
                    std::ptr::null(),
                    addr.as_raw_address(),
                    proto,
                    inner.raw_cfg.as_mut(),
                )
            })
            .ok_or(SessionCreationError::Unknown)
        }
    }
}

impl<'a> ClientPskContext<'a> {
    /// Restores a [`ClientPskContext`] from a pointer to its inner structure (i.e. from the
    /// user-provided pointer given to DTLS callbacks).
    ///
    /// # Panics
    ///
    /// Panics if the given pointer is a null pointer or the inner structure was already dropped.
    ///
    /// # Safety
    /// The provided pointer must be a valid reference to a [`RefCell<ClientPskContextInner>`]
    /// instance created from a call to [`Weak::into_raw()`].
    unsafe fn from_raw(raw_ctx: *const RefCell<ClientPskContextInner<'a>>) -> Self {
        assert!(!raw_ctx.is_null(), "provided raw DTLS PSK client context was null");
        let inner_weak = Weak::from_raw(raw_ctx);
        let inner = inner_weak
            .upgrade()
            .expect("provided DTLS PSK client context was already dropped!");
        let _ = Weak::into_raw(inner_weak);
        ClientPskContext { inner }
    }
}

#[derive(Debug)]
struct ClientPskContextInner<'a> {
    key_provider: Option<Box<dyn ClientPskHintKeyProvider<'a>>>,
    raw_cfg: Box<coap_dtls_cpsk_t>,
    /// Store for `coap_dtls_cpsk_info_t` instances that we provided in previous identity hint
    /// callback invocations.
    ///
    /// The stored pointers *must* all be created from Box::into_raw().
    ///
    /// Using `Vec<coap_dtls_cpsk_info_t>` instead is not an option, as a Vec resize may cause the
    /// instances to be moved to a different place in memory, invalidating pointers provided to
    /// libcoap.
    provided_keys: Vec<*mut coap_dtls_cpsk_info_t>,
    client_sni: Option<Box<[u8]>>,
}

impl Drop for ClientPskContextInner<'_> {
    fn drop(&mut self) {
        for provided_key in std::mem::take(&mut self.provided_keys).into_iter() {
            // SAFETY: Vector has only ever been filled by instances created from to_raw_cpsk_info.
            unsafe {
                PskKey::from_raw_cpsk_info(*Box::from_raw(provided_key));
            }
        }
        if !self.raw_cfg.ih_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been a call to Weak::into_raw with the correct
            //         type.
            unsafe {
                Weak::from_raw(self.raw_cfg.ih_call_back_arg as *mut RefCell<Self>);
            }
        }
        unsafe {
            // SAFETY: Pointer should not have been changed by anything else and refers to a CPSK
            //         info instance created from DtlsPsk::into_raw_cpsk_info().
            PskKey::from_raw_cpsk_info(self.raw_cfg.psk_info);
        }
    }
}

pub trait ClientPskHintKeyProvider<'a>: Debug {
    fn key_for_identity_hint(&self, identity_hint: Option<&[u8]>, session: &CoapClientSession<'_>) -> Option<PskKey<'a>>;
}

impl<'a, T: Debug> ClientPskHintKeyProvider<'a> for T
where
    T: AsRef<PskKey<'a>>,
{
    fn key_for_identity_hint(&self, identity_hint: Option<&[u8]>, _session: &CoapClientSession<'_>) -> Option<PskKey<'a>> {
        let key = self.as_ref();
        if identity_hint.is_none() || key.identity().as_deref() == identity_hint {
            Some(key.clone())
        } else {
            None
        }
    }
}

unsafe extern "C" fn dtls_psk_client_ih_callback(
    hint: *mut coap_str_const_t,
    session: *mut coap_session_t,
    userdata: *mut c_void,
) -> *const coap_dtls_cpsk_info_t {
    let session = CoapClientSession::from_raw(session);
    let client_context = ClientPskContext::from_raw(userdata as *const RefCell<ClientPskContextInner>);
    let provided_identity =
        NonNull::new(hint).map(|h| std::slice::from_raw_parts((*h.as_ptr()).s, (*h.as_ptr()).length));
    client_context.ih_callback(provided_identity, &session)
}

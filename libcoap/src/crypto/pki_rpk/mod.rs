mod key;
#[cfg(feature = "dtls-pki")]
mod pki;
#[cfg(feature = "dtls-rpk")]
mod rpk;

#[cfg(feature = "dtls-pki")]
pub use pki::*;
#[cfg(feature = "dtls-rpk")]
pub use rpk::*;

pub use key::*;

use crate::error::SessionCreationError;
use crate::session::CoapSession;
use crate::types::CoapAddress;
use crate::CoapContext;
use libcoap_sys::{
    coap_context_set_pki, coap_context_t, coap_dtls_key_t, coap_dtls_pki_t, coap_new_client_session_pki, coap_proto_t,
    coap_session_t, COAP_DTLS_PKI_SETUP_VERSION,
};
use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString, NulError};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::{Rc, Weak};

#[derive(Clone, Debug)]
pub enum ServerPkiRpkCryptoContext<'a> {
    #[cfg(feature = "dtls-pki")]
    Pki(PkiRpkContext<'a, Pki>),
    #[cfg(feature = "dtls-rpk")]
    Rpk(PkiRpkContext<'a, Rpk>),
}

impl ServerPkiRpkCryptoContext<'_> {
    /// SAFETY: The provided CoAP context must not outlive this PkiRpkContext.
    pub(crate) unsafe fn apply_to_context(&self, ctx: NonNull<coap_context_t>) {
        match self {
            #[cfg(feature = "dtls-pki")]
            ServerPkiRpkCryptoContext::Pki(v) => { v.apply_to_context(ctx) }
            #[cfg(feature = "dtls-rpk")]
            ServerPkiRpkCryptoContext::Rpk(v) => { v.apply_to_context(ctx) }
        }
    }
}

pub struct NonCertVerifying;
pub struct CertVerifying;

trait CertVerificationModeSealed {}

#[allow(private_bounds)]
pub trait CertVerificationMode: CertVerificationModeSealed {}

impl CertVerificationModeSealed for NonCertVerifying {}

impl CertVerificationModeSealed for CertVerifying {}

impl CertVerificationMode for NonCertVerifying {}

impl CertVerificationMode for CertVerifying {}

pub struct PkiRpkContextBuilder<'a, KTY: KeyType, V: CertVerificationMode> {
    ctx: PkiRpkContextInner<'a, KTY>,
    verifying: PhantomData<V>,
}

impl<'a, KTY: KeyType> PkiRpkContextBuilder<'a, KTY, NonCertVerifying> {
    fn new_untyped<K: KeyDef<KeyType = KTY> + 'a>(key: K) -> Self {
        PkiRpkContextBuilder::<KTY, NonCertVerifying> {
            ctx: PkiRpkContextInner {
                raw_cfg: Box::new(coap_dtls_pki_t {
                    version: COAP_DTLS_PKI_SETUP_VERSION as u8,
                    verify_peer_cert: 0,
                    check_common_ca: 0,
                    allow_self_signed: 0,
                    allow_expired_certs: 0,
                    cert_chain_validation: 0,
                    cert_chain_verify_depth: 0,
                    check_cert_revocation: 0,
                    allow_no_crl: 0,
                    allow_expired_crl: 0,
                    allow_bad_md_hash: 0,
                    allow_short_rsa_length: 0,
                    is_rpk_not_cert: 0,
                    use_cid: 0,
                    reserved: Default::default(),
                    validate_cn_call_back: None,
                    cn_call_back_arg: std::ptr::null_mut(),
                    validate_sni_call_back: None,
                    sni_call_back_arg: std::ptr::null_mut(),
                    additional_tls_setup_call_back: None,
                    client_sni: std::ptr::null_mut(),
                    pki_key: key.as_raw_dtls_key(),
                }),
                provided_keys: vec![Box::new(key)],
                provided_key_descriptors: vec![],
                cn_callback: None,
                sni_key_provider: None,
                client_sni: None,
            },
            verifying: Default::default(),
        }
    }
}

impl<'a, KTY: KeyType> PkiRpkContextBuilder<'a, KTY, NonCertVerifying> {
    pub fn new<K: KeyDef<KeyType=KTY> + 'a>(key: K) -> Self {
        let mut result = Self::new_untyped(key);
        result.ctx.raw_cfg.is_rpk_not_cert = 1;
        result
    }
}

impl<KTY: KeyType, V: CertVerificationMode> PkiRpkContextBuilder<'_, KTY, V> {
    pub fn use_cid(mut self, use_cid: bool) -> Self {
        self.ctx.raw_cfg.use_cid = use_cid.then_some(1).unwrap_or(0);
        self
    }

    pub fn sni_key_provider(mut self, sni_key_provider: Box<dyn PkiRpkSniKeyProvider<KTY>>) -> Self {
        self.ctx.sni_key_provider = Some(sni_key_provider);
        self.ctx.raw_cfg.validate_sni_call_back = Some(dtls_pki_sni_callback::<KTY>);
        self
    }

    pub fn client_sni(mut self, client_sni: impl Into<Vec<u8>>) -> Result<Self, NulError> {
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

impl<KTY: KeyType> PkiRpkContextBuilder<'_, KTY, CertVerifying> {
    pub fn check_common_ca(mut self, check_common_ca: bool) -> Self {
        self.ctx.raw_cfg.check_common_ca = check_common_ca.then_some(1).unwrap_or(0);
        self
    }

    pub fn allow_self_signed(mut self, allow_self_signed: bool) -> Self {
        self.ctx.raw_cfg.allow_self_signed = allow_self_signed.then_some(1).unwrap_or(0);
        self
    }

    pub fn allow_expired_certs(mut self, allow_expired_certs: bool) -> Self {
        self.ctx.raw_cfg.allow_expired_certs = allow_expired_certs.then_some(1).unwrap_or(0);
        self
    }

    pub fn cert_chain_validation(mut self, cert_chain_validation: bool) -> Self {
        self.ctx.raw_cfg.cert_chain_validation = cert_chain_validation.then_some(1).unwrap_or(0);
        self
    }

    pub fn cert_chain_verify_depth(mut self, cert_chain_verify_depth: u8) -> Self {
        self.ctx.raw_cfg.cert_chain_verify_depth = cert_chain_verify_depth;
        self
    }

    pub fn check_cert_revocation(mut self, check_cert_revocation: bool) -> Self {
        self.ctx.raw_cfg.check_cert_revocation = check_cert_revocation.then_some(1).unwrap_or(0);
        self
    }

    pub fn allow_no_crl(mut self, allow_no_crl: bool) -> Self {
        self.ctx.raw_cfg.allow_no_crl = allow_no_crl.then_some(1).unwrap_or(0);
        self
    }

    pub fn allow_expired_crl(mut self, allow_expired_crl: bool) -> Self {
        self.ctx.raw_cfg.allow_expired_crl = allow_expired_crl.then_some(1).unwrap_or(0);
        self
    }

    pub fn allow_bad_md_hash(mut self, allow_bad_md_hash: bool) -> Self {
        self.ctx.raw_cfg.allow_bad_md_hash = allow_bad_md_hash.then_some(1).unwrap_or(0);
        self
    }

    pub fn allow_short_rsa_length(mut self, allow_short_rsa_length: bool) -> Self {
        self.ctx.raw_cfg.allow_short_rsa_length = allow_short_rsa_length.then_some(1).unwrap_or(0);
        self
    }
}

impl<'a, KTY: KeyType, V: CertVerificationMode> PkiRpkContextBuilder<'a, KTY, V> {
    pub fn build(self) -> PkiRpkContext<'a, KTY> {
        let ctx = Rc::new(RefCell::new(self.ctx));
        {
            let mut ctx_borrow = ctx.borrow_mut();
            if ctx_borrow.raw_cfg.validate_cn_call_back.is_some() {
                ctx_borrow.raw_cfg.cn_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void;
            }
            if ctx_borrow.raw_cfg.validate_sni_call_back.is_some() {
                ctx_borrow.raw_cfg.sni_call_back_arg = Rc::downgrade(&ctx).into_raw() as *mut c_void;
            }
        }
        PkiRpkContext { inner: ctx }
    }
}

pub struct PkiRpkContextInner<'a, KTY: KeyType> {
    raw_cfg: Box<coap_dtls_pki_t>,
    /// Store for `coap_dtls_key_t` instances that we provided in previous callback invocations.
    ///
    /// The stored pointers *must* all be created from Box::into_raw().
    ///
    /// Using `Vec<coap_dtls_key_t>` instead is not an option, as a Vec resize may cause the
    /// instances to be moved to a different place in memory, invalidating pointers provided to
    /// libcoap.
    provided_keys: Vec<Box<dyn KeyDef<KeyType = KTY> + 'a>>,
    provided_key_descriptors: Vec<*mut coap_dtls_key_t>,
    cn_callback: Option<CnCallback<'a>>,
    sni_key_provider: Option<Box<dyn PkiRpkSniKeyProvider<KTY>>>,
    client_sni: Option<Box<[u8]>>,
}

impl<KTY: KeyType> Debug for PkiRpkContextInner<'_, KTY> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiContextInner")
            .field(
                "raw_cfg",
                &format!("(does not implement Debug), address: {:p}", self.raw_cfg),
            )
            .field("provided_keys", &self.provided_keys)
            .field("provided_key_descriptors", &format!("(values do not implement Debug), length: {}", self.provided_key_descriptors.len()))
            .field("cn_callback", &self.cn_callback)
            .field("sni_key_provider", &self.sni_key_provider)
            .field("client_sni", &self.client_sni)
            .finish()
    }
}

impl<KTY: KeyType> Drop for PkiRpkContextInner<'_, KTY> {
    fn drop(&mut self) {
        for key_ref in std::mem::take(&mut self.provided_key_descriptors).into_iter() {
            // SAFETY: If the inner context is dropped, this implies that the pointers returned in
            // previous callbacks are no longer used (because of the contracts of apply_to_context()
            // and create_raw_session()). We can therefore restore and drop these values without
            // breaking the aliasing rules.
            unsafe {
                drop(Box::from_raw(key_ref));
            }
        }
        if !self.raw_cfg.cn_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been using a call to Weak::into_raw with the
            //         correct type, otherwise, the value will always be null.
            unsafe {
                Weak::from_raw(self.raw_cfg.cn_call_back_arg as *mut RefCell<Self>);
            }
        }
        if !self.raw_cfg.sni_call_back_arg.is_null() {
            // SAFETY: If we set this, it must have been using a call to Weak::into_raw with the
            //         correct type, otherwise, the value will always be null.
            unsafe {
                Weak::from_raw(self.raw_cfg.sni_call_back_arg as *mut RefCell<Self>);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PkiRpkContext<'a, KTY: KeyType> {
    inner: Rc<RefCell<PkiRpkContextInner<'a, KTY>>>,
}

impl<KTY: KeyType> PkiRpkContext<'_, KTY> {
    /// SAFETY: this PkiRpkContext must outlive the returned coap_session_t.
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
                coap_new_client_session_pki(
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

    /// SAFETY: The provided CoAP context must not outlive this PkiRpkContext.
    unsafe fn apply_to_context(&self, mut ctx: NonNull<coap_context_t>) {
        let mut inner = self.inner.borrow_mut();
        // TODO error handling
        // SAFETY: context is valid as per caller contract, raw_cfg is a valid configuration as
        // ensured by the builder.
        unsafe {
            coap_context_set_pki(ctx.as_mut(), inner.raw_cfg.as_mut());
        }
    }
}

impl<'a, KTY: KeyType> PkiRpkContext<'a, KTY> {
    // cn and depth are unused only if dtls-pki feature is not enabled
    #[cfg_attr(not(feature = "dtls-pki"), allow(unused_variables))]
    fn cn_callback(
        &self,
        cn: &CStr,
        asn1_public_cert: &[u8],
        session: &CoapSession,
        depth: c_uint,
        validated: bool,
    ) -> c_int {
        let inner = (*self.inner).borrow();
        // This function is only ever called if a CN key provider is set, so it's fine to unwrap
        // here.
        if match inner
            .cn_callback
            .as_ref()
            .unwrap() {
            #[cfg(feature = "dtls-pki")]
            CnCallback::Pki(pki) => { pki.validate_cn(cn, asn1_public_cert, session, depth, validated) }
            #[cfg(feature = "dtls-rpk")]
            CnCallback::Rpk(rpk) => { rpk.validate_rpk(asn1_public_cert, session, validated) }
        } { 1 } else { 0 }
    }

    fn sni_callback(&self, sni: &CStr) -> *mut coap_dtls_key_t {
        let mut inner = self.inner.borrow_mut();
        // This function is only ever called if an SNI key provider is set, so it's fine to unwrap
        // here.
        let key = inner.sni_key_provider.as_ref().unwrap().key_for_sni(sni);
        if let Some(key) = key {
            let key_ref = Box::into_raw(Box::new(key.as_raw_dtls_key()));
            inner.provided_keys.push(key);
            inner.provided_key_descriptors.push(key_ref);
            key_ref
        } else {
            std::ptr::null_mut()
        }
    }

    /// Restores a [`PkiRpkContext`] from a pointer to its inner structure (i.e. from the
    /// user-provided pointer given to DTLS callbacks).
    ///
    /// # Panics
    ///
    /// Panics if the given pointer is a null pointer or the inner structure was already dropped.
    ///
    /// # Safety
    /// The provided pointer must be a valid reference to a [`RefCell<PkiRpkContextInner<KTY>>`]
    /// instance created from a call to [`Weak::into_raw()`].
    unsafe fn from_raw(raw_ctx: *const RefCell<PkiRpkContextInner<'a, KTY>>) -> Self {
        assert!(!raw_ctx.is_null(), "provided raw DTLS PKI context was null");
        let inner_weak = Weak::from_raw(raw_ctx);
        let inner = inner_weak
            .upgrade()
            .expect("provided DTLS PKI context was already dropped!");
        let _ = Weak::into_raw(inner_weak);
        PkiRpkContext { inner }
    }
}

#[derive(Debug)]
pub enum CnCallback<'a> {
    #[cfg(feature = "dtls-pki")]
    Pki(Box<dyn PkiCnValidator + 'a>),
    #[cfg(feature = "dtls-rpk")]
    Rpk(Box<dyn RpkValidator + 'a>)
}

pub trait PkiRpkSniKeyProvider<KTY: KeyType>: Debug {
    fn key_for_sni(&self, sni: &CStr) -> Option<Box<dyn KeyDef<KeyType = KTY>>>;
}

unsafe extern "C" fn dtls_pki_cn_callback<KTY: KeyType>(
    cn: *const c_char,
    asn1_public_cert: *const u8,
    asn1_length: usize,
    session: *mut coap_session_t,
    depth: c_uint,
    validated: c_int,
    arg: *mut c_void,
) -> c_int {
    let session = CoapSession::from_raw(session);
    let cn = CStr::from_ptr(cn);
    let asn1_public_cert = std::slice::from_raw_parts(asn1_public_cert, asn1_length);
    let validated = validated == 1;
    let context = PkiRpkContext::from_raw(arg as *const RefCell<PkiRpkContextInner<KTY>>);
    context.cn_callback(cn, asn1_public_cert, &session, depth, validated)
}

unsafe extern "C" fn dtls_pki_sni_callback<KTY: KeyType>(sni: *const c_char, arg: *mut c_void) -> *mut coap_dtls_key_t {
    let sni = CStr::from_ptr(sni);
    let context = PkiRpkContext::from_raw(arg as *const RefCell<PkiRpkContextInner<KTY>>);
    context.sni_callback(sni)
}

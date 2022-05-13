// SPDX-License-Identifier: BSD-2-Clause
/*
 * mem.rs - Memory handling helper structs and traits for the libcoap Rust Wrapper.
 * Copyright (c) 2022 The NAMIB Project Developers, all rights reserved.
 * See the README as well as the LICENSE file for more information.
 */

use std::cell::{Ref, RefCell, RefMut};
use std::ffi::c_void;
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use std::rc::{Rc, Weak};

/// A strong reference to an existing Coap Rust library struct, created from an app data/user data
/// pointer inside of a C library struct.
///
/// This type is used to emulate Rust's aliasing rules through the FFI boundary.
///
/// # Purpose and Safety
/// When [CoapContext::do_io()](crate::context::CoapContext::do_io()) is called, a mutable reference
/// to the context is provided, which implies that inside of this call, we can assume to have exclusive
/// access to the context (and therefore also all of its sessions, resources, endpoints, etc.).
///
/// At some point inside of the [CoapContext::do_io()](crate::context::CoapContext::do_io()) call,
/// the callback functions are called from within the C library. Because these callbacks only get
/// the raw pointers to the underlying C library structs, we have to use their app_data pointers to
/// get to our actual Rust structs.
///
/// These pointers also have to be raw, which is why we use [Rc]/[Weak]s and
/// [Rc::into_raw()]/[Weak::into_raw()] to create such raw pointers.
/// However, after restoration, these smart pointers only provide immutable access to the underlying
/// structs.
///
/// Because we know that the callbacks are only called from [CoapContext::do_io()](crate::context::CoapContext::do_io()),
/// which treats the call to the raw libraries [coap_io_process()](libcoap_sys::coap_io_process())
/// as if the context (and all of its related structures like sessions) were mutably borrowed to
/// this function, we can therefore assume that creating a mutable reference to the Rust structs
/// from the callback function does not violate Rust's aliasing rules. In order to get these
/// references, this wrapper type is used, which provides basically the same functionality as an
/// `Rc<RefCell<D>>`, but with additional helper functions to aid in creating and using the raw
/// pointers stored in the libcoap C structs.
pub(crate) struct CoapAppDataRef<D>(Rc<RefCell<D>>);

impl<D> CoapAppDataRef<D> {
    /// Creates a new instance of CoapStrongAppDataRef, containing the provided value.
    pub fn new(value: D) -> CoapAppDataRef<D> {
        CoapAppDataRef(Rc::new(RefCell::new(value)))
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the appropriate reference type.
    ///
    /// This is done by first restoring the `Rc<RefCell<D>>` using [Rc::from_raw()], then
    /// cloning and creating the [CoapAppDataRef] from it (maintaining the original reference using
    /// [Rc::into_raw()]).
    ///
    /// Note that for the lifetime of this [CoapAppDataRef], the reference counter of the
    /// underlying [Rc] is increased by one.
    ///
    /// # Safety
    /// For an explanation of the purpose of this struct and where it was originally intended to be
    /// used, see the struct-level documentation.
    ///
    /// To safely use this function, the following invariants must be kept:
    /// - ptr is a valid pointer to an Rc<RefCell<D>>
    pub unsafe fn clone_raw_rc(ptr: *mut c_void) -> CoapAppDataRef<D> {
        let orig_ref = Rc::from_raw(ptr as *const RefCell<D>);
        let new_ref = Rc::clone(&orig_ref);
        Rc::into_raw(orig_ref);
        CoapAppDataRef(new_ref)
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the appropriate reference type.
    ///
    /// This is done by first restoring the `Weak<RefCell<D>>` using [Weak::from_raw()],
    /// upgrading it to a `Rc<RefCell<D>>` then cloning and creating the [CoapAppDataRef] from the
    /// upgraded reference (restoring the raw pointer again afterwards using [Rc::downgrade()] and
    /// [Weak::into_raw()]).
    ///
    /// Note that for the lifetime of this [CoapAppDataRef], the reference counter of the underlying
    /// [Rc] is increased by one.
    ///
    /// # Panics
    /// Panics if the provided Weak reference is orphaned.
    ///
    /// # Safety
    /// For an explanation of the purpose of this struct and where it was originally intended to be
    /// used, see the struct-level documentation.
    ///
    /// To safely use this function, the following invariants must be kept:
    /// - ptr is a valid pointer to a `Weak<RefCell<D>>`
    pub unsafe fn clone_raw_weak(ptr: *mut c_void) -> CoapAppDataRef<D> {
        let orig_ref = Weak::from_raw(ptr as *const RefCell<D>);
        let new_ref = Weak::upgrade(&orig_ref).expect("attempted to upgrade a weak reference that was orphaned");
        let _weakref = Weak::into_raw(orig_ref);
        CoapAppDataRef(new_ref)
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the underlying `Weak<RefCell<D>>`.
    ///
    /// This is done by restoring the `Weak<RefCell<D>>` using [Weak::from_raw()],
    ///
    /// # Panics
    /// Panics if the provided Weak reference is orphaned.
    ///
    /// # Safety
    /// For an explanation of the purpose of this struct and where it was originally intended to be
    /// used, see the struct-level documentation.
    ///
    /// To safely use this function, the following invariants must be kept:
    /// - ptr is a valid pointer to a `Weak<RefCell<D>>`
    /// - as soon as the returned `Weak<RefCell<D>>` is dropped, the provided pointer is treated as
    ///   invalid.
    pub unsafe fn raw_ptr_to_weak(ptr: *mut c_void) -> Weak<RefCell<D>> {
        Weak::from_raw(ptr as *const RefCell<D>)
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the underlying `Rc<RefCell<D>>`.
    ///
    /// This is done by restoring the `Rc<RefCell<D>>` using [Rc::from_raw()],
    ///
    /// # Safety
    /// For an explanation of the purpose of this struct and where it was originally intended to be
    /// used, see the struct-level documentation.
    ///
    /// To safely use this function, the following invariants must be kept:
    /// - ptr is a valid pointer to a `Rc<RefCell<D>>`
    // Kept for consistency
    #[allow(unused)]
    pub unsafe fn raw_ptr_to_rc(ptr: *mut c_void) -> Rc<RefCell<D>> {
        Rc::from_raw(ptr as *const RefCell<D>)
    }

    /// Creates a raw reference, suitable for storage inside of a libcoap C library user/application
    /// data pointer.
    ///
    /// This function internally calls [Rc::clone()] and then [Rc::into_raw()] to create a pointer
    /// referring to a clone of the `Rc<RefCell<D>>` contained in this type.
    ///
    /// Note that this increases the reference count of the Rc by one.
    // Kept for consistency
    #[allow(unused)]
    pub fn create_raw_rc(&self) -> *mut c_void {
        Rc::into_raw(Rc::clone(&self.0)) as *mut c_void
    }

    /// Creates a raw reference, suitable for storage inside of a libcoap C library user/application
    /// data pointer.
    ///
    /// This function internally calls [Rc::downgrade()] and then [Weak::into_raw()] to create a
    /// pointer referring to a weak reference of the `Rc<RefCell<D>>` contained in this type.
    ///
    /// Note that this does not increase the reference count of the [Rc] by one. If you want to
    /// ensure that the underlying D is never cleaned up for as long as this pointer exists, you
    /// need to maintain this object for as least as long as the reference.
    pub fn create_raw_weak(&self) -> *mut c_void {
        Weak::into_raw(Rc::downgrade(&self.0)) as *mut c_void
    }

    /// Creates an immutable reference to the contained data type.
    ///
    /// # Panics
    /// Panics if borrowing here would violate Rusts aliasing rules.
    pub fn borrow(&self) -> Ref<D> {
        RefCell::borrow(&self.0)
    }

    /// Creates a mutable reference to the contained data type.
    ///
    /// # Panics
    /// Panics if borrowing mutably here would violate Rusts aliasing rules.
    pub fn borrow_mut(&self) -> RefMut<D> {
        RefCell::borrow_mut(&self.0)
    }
}

impl<D: PartialEq> PartialEq for CoapAppDataRef<D> {
    fn eq(&self, other: &Self) -> bool {
        Rc::eq(&self.0, &other.0)
    }
}

impl<D: Eq + PartialEq> Eq for CoapAppDataRef<D> {}

impl<D> Clone for CoapAppDataRef<D> {
    fn clone(&self) -> Self {
        CoapAppDataRef(self.0.clone())
    }
}

impl<D: Debug> Debug for CoapAppDataRef<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoapAppDataRef").field("0", &self.0).finish()
    }
}

#[derive(Debug)]
pub(crate) struct FfiPassthroughRefContainer<T: Debug>(Rc<RefCell<T>>, Rc<RefCell<Option<*mut T>>>);

#[derive(Debug)]
pub(crate) struct FfiPassthroughWeakContainer<T: Debug>(Weak<RefCell<T>>, Weak<RefCell<Option<*mut T>>>);

impl<T: Debug> Clone for FfiPassthroughRefContainer<T> {
    fn clone(&self) -> Self {
        FfiPassthroughRefContainer(Rc::clone(&self.0), Rc::clone(&self.1))
    }
}

impl<T: Debug> Clone for FfiPassthroughWeakContainer<T> {
    fn clone(&self) -> Self {
        FfiPassthroughWeakContainer(Weak::clone(&self.0), Weak::clone(&self.1))
    }
}

pub(crate) enum FfiPassthroughRefMut<'a, T> {
    Owned(RefMut<'a, T>),
    Borrowed(&'a mut T, Rc<RefCell<Option<*mut T>>>),
}

impl<T> Deref for FfiPassthroughRefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            FfiPassthroughRefMut::Owned(v) => v.deref(),
            FfiPassthroughRefMut::Borrowed(v, _lend_container) => v,
        }
    }
}

impl<T> DerefMut for FfiPassthroughRefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            FfiPassthroughRefMut::Owned(v) => v.deref_mut(),
            FfiPassthroughRefMut::Borrowed(v, _lend_container) => v,
        }
    }
}

impl<T> Drop for FfiPassthroughRefMut<'_, T> {
    fn drop(&mut self) {
        if let FfiPassthroughRefMut::Borrowed(refer, lend_container) = self {
            let mut lend_container = RefCell::borrow_mut(lend_container);
            if lend_container.is_some() {
                panic!("somehow, multiple references are stored in the same FfiPassthroughRefContainer");
            }
            assert!(
                lend_container.replace(*refer).is_none(),
                "somehow, multiple references are stored in the same FfiPassthroughRefContainer"
            );
        }
    }
}

pub(crate) enum FfiPassthroughRef<'a, T> {
    Owned(Ref<'a, T>),
    Borrowed(&'a mut T, Rc<RefCell<Option<*mut T>>>),
}

impl<T> Deref for FfiPassthroughRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            FfiPassthroughRef::Owned(v) => v.deref(),
            FfiPassthroughRef::Borrowed(v, _lend_container) => v,
        }
    }
}

impl<T> Drop for FfiPassthroughRef<'_, T> {
    fn drop(&mut self) {
        if let FfiPassthroughRef::Borrowed(refer, lend_container) = self {
            let mut lend_container = RefCell::borrow_mut(lend_container);
            if lend_container.is_some() {
                panic!("somehow, multiple references are stored in the same FfiPassthroughRefContainer");
            }
            assert!(
                lend_container.replace(*refer).is_none(),
                "somehow, multiple references are stored in the same FfiPassthroughRefContainer"
            );
        }
    }
}

pub struct FfiPassthroughRefLender<'a, T> {
    lent_ref: &'a mut T,
    lent_ptr_ctr: Weak<RefCell<Option<*mut T>>>,
}

impl<'a, T> FfiPassthroughRefLender<'a, T> {
    fn new(refer: &'a mut T, container: &Rc<RefCell<Option<*mut T>>>) -> FfiPassthroughRefLender<'a, T> {
        RefCell::borrow_mut(container).replace(refer as *mut T);
        FfiPassthroughRefLender {
            lent_ref: refer,
            lent_ptr_ctr: Rc::downgrade(container),
        }
    }

    pub(crate) fn unlend(self) {
        std::mem::drop(self);
    }
}

impl<T> Drop for FfiPassthroughRefLender<'_, T> {
    fn drop(&mut self) {
        if let Some(lent_ptr_ctr) = self.lent_ptr_ctr.upgrade() {
            assert_eq!(
                self.lent_ref as *mut T,
                lent_ptr_ctr
                    .take()
                    .expect("unable to retrieve lent reference, implying that it may be in use somewhere"),
                "somehow, multiple references are stored in the same FfiPassthroughRefContainer"
            )
        }
    }
}

impl<T: Debug> FfiPassthroughRefContainer<T> {
    pub fn borrow_mut(&self) -> FfiPassthroughRefMut<'_, T> {
        if let Some(borrowed) = RefCell::borrow_mut(&self.1).take() {
            // SAFETY: The aliasing rules are ensured here by making sure that only one person may
            // retrieve the pointer value stored in the container at any time (as the value in the
            // Option is always retrieved using _take()_.
            // The validity of the pointer is ensured because the only way a value can be stored
            // here is by calling FfiPassthroughRefContainer::lend_ref_mut(), which converts a
            // reference into an always valid pointer.
            FfiPassthroughRefMut::Borrowed(unsafe { borrowed.as_mut() }.unwrap(), Rc::clone(&self.1))
        } else {
            FfiPassthroughRefMut::Owned(RefCell::borrow_mut(&self.0))
        }
    }

    pub fn borrow(&self) -> FfiPassthroughRef<'_, T> {
        if let Some(borrowed) = RefCell::borrow_mut(&self.1).take() {
            // SAFETY: The aliasing rules are ensured here by making sure that only one person may
            // retrieve the pointer value stored in the container at any time (as the value in the
            // Option is always retrieved using _take()_.
            // The validity of the pointer is ensured because the only way a value can be stored
            // here is by calling FfiPassthroughRefContainer::lend_ref_mut(), which converts a
            // reference into an always valid pointer.
            // TODO we may want to allow multiple immutable borrows at some point(?)
            FfiPassthroughRef::Borrowed(unsafe { borrowed.as_mut() }.unwrap(), Rc::clone(&self.1))
        } else {
            FfiPassthroughRef::Owned(RefCell::borrow(&self.0))
        }
    }

    // Kept for consistency
    #[allow(unused)]
    pub fn create_raw_ref(&self) -> *mut FfiPassthroughRefContainer<T> {
        Box::into_raw(Box::new(FfiPassthroughRefContainer::<T>::clone(self)))
    }

    pub fn create_raw_weak(&self) -> *mut FfiPassthroughWeakContainer<T> {
        Box::into_raw(Box::new(self.downgrade()))
    }

    // Kept for consistency
    #[allow(unused)]
    pub unsafe fn clone_raw_ref(ptr: *mut FfiPassthroughRefContainer<T>) -> FfiPassthroughRefContainer<T> {
        let ref_box: Box<FfiPassthroughRefContainer<T>> = Box::from_raw(ptr);
        let ret_val = FfiPassthroughRefContainer::<T>::clone(ref_box.as_ref());
        Box::into_raw(ref_box);
        ret_val
    }

    pub unsafe fn clone_raw_weak(ptr: *mut FfiPassthroughWeakContainer<T>) -> FfiPassthroughRefContainer<T> {
        let ref_box: Box<FfiPassthroughWeakContainer<T>> = Box::from_raw(ptr);
        let ret_val = ref_box
            .upgrade()
            .expect("unable to restore FfiPassthroughRefContainer as the underlying value was already dropped.");
        Box::into_raw(ref_box);
        ret_val
    }

    // Kept for consistency
    #[allow(unused)]
    pub unsafe fn from_raw_box(ptr: *mut FfiPassthroughRefContainer<T>) -> Box<FfiPassthroughRefContainer<T>> {
        Box::from_raw(ptr)
    }

    /// Stores a mutable reference to an instance of T for later retrieval by code running on the
    /// other side of the FFI barrier.
    pub fn lend_ref_mut<'a>(&self, refer: &'a mut T) -> FfiPassthroughRefLender<'a, T> {
        assert_eq!(
            RefCell::as_ptr(&self.0),
            refer as *mut T,
            "attempted to lend different object over FfiPassthroughRefContainer"
        );
        FfiPassthroughRefLender::new(refer, &self.1)
    }

    pub fn downgrade(&self) -> FfiPassthroughWeakContainer<T> {
        FfiPassthroughWeakContainer(Rc::downgrade(&self.0), Rc::downgrade(&self.1))
    }
}

impl<T: Debug> FfiPassthroughWeakContainer<T> {
    pub fn upgrade(&self) -> Option<FfiPassthroughRefContainer<T>> {
        self.0
            .upgrade()
            .zip(self.1.upgrade())
            .map(|(v0, v1)| FfiPassthroughRefContainer(v0, v1))
    }

    pub unsafe fn from_raw_box(ptr: *mut FfiPassthroughWeakContainer<T>) -> Box<FfiPassthroughWeakContainer<T>> {
        Box::from_raw(ptr)
    }
}

impl<V: Debug> FfiPassthroughRefContainer<V> {
    pub fn new(value: V) -> FfiPassthroughRefContainer<V> {
        FfiPassthroughRefContainer(Rc::new(RefCell::new(value)), Rc::new(RefCell::new(None)))
    }
}

impl<T: Debug> DropInnerExclusively for CoapAppDataRef<T> {
    fn drop_exclusively(self) {
        std::mem::drop(
            Rc::try_unwrap(self.0).expect("unable to unwrap instance of CoapAppDataRef as it is still in use"),
        )
    }
}

pub(crate) trait DropInnerExclusively {
    /// Consume this instance, ensuring that the inner (and potentially shared) part of the struct
    /// referenced by this instance is also dropped.
    ///
    /// # Panics
    /// Panics if the inner part of this struct cannot be exclusively dropped, i.e., it is still
    /// used by another instance.
    fn drop_exclusively(self);
}

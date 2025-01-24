// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © The libcoap-rs Contributors, all rights reserved.
 * This file is part of the libcoap-rs project, see the README file for
 * general information on this project and the NOTICE.md and LICENSE files
 * for information regarding copyright ownership and terms of use.
 *
 * mem.rs - Memory handling helper structs and traits for the libcoap Rust wrapper.
 */

//! Code related to memory handling, especially for passing objects through FFI

use std::{
    cell::{Ref, RefCell, RefMut},
    ffi::c_void,
    fmt::{Debug, Formatter},
    ops::{Deref, DerefMut},
    rc::{Rc, Weak},
};

/// Trait implemented by libcoap wrapper structs that contain an inner value that may be dropped
/// exclusively, i.e., that can be dropped with the additional check that there are no further
/// references to the inner value.
pub(crate) trait DropInnerExclusively {
    /// Consume this instance, ensuring that the inner (and potentially shared) part of the struct
    /// referenced by this instance is also dropped.
    ///
    /// # Panics
    ///
    /// Panics if the inner part of this struct cannot be exclusively dropped, i.e., it is still
    /// used by another instance.
    fn drop_exclusively(self);
}

/// A strong reference counted cell, created from an app data/user data pointer inside of a C
/// library struct.
///
/// This type is a wrapper around Rc<RefCell<D>> with some additional functions for creating from
/// or converting to raw pointers.
pub(crate) struct CoapFfiRcCell<D>(Rc<RefCell<D>>);

impl<D> CoapFfiRcCell<D> {
    /// Creates a new instance of CoapFfiRcCell, containing the provided value.
    pub fn new(value: D) -> CoapFfiRcCell<D> {
        CoapFfiRcCell(Rc::new(RefCell::new(value)))
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the appropriate reference type.
    ///
    /// This is done by first restoring the `Rc<RefCell<D>>` using [Rc::from_raw()], then
    /// cloning and creating the [CoapFfiRcCell] from it (maintaining the original reference using
    /// [Rc::into_raw()]).
    ///
    /// Note that for the lifetime of this [CoapFfiRcCell], the reference counter of the
    /// underlying [Rc] is increased by one.
    ///
    /// # Safety
    /// For an explanation of the purpose of this struct and where it was originally intended to be
    /// used, see the struct-level documentation.
    ///
    /// To safely use this function, the following invariants must be kept:
    /// - ptr is a valid pointer to an Rc<RefCell<D>>
    pub unsafe fn clone_raw_rc(ptr: *mut c_void) -> CoapFfiRcCell<D> {
        let orig_ref = Rc::from_raw(ptr as *const RefCell<D>);
        let new_ref = Rc::clone(&orig_ref);
        // Pointer should not have changed, so we don't need to use the returned value.
        let _ = Rc::into_raw(orig_ref);
        CoapFfiRcCell(new_ref)
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the appropriate reference type.
    ///
    /// This is done by first restoring the `Weak<RefCell<D>>` using [Weak::from_raw()],
    /// upgrading it to a `Rc<RefCell<D>>` then cloning and creating the [CoapFfiRcCell] from the
    /// upgraded reference (restoring the raw pointer again afterwards using [Rc::downgrade()] and
    /// [Weak::into_raw()]).
    ///
    /// Note that for the lifetime of this [CoapFfiRcCell], the reference counter of the underlying
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
    pub unsafe fn clone_raw_weak(ptr: *mut c_void) -> CoapFfiRcCell<D> {
        let orig_ref = Weak::from_raw(ptr as *const RefCell<D>);
        let new_ref = Weak::upgrade(&orig_ref).expect("attempted to upgrade a weak reference that was orphaned");
        let _weakref = Weak::into_raw(orig_ref);
        CoapFfiRcCell(new_ref)
    }

    /// Converts from a raw user data/application data pointer inside of a libcoap C library struct
    /// into the underlying `Weak<RefCell<D>>`.
    ///
    /// This is done by restoring the `Weak<RefCell<D>>` using [Weak::from_raw()],
    ///
    /// Note that unlike [CoapFfiRcCell::clone_raw_weak()], this does not clone the weak reference
    /// inside of the pointer and instead restores the `Weak` directly from the pointer.
    /// This means that dropping the `Weak` returned from this function invalidates the pointer
    /// provided to this function.
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
    /// Note that unlike [CoapFfiRcCell::clone_raw_rc()], this does not clone the weak reference
    /// inside of the pointer and instead restores the `Rc` directly from the pointer.
    /// This means that dropping the `Rc` returned from this function invalidates the pointer
    /// provided to this function and that the provided pointer must point to a valid
    /// `Rc<RefCell<D>>`.
    ///
    /// # Panics
    /// Panics if the provided Weak reference is orphaned.
    ///
    /// # Safety
    /// For an explanation of the purpose of this struct and where it was originally intended to be
    /// used, see the struct-level documentation.
    ///
    /// To safely use this function, the following invariants must be kept:
    /// - ptr is a valid pointer to a `Rc<RefCell<D>>`
    /// - as soon as the returned `Rc<RefCell<D>>` is dropped, the provided pointer is treated as
    ///   invalid.
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

impl<D: PartialEq> PartialEq for CoapFfiRcCell<D> {
    fn eq(&self, other: &Self) -> bool {
        Rc::eq(&self.0, &other.0)
    }
}

impl<D: Eq + PartialEq> Eq for CoapFfiRcCell<D> {}

impl<D> Clone for CoapFfiRcCell<D> {
    fn clone(&self) -> Self {
        CoapFfiRcCell(self.0.clone())
    }
}

impl<D: Debug> Debug for CoapFfiRcCell<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoapFfiRcCell").field("0", &self.0).finish()
    }
}

impl<T: Debug> DropInnerExclusively for CoapFfiRcCell<T> {
    fn drop_exclusively(self) {
        std::mem::drop(
            Rc::try_unwrap(self.0).expect("unable to unwrap instance of CoapFfiRcCell as it is still in use"),
        )
    }
}

/// A reference counted cell suitable for passing through the FFI barrier, with the additional
/// possibility of passing an existing reference through this barrier.
///
/// This struct is similar to [CoapFfiRcCell], but provides additional functionality for
/// maintaining a reference through the FFI barrier using the [lend()] function.
#[derive(Debug)]
pub(crate) struct CoapLendableFfiRcCell<T: Debug>(Rc<RefCell<T>>, Rc<RefCell<Option<*mut T>>>);

impl<T: Debug> CoapLendableFfiRcCell<T> {
    /// Creates a new [`CoapLendableFfiRcCell`] from the given value.
    pub fn new(value: T) -> CoapLendableFfiRcCell<T> {
        CoapLendableFfiRcCell(Rc::new(RefCell::new(value)), Rc::new(RefCell::new(None)))
    }

    /// Mutably borrows from the value in this cell.
    ///
    /// This function will first check if a reference was lent through the FFI barrier using a call
    /// to [lend()].
    /// If so, it will take that reference (and return it to the cell when the returned
    /// [CoapLendableFfiRef] goes out of scope).
    /// If not, it will borrow the value normally by calling [Rc::borrow()] on the contained value.
    ///
    /// # Panics
    /// Panics if the value was already mutably borrowed.
    pub fn borrow_mut(&self) -> CoapLendableFfiRefMut<'_, T> {
        if let Some(borrowed) = RefCell::borrow_mut(&self.1).take() {
            // SAFETY: The aliasing rules are ensured here by making sure that only one person may
            // retrieve the pointer value stored in the container at any time (as the value in the
            // Option is always retrieved using _take()_.
            // The validity of the pointer is ensured because the only way a value can be stored
            // here is by calling CoapLendableFfiRcCell::lend_ref_mut(), which converts a
            // reference into an always valid pointer.
            CoapLendableFfiRefMut::Borrowed(unsafe { borrowed.as_mut() }.unwrap(), Rc::clone(&self.1))
        } else {
            CoapLendableFfiRefMut::Owned(RefCell::borrow_mut(&self.0))
        }
    }

    /// Immutably borrows from the value in this cell.
    ///
    /// This function will first check if a reference was lent through the FFI barrier using a call
    /// to [lend()].
    /// If so, it will take that reference (and return it to the cell when the returned
    /// [CoapLendableFfiRef] goes out of scope).
    /// If not, it will borrow the value normally by calling [Rc::borrow()] on the contained value.
    ///
    /// # Panics
    /// Panics if the value was already mutably borrowed.
    pub fn borrow(&self) -> CoapLendableFfiRef<'_, T> {
        if let Some(borrowed) = RefCell::borrow_mut(&self.1).take() {
            // SAFETY: The aliasing rules are ensured here by making sure that only one person may
            // retrieve the pointer value stored in the container at any time (as the value in the
            // Option is always retrieved using _take()_.
            // The validity of the pointer is ensured because the only way a value can be stored
            // here is by calling CoapLendableFfiRcCell::lend_ref_mut(), which converts a
            // reference into an always valid pointer.
            // TODO we may want to allow multiple immutable borrows at some point(?)
            CoapLendableFfiRef::Borrowed(unsafe { borrowed.as_mut() }.unwrap(), Rc::clone(&self.1))
        } else {
            CoapLendableFfiRef::Owned(RefCell::borrow(&self.0))
        }
    }

    /// Create a raw pointer to this cell, suitable for storage in a libcoap application data
    /// pointer.
    ///
    /// Internally, this function creates a clone of this cell, wraps this cell in a `Box` and then
    /// converts this value into a pointer using [Box::into_raw].
    ///
    /// It is in the callers responsibility to free the memory associated with this `Box`, e.g., by
    /// calling [from_raw_box()] and then dropping the value.
    // Kept for consistency
    #[allow(unused)]
    pub fn create_raw_rc_box(&self) -> *mut CoapLendableFfiRcCell<T> {
        Box::into_raw(Box::new(CoapLendableFfiRcCell::<T>::clone(self)))
    }

    /// Create a raw pointer to this cell, suitable for storage in a libcoap application data
    /// pointer.
    ///
    /// Internally, this function creates a weak clone of this cell, wraps this cell in a `Box` and
    /// then converts this value into a pointer using [Box::into_raw].
    ///
    /// It is in the callers responsibility to free the memory associated with this `Box`, e.g., by
    /// calling [CoapLendableFfiWeakCell::from_raw_box()] and then dropping the value.
    pub fn create_raw_weak_box(&self) -> *mut CoapLendableFfiWeakCell<T> {
        Box::into_raw(Box::new(self.downgrade()))
    }

    /// Creates a new instance of this struct by cloning from a raw pointer pointing to a
    /// `Box<CoapLendableFfiRcCell<T>`.
    ///
    /// # Safety
    /// The provided pointer must point to a valid instance of `Box<CoapLendableFfiRcCell<T>`.
    // Kept for consistency
    #[allow(unused)]
    pub unsafe fn clone_raw_rc_box(ptr: *mut CoapLendableFfiRcCell<T>) -> CoapLendableFfiRcCell<T> {
        let ref_box: Box<CoapLendableFfiRcCell<T>> = Box::from_raw(ptr);
        let ret_val = CoapLendableFfiRcCell::<T>::clone(ref_box.as_ref());
        Box::into_raw(ref_box);
        ret_val
    }

    /// Creates a new instance of this struct by cloning from a raw pointer pointing to a
    /// `Box<CoapLendableFfiWeakCell<T>`.
    ///
    /// # Panics
    /// Panics if the provided weak cell is orphaned.
    ///
    /// # Safety
    /// The provided pointer must point to a valid instance of `Box<CoapLendableFfiWeakCell<T>`.
    pub unsafe fn clone_raw_weak_box(ptr: *mut CoapLendableFfiWeakCell<T>) -> CoapLendableFfiRcCell<T> {
        let ref_box: Box<CoapLendableFfiWeakCell<T>> = Box::from_raw(ptr);
        let ret_val = ref_box
            .upgrade()
            .expect("unable to restore CoapLendableFfiRcCell as the underlying value was already dropped");
        assert_eq!(Box::into_raw(ref_box), ptr);
        ret_val
    }

    /// Restores a `Box<CoapLendableFfiRcCell<T>>` from a raw pointer.
    ///
    /// Note that unlike [clone_raw_rc_box()], this function does not create a clone but directly
    /// restores the underlying provided box.
    /// As soon as the returned value is dropped, the provided pointer is therefore invalid.
    ///
    /// # Safety
    /// The provided pointer must point to a valid instance of `Box<CoapLendableFfiRcCell<T>`.
    // Kept for consistency
    #[allow(unused)]
    pub unsafe fn from_raw_rc_box(ptr: *mut CoapLendableFfiRcCell<T>) -> Box<CoapLendableFfiRcCell<T>> {
        Box::from_raw(ptr)
    }

    /// Stores a mutable reference to an instance of T for later retrieval by code running on the
    /// other side of the FFI barrier.
    ///
    /// This function can be used to pass a previously borrowed value to other users of this cell
    /// through the FFI barrier _without_ intermittently releasing the borrow.
    ///
    /// The reference will be lent for as long as the returned [CoapLendableFfiRefLender<'a, T>] is
    /// not dropped.
    pub fn lend_ref_mut<'a>(&self, refer: &'a mut T) -> CoapLendableFfiRefLender<'a, T> {
        assert_eq!(
            RefCell::as_ptr(&self.0),
            refer as *mut T,
            "attempted to lend different object over CoapLendableFfiRcCell"
        );
        CoapLendableFfiRefLender::new(refer, &self.1)
    }

    /// Creates a weak version of this reference counted cell by downgrading its components.
    pub fn downgrade(&self) -> CoapLendableFfiWeakCell<T> {
        CoapLendableFfiWeakCell(Rc::downgrade(&self.0), Rc::downgrade(&self.1))
    }
}

impl<T: Debug> Clone for CoapLendableFfiRcCell<T> {
    fn clone(&self) -> Self {
        CoapLendableFfiRcCell(Rc::clone(&self.0), Rc::clone(&self.1))
    }
}

/// The weak variant of a [CoapLendableFfiRcCell].
#[derive(Debug)]
pub(crate) struct CoapLendableFfiWeakCell<T: Debug>(Weak<RefCell<T>>, Weak<RefCell<Option<*mut T>>>);

impl<T: Debug> Clone for CoapLendableFfiWeakCell<T> {
    fn clone(&self) -> Self {
        CoapLendableFfiWeakCell(Weak::clone(&self.0), Weak::clone(&self.1))
    }
}

impl<T: Debug> CoapLendableFfiWeakCell<T> {
    /// Attempts to upgrade this weak cell into a full [CoapLendableFfiRcCell<T>], returning None
    /// if the underlying value was already dropped.
    pub fn upgrade(&self) -> Option<CoapLendableFfiRcCell<T>> {
        self.0
            .upgrade()
            .zip(self.1.upgrade())
            .map(|(v0, v1)| CoapLendableFfiRcCell(v0, v1))
    }

    /// Restores a `Box<CoapLendableFfiWeakCell<T>>` from a raw pointer.
    ///
    /// Note that unlike [CoapLendableFfiRcCell<T>::clone_raw_weak_box()], this function does not
    /// create a clone but directly restores the underlying provided box.
    /// As soon as the returned value is dropped, the provided pointer is therefore invalid.
    ///
    /// # Safety
    /// The provided pointer must point to a valid instance of `Box<CoapLendableFfiWeakCell<T>`.
    pub unsafe fn from_raw_box(ptr: *mut CoapLendableFfiWeakCell<T>) -> Box<CoapLendableFfiWeakCell<T>> {
        Box::from_raw(ptr)
    }
}

/// A token that is held by the lender of a mutable reference.
///
/// As long as this token is held, the mutable reference provided to [CoapLendableFfiRcCell] can be
/// borrowed by other functions owning clones of the same [CoapLendableFfiRcCell].
///
/// When this value is dropped, it will check whether the lent reference is currently used
/// elsewhere and panic/abort if this is the case, as this would violate the Rust aliasing rules.
pub(crate) struct CoapLendableFfiRefLender<'a, T> {
    lent_ref: &'a mut T,
    lent_ptr_ctr: Weak<RefCell<Option<*mut T>>>,
}

impl<'a, T> CoapLendableFfiRefLender<'a, T> {
    /// Create a new lender token from the given reference.
    fn new(refer: &'a mut T, container: &Rc<RefCell<Option<*mut T>>>) -> CoapLendableFfiRefLender<'a, T> {
        RefCell::borrow_mut(container).replace(refer as *mut T);
        CoapLendableFfiRefLender {
            lent_ref: refer,
            lent_ptr_ctr: Rc::downgrade(container),
        }
    }

    pub(crate) fn unlend(self) {
        std::mem::drop(self);
    }
}

impl<T> Drop for CoapLendableFfiRefLender<'_, T> {
    fn drop(&mut self) {
        if let Some(lent_ptr_ctr) = self.lent_ptr_ctr.upgrade() {
            assert_eq!(
                self.lent_ref as *mut T,
                lent_ptr_ctr
                    .take()
                    .expect("unable to retrieve lent reference, implying that it may be in use somewhere"),
                "somehow, multiple references are stored in the same CoapLendableFfiRcCell"
            )
        }
    }
}

/// A non-mutable reference created by borrowing mutably from a [CoapFfiRcCell] using
/// [CoapFfiRcCell::borrow_mut()].
pub(crate) enum CoapLendableFfiRef<'a, T> {
    Owned(Ref<'a, T>),
    Borrowed(&'a mut T, Rc<RefCell<Option<*mut T>>>),
}

impl<T> Deref for CoapLendableFfiRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            CoapLendableFfiRef::Owned(v) => v.deref(),
            CoapLendableFfiRef::Borrowed(v, _lend_container) => v,
        }
    }
}

impl<T> Drop for CoapLendableFfiRef<'_, T> {
    fn drop(&mut self) {
        if let CoapLendableFfiRef::Borrowed(refer, lend_container) = self {
            let mut lend_container = RefCell::borrow_mut(lend_container);
            assert!(
                lend_container.is_none(),
                "somehow, multiple references are stored in the same CoapLendableFfiRcCell"
            );
            assert!(
                lend_container.replace(*refer).is_none(),
                "somehow, multiple references are stored in the same CoapLendableFfiRcCell"
            );
        }
    }
}

/// A mutable reference created by borrowing mutably from a [CoapFfiRcCell] using
/// [CoapFfiRcCell::borrow_mut()].
pub(crate) enum CoapLendableFfiRefMut<'a, T> {
    Owned(RefMut<'a, T>),
    Borrowed(&'a mut T, Rc<RefCell<Option<*mut T>>>),
}

impl<T> Deref for CoapLendableFfiRefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            CoapLendableFfiRefMut::Owned(v) => v.deref(),
            CoapLendableFfiRefMut::Borrowed(v, _lend_container) => v,
        }
    }
}

impl<T> DerefMut for CoapLendableFfiRefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            CoapLendableFfiRefMut::Owned(v) => v.deref_mut(),
            CoapLendableFfiRefMut::Borrowed(v, _lend_container) => v,
        }
    }
}

impl<T> Drop for CoapLendableFfiRefMut<'_, T> {
    fn drop(&mut self) {
        if let CoapLendableFfiRefMut::Borrowed(refer, lend_container) = self {
            let mut lend_container = RefCell::borrow_mut(lend_container);
            assert!(
                lend_container.is_none(),
                "somehow, multiple references are stored in the same CoapLendableFfiRcCell"
            );
            assert!(
                lend_container.replace(*refer).is_none(),
                "somehow, multiple references are stored in the same CoapLendableFfiRcCell"
            );
        }
    }
}

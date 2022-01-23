#![cfg_attr(feature = "nightly", feature(trait_upcasting))]

//! A safe wrapper around the libcoap C library.

pub mod context;
pub mod crypto;
pub mod error;
pub mod message;
pub mod protocol;
pub mod request;
pub mod resource;
pub mod session;
#[cfg(feature = "server")]
pub mod transport;
pub mod types;

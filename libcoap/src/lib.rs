#![cfg_attr(feature = "nightly", feature(trait_upcasting))]

pub mod context;
pub mod crypto;
pub mod error;
mod message;
pub mod protocol;
pub mod request;
pub mod resource;
pub mod session;
#[cfg(feature = "server")]
pub mod transport;
pub mod types;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

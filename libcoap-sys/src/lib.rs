// Bindgen translates the C headers, clippy's and rustfmt's recommendations are not applicable here.
#![allow(clippy::all)]
#![allow(non_camel_case_types)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    /// Test case that creates a basic coap server and makes a request to it from a separate context
    #[test]
    fn test_coap_client_server_basic() {
        //let server_addr = coap_new_server_address();
        //let server_ctx = coap_new_context();
    }
}

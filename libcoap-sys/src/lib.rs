include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {

    /// Test case that replicates both client and server behavior of the libcoap examples.
    #[test]
    fn test_coap_client_server_example() {}
}

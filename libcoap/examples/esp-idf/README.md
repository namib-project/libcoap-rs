This folder contains a slightly modified version of the ESP-IDF Rust project template that can be found
[here](https://github.com/esp-rs/esp-idf-template/tree/master/cargo), with slight modifications to
`sdkconfig.defaults`, `Cargo.toml` and `main.rs` to add support for `libcoap-sys` and `libcoap-rs`.

It is mainly used to test the compilation and binding generation process for ESP-IDF builds of `libcoap-rs`,
but you may also use it as a reference for your own projects.
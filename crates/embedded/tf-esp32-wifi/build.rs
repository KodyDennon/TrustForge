//! ESP-IDF build glue. Delegates to `embuild` which discovers the
//! Espressif toolchain and emits the linker arguments the `ldproxy`
//! runner expects.

fn main() {
    embuild::espidf::sysenv::output();
}

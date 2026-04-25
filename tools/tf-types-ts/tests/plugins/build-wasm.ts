/**
 * Build a minimal hand-crafted WebAssembly module at test time.
 *
 *   (module
 *     (import "env" "log" (func $log (param i32)))
 *     (func (export "run")
 *       i32.const 42
 *       call $log)
 *   )
 *
 * 54 bytes. Returns the raw bytes so the test can write them to disk for
 * PluginRegistry.load().
 */
export function buildTinyWasm(): Uint8Array {
  return new Uint8Array([
    // Magic + version
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,

    // Type section (id=1, size=8): 2 types
    0x01, 0x08, 0x02,
    0x60, 0x01, 0x7f, 0x00,       // (i32) -> void
    0x60, 0x00, 0x00,             // () -> void

    // Import section (id=2, size=11): 1 import
    0x02, 0x0b, 0x01,
    0x03, 0x65, 0x6e, 0x76,       // "env"
    0x03, 0x6c, 0x6f, 0x67,       // "log"
    0x00, 0x00,                   // func, type index 0

    // Function section (id=3, size=2): 1 function with type 1
    0x03, 0x02, 0x01, 0x01,

    // Export section (id=7, size=7): 1 export "run" → func index 1
    0x07, 0x07, 0x01,
    0x03, 0x72, 0x75, 0x6e,       // "run"
    0x00, 0x01,                   // func, index 1

    // Code section (id=10, size=8): 1 body
    0x0a, 0x08, 0x01,
    0x06,                         // body size = 6
    0x00,                         // 0 locals
    0x41, 0x2a,                   // i32.const 42
    0x10, 0x00,                   // call func 0 (imported "log")
    0x0b,                         // end
  ]);
}

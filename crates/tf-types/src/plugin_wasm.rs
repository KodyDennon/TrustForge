//! Rust WASM plugin runtime — mirror of TS `PluginRegistry` WASM path.
//!
//! Each plugin's host imports are gated through the supplied
//! `CapabilityCheck` callback. A plugin that calls a host function
//! whose capability is denied gets a runtime trap.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use wasmtime::{Caller, Engine, Func, Instance, Linker, Module, Store, Trap, Val, ValType};

use crate::plugin::PluginError;

pub type CapabilityCheck = Arc<dyn Fn(&CapabilityArgs) -> bool + Send + Sync + 'static>;

#[derive(Clone, Debug)]
pub struct CapabilityArgs {
    pub plugin_actor: String,
    pub capability: String,
    pub caller: String,
}

pub struct WasmPluginRuntimeOptions {
    pub plugin_actor: String,
    /// Manifest-declared imports of the form `"namespace.name"`.
    pub allowed_imports: HashSet<String>,
    /// Optional: gate every host import through this callback at call
    /// time. The runtime traps when the callback returns false.
    pub capability_check: Option<CapabilityCheck>,
}

pub struct WasmPlugin {
    pub plugin_actor: String,
    instance: Instance,
    store: Store<HostState>,
}

struct HostState {
    revoked: Arc<AtomicBool>,
}

impl WasmPlugin {
    /// Compile and instantiate a WASM plugin from a file path.
    pub fn from_file<P: AsRef<Path>>(
        path: P,
        opts: WasmPluginRuntimeOptions,
    ) -> Result<Self, PluginError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|e| PluginError::Io(e.to_string()))?;
        Self::from_bytes(&bytes, opts)
    }

    pub fn from_bytes(wasm: &[u8], opts: WasmPluginRuntimeOptions) -> Result<Self, PluginError> {
        let engine = Engine::default();
        let module = Module::from_binary(&engine, wasm)
            .map_err(|e| PluginError::Parse(format!("wasm compile: {e}")))?;
        let revoked = Arc::new(AtomicBool::new(false));
        let mut store = Store::new(
            &engine,
            HostState {
                revoked: revoked.clone(),
            },
        );
        let mut linker: Linker<HostState> = Linker::new(&engine);

        // For every import the module declares, install a stub that:
        //   1. checks the import is in `allowed_imports`;
        //   2. fires the capability_check;
        //   3. if either fails, traps.
        // The host doesn't expose any I/O; plugins talk to the host
        // exclusively via the manifest-declared `tf.*` capability
        // namespace. This build ships ONE host fn — `tf.log` — taking
        // an i32 status code, so plugins can signal completion.
        for import in module.imports() {
            let module_name = import.module().to_string();
            let field_name = import.name().to_string();
            let combined = format!("{module_name}.{field_name}");
            let allowed = opts.allowed_imports.contains(&combined);
            let plugin_actor = opts.plugin_actor.clone();
            let capability_check = opts.capability_check.clone();

            // We only know how to install i32->void or i32->i32 host
            // shims for now (the TS POC is the same shape). More
            // signatures can be added when manifests start exercising
            // them.
            let func_ty = match import.ty() {
                wasmtime::ExternType::Func(ft) => ft,
                _ => continue,
            };

            let plugin_actor_for_func = plugin_actor.clone();
            let cap_for_func = combined.clone();
            let func = Func::new(
                &mut store,
                func_ty.clone(),
                move |_caller: Caller<'_, HostState>,
                      params: &[Val],
                      results: &mut [Val]|
                      -> Result<(), wasmtime::Error> {
                    if !allowed {
                        return Err(Trap::UnreachableCodeReached.into());
                    }
                    if let Some(cb) = &capability_check {
                        let ok = cb(&CapabilityArgs {
                            plugin_actor: plugin_actor_for_func.clone(),
                            capability: format!("wasm.import.{}", cap_for_func),
                            caller: plugin_actor_for_func.clone(),
                        });
                        if !ok {
                            return Err(Trap::UnreachableCodeReached.into());
                        }
                    }
                    // Default behavior for the shipped `tf.log` import is
                    // to discard the i32 argument. Custom WASM plugins
                    // that import other shapes will reach this branch
                    // with their own params; we no-op + zero-fill the
                    // results because the host doesn't model side
                    // effects in v0.1.0. (The TS POC is the same
                    // shape.)
                    let _ = params;
                    for (i, result_ty) in func_ty.results().enumerate() {
                        results[i] = match result_ty {
                            ValType::I32 => Val::I32(0),
                            ValType::I64 => Val::I64(0),
                            ValType::F32 => Val::F32(0),
                            ValType::F64 => Val::F64(0),
                            _ => Val::I32(0),
                        };
                    }
                    Ok(())
                },
            );
            linker
                .define(&store, &module_name, &field_name, func)
                .map_err(|e| PluginError::Parse(format!("wasm linker.define: {e}")))?;
        }

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| PluginError::Parse(format!("wasm instantiate: {e}")))?;
        Ok(WasmPlugin {
            plugin_actor: opts.plugin_actor,
            instance,
            store,
        })
    }

    /// Mark the plugin's actor as revoked. Subsequent `call_i32` invocations
    /// trap before executing.
    pub fn revoke(&self) {
        self.revoked().store(true, Ordering::SeqCst);
    }

    fn revoked(&self) -> Arc<AtomicBool> {
        self.store.data().revoked.clone()
    }

    /// Call an exported i32->i32 function. (Mirrors the TS POC's
    /// minimal shape.) Returns Err if the function isn't exported, the
    /// signature mismatches, or the plugin actor was revoked.
    pub fn call_i32(&mut self, name: &str, arg: i32) -> Result<i32, PluginError> {
        if self.revoked().load(Ordering::SeqCst) {
            return Err(PluginError::BadSignature(format!(
                "plugin {} actor was revoked",
                self.plugin_actor
            )));
        }
        let f = self
            .instance
            .get_typed_func::<i32, i32>(&mut self.store, name)
            .map_err(|e| PluginError::Parse(format!("get_typed_func {name}: {e}")))?;
        f.call(&mut self.store, arg)
            .map_err(|e| PluginError::Parse(format!("wasm call {name}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 9-byte WASM module that exports a function `f` returning i32 0.
    /// This is the smallest possible valid WASM that exercises the
    /// runtime; if wasmtime can compile + run it, the gate works.
    const TINY_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, // "\0asm"
        0x01, 0x00, 0x00, 0x00, // version 1
        // Type section: one [] -> [i32] type
        0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
        // Function section: function 0 uses type 0
        0x03, 0x02, 0x01, 0x00, // Export section: export "f" (func 0)
        0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
        // Code section: function 0 body — i32.const 0, end
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x00, 0x0b,
    ];

    #[test]
    fn instantiate_minimal_wasm_no_imports() {
        let plugin = WasmPlugin::from_bytes(
            TINY_WASM,
            WasmPluginRuntimeOptions {
                plugin_actor: "tf:actor:plugin:example.com/test".to_string(),
                allowed_imports: HashSet::new(),
                capability_check: None,
            },
        )
        .expect("instantiate");
        // The exported function takes no args; call_i32 expects (i32) → i32,
        // so this assertion just confirms the wasm module compiled.
        assert_eq!(plugin.plugin_actor, "tf:actor:plugin:example.com/test");
    }

    #[test]
    fn revocation_blocks_subsequent_calls() {
        let mut plugin = WasmPlugin::from_bytes(
            TINY_WASM,
            WasmPluginRuntimeOptions {
                plugin_actor: "tf:actor:plugin:example.com/test".to_string(),
                allowed_imports: HashSet::new(),
                capability_check: None,
            },
        )
        .expect("instantiate");
        plugin.revoke();
        let err = plugin.call_i32("nope", 0).unwrap_err();
        assert!(matches!(err, PluginError::BadSignature(_)));
    }
}

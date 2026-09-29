use std::collections::BTreeSet;

use crate::errors::{VmError, VmResult};
use crate::parsed_wasm::ParsedWasm;
use crate::wasm_backend::engine::make_compiling_engine;
use crate::Size;
use nam_wasm_instrument::parity_wasm::elements::{ImportCountType, Module as PModule};
use nam_wasm_instrument::parity_wasm::{deserialize_buffer, serialize};
use nam_wasm_instrument::inject_stack_limiter;
use wasmer::{Engine, Module};

/// Operand-stack budget, in values.
///
/// Cost of a function is its local count plus its maximum operand-stack
/// height. 4096 is under the native guard for a wide frame on aarch64.
pub const MAX_WASM_STACK_HEIGHT: u32 = 4096;

/// Compiles Wasm bytecode into a module using the given engine.
///
/// The bytes are rewritten with a stack-height counter before Wasmer sees
/// them. Host imports are exempt: they have no body to meter.
pub fn compile(engine: &Engine, code: &[u8]) -> VmResult<Module> {
    let limited = limit_stack_height(code)?;
    let module = Module::new(engine, &limited)?;
    Ok(module)
}

fn limit_stack_height(code: &[u8]) -> VmResult<Vec<u8>> {
    let parsed: PModule = deserialize_buffer(code)
        .map_err(|e| VmError::static_validation_err(format!("stack-limiter deserialize: {e}")))?;
    let func_imports = parsed.import_count(ImportCountType::Function) as u32;
    let exempt: BTreeSet<u32> = (0..func_imports).collect();
    let limited = inject_stack_limiter(parsed, MAX_WASM_STACK_HEIGHT, &exempt)
        .map_err(|e| VmError::static_validation_err(format!("stack-limiter inject: {e}")))?;
    serialize(limited)
        .map_err(|e| VmError::compile_err(format!("stack-limiter serialize: {e}")))
}

/// Compiles a given Wasm byte code into a module using compiling engine.
pub fn compile_module(wasm: &[u8], memory_limit: Option<Size>) -> VmResult<(Module, Engine)> {
    let parsed_wasm = ParsedWasm::parse(wasm)?;
    let engine = make_compiling_engine(memory_limit, Some(parsed_wasm));
    let module = compile(&engine, wasm)?;
    Ok((module, engine))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmer::{imports, Instance, Store};

    static FLOATY: &[u8] = include_bytes!("../../testdata/floaty.wasm");
    static WIDE_STACK: &str = include_str!("../../testdata/wide_operand_stack.wat");
    static BULK: &str = include_str!("../../testdata/bulk_memory.wat");
    static SIMD_TRUNC: &str = include_str!("../../testdata/simd_trunc_sat.wat");
    static BLAKE3_GUEST: &str = include_str!("../../testdata/blake3_simd_guest.wat");
    static BULK_RUSTC: &[u8] = include_bytes!("../../testdata/bulk_copy_rustc.wasm");

    /// No stack-height rewrite. One function with a 5000-deep operand stack
    /// hits the native guard. `compile` is what rejects it.
    #[test]
    fn wide_operand_stack_hits_native_guard_without_limiter() {
        let wasm = wat::parse_str(WIDE_STACK).unwrap();
        let engine = make_compiling_engine(None, None);
        let mut store = Store::new(engine);
        let module = Module::new(&store, &wasm).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        instance
            .exports
            .get_function("blow")
            .unwrap()
            .call(&mut store, &[])
            .expect_err("native guard");
    }

    #[test]
    fn wide_operand_stack_trips_stack_height_limiter() {
        let wasm = wat::parse_str(WIDE_STACK).unwrap();
        let engine = make_compiling_engine(None, None);
        let module = compile(&engine, &wasm).unwrap();
        let mut store = Store::new(engine);
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let err = instance
            .exports
            .get_function("blow")
            .unwrap()
            .call(&mut store, &[])
            .expect_err("stack height 5000 is over 4096");
        let text = err.to_string();
        assert!(
            text.contains("unreachable") || text.contains("trap") || text.contains("Runtime"),
            "{text}"
        );
    }

    #[test]
    fn contract_with_floats_passes_check() {
        let parsed_wasm = ParsedWasm::parse(FLOATY).unwrap();
        let engine = make_compiling_engine(None, Some(parsed_wasm));
        assert!(compile(&engine, FLOATY).is_ok());
    }

    #[test]
    fn reference_types_dont_panic() {
        const WASM: &str = r#"(module
            (type $t0 (func (param funcref externref)))
            (import "" "" (func $hello (type $t0)))
        )"#;

        let wasm = wat::parse_str(WASM).unwrap();
        let engine = make_compiling_engine(None, None);
        let error = compile(&engine, &wasm).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("FuncRef") || text.contains("value type"),
            "{text}"
        );
    }

    /// 0xFC (memory.copy) is decoded by the limiter and allowed by the
    /// gatekeeper. Singlepass then emits a libcall; this checks the module
    /// is accepted, which is the compile gate contracts hit.
    #[test]
    fn bulk_memory_copy_passes_limiter() {
        let wasm = wat::parse_str(BULK).unwrap();
        assert!(
            wasm.windows(2).any(|w| w == [0xfc, 0x0a]),
            "wat did not emit memory.copy"
        );
        let engine = make_compiling_engine(None, None);
        compile(&engine, &wasm).expect("memory.copy");
    }

    /// 0xFD 0xFC is i32x4.trunc_sat_f64x2_s_zero. The limiter must decode it.
    /// The gatekeeper then refuses guest SIMD. The error is not a parse failure.
    #[test]
    fn simd_trunc_sat_is_decoded_then_rejected_by_gatekeeper() {
        let wasm = wat::parse_str(SIMD_TRUNC).unwrap();
        assert!(
            wasm.windows(2).any(|w| w == [0xfd, 0xfc]),
            "wat did not emit 0xFD 0xFC"
        );
        let engine = make_compiling_engine(None, None);
        let error = compile(&engine, &wasm).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("SIMD"),
            "{text}"
        );
        assert!(
            !text.contains("Unknown opcode"),
            "{text}"
        );
    }

    fn limited_wasm(wasm: &[u8]) -> Vec<u8> {
        use nam_wasm_instrument::parity_wasm::elements::{ImportCountType, Module as PModule};
        let parsed: PModule = nam_wasm_instrument::parity_wasm::deserialize_buffer(wasm).unwrap();
        let n_import = parsed.import_count(ImportCountType::Function) as u32;
        let exempt: std::collections::BTreeSet<u32> = (0..n_import).collect();
        let limited = nam_wasm_instrument::inject_stack_limiter(
            parsed,
            MAX_WASM_STACK_HEIGHT,
            &exempt,
        )
        .unwrap();
        nam_wasm_instrument::parity_wasm::serialize(limited).unwrap()
    }

    #[test]
    fn rustc_bulk_guest_passes_limiter() {
        let engine = make_compiling_engine(None, None);
        compile(&engine, BULK_RUSTC).expect("rustc memory.copy guest");
    }

    #[test]
    fn bulk_memory_copy_executes() {
        // memory.copy's metered base is 4_500_000. Stay above that.
        let wasm = limited_wasm(&wat::parse_str(BULK).unwrap());
        let engine = crate::wasm_backend::make_compiling_engine_with_gas(20_000_000);
        let mut store = Store::new(engine);
        let module = Module::new(&store, &wasm).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let got = instance
            .exports
            .get_function("go")
            .unwrap()
            .call(&mut store, &[])
            .unwrap();
        assert_eq!(got[0].unwrap_i32(), 0x11);
    }

    /// Guest calls env.blake3_256 the way cosmwasm-std does, and the module
    /// also contains memory.copy plus i32x4.trunc_sat_f64x2_s_zero.
    #[test]
    fn blake3_host_api_accepts_simd_guest() {
        use wasmer::{Function, FunctionEnv, FunctionEnvMut, Memory};

        struct Host {
            memory: Option<Memory>,
        }

        fn read_region(view: &wasmer::MemoryView, ptr: u32) -> (u32, u32) {
            let mut buf = [0u8; 12];
            view.read(ptr as u64, &mut buf).unwrap();
            let offset = u32::from_le_bytes(buf[0..4].try_into().unwrap());
            let length = u32::from_le_bytes(buf[8..12].try_into().unwrap());
            (offset, length)
        }

        let wasm = limited_wasm(&wat::parse_str(BLAKE3_GUEST).unwrap());
        let engine = crate::wasm_backend::make_compiling_engine_with_gas(100_000);
        let mut store = Store::new(engine);
        let module = Module::new(&store, &wasm).unwrap();
        let host = FunctionEnv::new(&mut store, Host { memory: None });
        let blake3 = Function::new_typed_with_env(
            &mut store,
            &host,
            |mut env: FunctionEnvMut<Host>, in_ptr: i32, out_ptr: i32| -> i32 {
                let (data, store) = env.data_and_store_mut();
                let Some(memory) = data.memory.as_ref() else {
                    return 2;
                };
                let view = memory.view(&store);
                let (in_off, in_len) = read_region(&view, in_ptr as u32);
                let mut msg = vec![0u8; in_len as usize];
                if view.read(in_off as u64, &mut msg).is_err() {
                    return 3;
                }
                let digest = cosmwasm_crypto::blake3_256(&msg);
                let (out_off, out_len) = read_region(&view, out_ptr as u32);
                if out_len != 32 || view.write(out_off as u64, &digest).is_err() {
                    return 4;
                }
                0
            },
        );
        let mut imports = imports! {};
        imports.define("env", "blake3_256", blake3);
        let instance = Instance::new(&mut store, &module, &imports).unwrap();
        host.as_mut(&mut store).memory = Some(instance.exports.get_memory("memory").unwrap().clone());
        let ping = instance
            .exports
            .get_function("ping")
            .unwrap()
            .call(&mut store, &[])
            .expect("ping")[0]
            .unwrap_i32();
        assert_eq!(ping, 7);
        let code = instance
            .exports
            .get_function("hash")
            .unwrap()
            .call(&mut store, &[])
            .unwrap()[0]
            .unwrap_i32();
        assert_eq!(code, 0);
        let memory = instance.exports.get_memory("memory").unwrap();
        let mut got = [0u8; 32];
        memory.view(&store).read(200, &mut got).unwrap();
        assert_eq!(got, cosmwasm_crypto::blake3_256(b"terp"));
    }
}

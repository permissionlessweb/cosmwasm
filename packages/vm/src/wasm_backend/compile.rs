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
        assert!(error.to_string().contains("FuncRef"));
    }
}

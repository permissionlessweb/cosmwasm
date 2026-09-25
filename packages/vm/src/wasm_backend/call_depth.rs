//! Logical Wasm call depth.
//!
//! Wasmer 5.0.6 Singlepass inserts `TrapCode::StackOverflow` by comparing the
//! native stack pointer. That frame size differs between x86_64 and aarch64,
//! so it is not a consensus rule. This middleware counts Wasm function
//! activations in a global. Gas is unchanged. The native trap stays as a
//! process backstop and must be unreachable for any execution under the cap.
//!
//! `MAX_WASM_CALL_DEPTH` includes the exported entry. 1024 activations succeed.
//! 1025 traps with [`crate::errors::VmError::CallDepthExceeded`] on every arch.

use std::sync::Mutex;

use wasmer::wasmparser::Operator;
use wasmer::{
    ExportIndex, FunctionMiddleware, GlobalInit, GlobalType, LocalFunctionIndex, MiddlewareError,
    MiddlewareReaderState, ModuleMiddleware, Mutability, Type,
};
use wasmer_types::{GlobalIndex, ModuleInfo};

/// Maximum Wasm function activations on one stack, including the export.
pub const MAX_WASM_CALL_DEPTH: i32 = 1024;

pub const CALL_DEPTH_EXCEEDED_GLOBAL: &str = "cosmwasm_call_depth_exceeded";

#[derive(Debug)]
struct Indexes {
    depth: GlobalIndex,
    exceeded: GlobalIndex,
}

#[derive(Debug)]
pub struct CallDepth {
    max: i32,
    indexes: Mutex<Option<Indexes>>,
}

impl CallDepth {
    pub fn new(max: i32) -> Self {
        Self {
            max,
            indexes: Mutex::new(None),
        }
    }
}

impl ModuleMiddleware for CallDepth {
    fn generate_function_middleware(
        &self,
        _: LocalFunctionIndex,
    ) -> Box<dyn FunctionMiddleware> {
        Box::new(FunctionCallDepth {
            first: true,
            control: 0,
            max: self.max,
            indexes: self
                .indexes
                .lock()
                .unwrap()
                .as_ref()
                .expect("CallDepth::transform_module_info must run first")
                .clone_idx(),
        })
    }

    fn transform_module_info(&self, module_info: &mut ModuleInfo) -> Result<(), MiddlewareError> {
        let mut slot = self.indexes.lock().unwrap();
        if slot.is_some() {
            panic!("CallDepth middleware used for more than one module");
        }
        let depth = module_info
            .globals
            .push(GlobalType::new(Type::I32, Mutability::Var));
        module_info
            .global_initializers
            .push(GlobalInit::I32Const(0));
        let exceeded = module_info
            .globals
            .push(GlobalType::new(Type::I32, Mutability::Var));
        module_info
            .global_initializers
            .push(GlobalInit::I32Const(0));
        module_info.exports.insert(
            CALL_DEPTH_EXCEEDED_GLOBAL.to_string(),
            ExportIndex::Global(exceeded),
        );
        *slot = Some(Indexes { depth, exceeded });
        Ok(())
    }
}

impl Indexes {
    fn clone_idx(&self) -> (u32, u32) {
        (self.depth.as_u32(), self.exceeded.as_u32())
    }
}

struct FunctionCallDepth {
    first: bool,
    /// Open `block` / `loop` / `if` / `try` bodies. Zero means the next `end`
    /// closes the function.
    control: u32,
    max: i32,
    indexes: (u32, u32),
}

impl std::fmt::Debug for FunctionCallDepth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionCallDepth")
            .field("control", &self.control)
            .field("max", &self.max)
            .finish()
    }
}

impl FunctionMiddleware for FunctionCallDepth {
    fn feed<'a>(
        &mut self,
        operator: Operator<'a>,
        state: &mut MiddlewareReaderState<'a>,
    ) -> Result<(), MiddlewareError> {
        if self.first {
            state.extend(enter_frame(self.indexes, self.max));
            self.first = false;
        }
        match &operator {
            Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
            | Operator::Try { .. }
            | Operator::TryTable { .. } => self.control = self.control.saturating_add(1),
            Operator::End => {
                if self.control == 0 {
                    state.extend(leave_frame(self.indexes.0));
                } else {
                    self.control -= 1;
                }
            }
            Operator::Return | Operator::ReturnCall { .. } | Operator::ReturnCallIndirect { .. } => {
                state.extend(leave_frame(self.indexes.0));
            }
            _ => {}
        }
        state.push_operator(operator);
        Ok(())
    }
}

fn enter_frame<'a>(indexes: (u32, u32), max: i32) -> [Operator<'a>; 15] {
    let (depth, exceeded) = indexes;
    [
        Operator::GlobalGet { global_index: depth },
        Operator::I32Const { value: 1 },
        Operator::I32Add,
        Operator::GlobalSet { global_index: depth },
        Operator::GlobalGet { global_index: depth },
        Operator::I32Const { value: max },
        Operator::I32GtU,
        Operator::If {
            blockty: wasmer::wasmparser::BlockType::Empty,
        },
        Operator::I32Const { value: 1 },
        Operator::GlobalSet {
            global_index: exceeded,
        },
        Operator::Unreachable,
        Operator::End,
        Operator::Nop,
        Operator::Nop,
        Operator::Nop,
    ]
}

fn leave_frame<'a>(depth: u32) -> [Operator<'a>; 4] {
    [
        Operator::GlobalGet { global_index: depth },
        Operator::I32Const { value: 1 },
        Operator::I32Sub,
        Operator::GlobalSet { global_index: depth },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wasmer::{imports, CompilerConfig, Instance, Module, Store, Value};

    fn engine(max: i32) -> wasmer::Engine {
        let mut compiler = wasmer::Singlepass::new();
        compiler.push_middleware(Arc::new(CallDepth::new(max)));
        compiler.into()
    }

    /// `packages/vm/testdata/call_depth_recurse.wat`: go(n) places n activations
    /// on the stack, including the export.
    fn recurse_wat() -> &'static str {
        include_str!("../../testdata/call_depth_recurse.wat")
    }

    fn call_go(max: i32, n: i32) -> Result<(), String> {
        let mut store = Store::new(engine(max));
        let wasm = wat::parse_str(recurse_wat()).map_err(|e| e.to_string())?;
        let module = Module::new(&store, wasm).map_err(|e| e.to_string())?;
        let instance = Instance::new(&mut store, &module, &imports! {}).map_err(|e| e.to_string())?;
        let go = instance
            .exports
            .get_function("go")
            .map_err(|e| e.to_string())?;
        match go.call(&mut store, &[Value::I32(n)]) {
            Ok(_) => Ok(()),
            Err(err) => {
                let flag = instance
                    .exports
                    .get_global(CALL_DEPTH_EXCEEDED_GLOBAL)
                    .ok()
                    .map(|g| g.get(&mut store));
                Err(format!("{err}; flag={flag:?}"))
            }
        }
    }

    #[test]
    fn call_depth_recurse_contract_max_boundary() {
        // Smaller than production 1024 so the test stays fast. The contract
        // and the trap are the same ones production uses.
        const MAX: i32 = 64;
        call_go(MAX, MAX - 1).expect("MAX-1");
        call_go(MAX, MAX).expect("MAX");
        let err = call_go(MAX, MAX + 1).expect_err("MAX+1");
        assert!(
            err.contains("I32(1)"),
            "trap must set the depth flag, got {err}"
        );
    }
}

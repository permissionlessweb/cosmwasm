//! Derive macros for cosmwasm-vm. For internal use only. No stability guarantees.
//!
//! CosmWasm is a smart contract platform for the Cosmos ecosystem.
//! For more information, see: <https://cosmwasm.cosmos.network>

mod code_generators;
mod cosmwasm_circuit;
mod hash_function;
mod parsers;
mod validators;

#[cfg(test)]
mod tests;

macro_rules! maybe {
    ($result:expr) => {{
        match { $result } {
            Ok(val) => val,
            Err(err) => return err.into_compile_error(),
        }
    }};
}
use maybe;

/// Hash the function
///
/// # Example
///
/// ```rust
/// # use cosmwasm_vm_derive::hash_function;
/// #[hash_function(const_name = "HASH")]
/// fn foo() {
///     println!("Hello, world!");
/// }
/// ```
#[proc_macro_attribute]
pub fn hash_function(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    hash_function::hash_function_impl(attr.into(), item.into()).into()
}

/// Derive macro for CosmWasm-compatible Halo2 circuits
///
/// # Attributes
/// - `k`: Circuit size parameter (11-20)
/// - `instances`: Number of public inputs (1-255)
/// - `circuit_type`: Optional circuit type identifier (default: "Generic")
///
/// # Example
/// ```ignore
/// #[cosmwasm_circuit(k = 17, instances = 4)]
/// pub struct MyCircuit {
///     secret: Option<vesta::Scalar>,
/// }
///
/// impl Circuit<vesta::Scalar> for MyCircuit {
///     // ... standard halo2 implementation ...
/// }
/// ```
///
/// # Generated Code
/// The macro automatically generates:
/// - Implementation of `CosmwasmCircuitFor<T>` trait
/// - Helper methods: `circuit_metadata()`, `verifying_key()`, `instance_count()`, `k_parameter()`, `is_compatible()`
/// - Constants containing metadata for compile-time access
#[proc_macro_attribute]
pub fn cosmwasm_circuit(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    cosmwasm_circuit::cosmwasm_circuit_impl(attr.into(), item.into())
        .unwrap_or_else(|err| err)
        .into()
}

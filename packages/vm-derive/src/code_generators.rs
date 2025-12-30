use proc_macro2::TokenStream;
use quote::quote;

use crate::parsers::CircuitAttributes;

/// Generates Rust code for a circuit based on its attributes
pub struct CodeGenerator {
    circuit_name: syn::Ident,
    attrs: CircuitAttributes,
}

impl CodeGenerator {
    /// Create a new code generator
    pub fn new(circuit_name: syn::Ident, attrs: CircuitAttributes) -> Self {
        CodeGenerator {
            circuit_name,
            attrs,
        }
    }

    /// Generate the complete macro implementation
    pub fn generate(&self) -> TokenStream {
        let trait_impl = self.generate_trait_impl();
        let constants = self.generate_constants();

        quote! {
            #trait_impl
            #constants
        }
    }

    /// Generate CosmwasmCircuitFor<T> trait implementation
    fn generate_trait_impl(&self) -> TokenStream {
        let circuit_name = &self.circuit_name;
        let k = self.attrs.k;
        let instances = self.attrs.instances;
        let circuit_type_byte = self.circuit_type_to_u8(&self.attrs.circuit_type);

        quote! {
            /// Automatically generated trait implementation for CosmWasm circuit compatibility
            impl cosmwasm_vm::zk::CosmwasmCircuitFor<#circuit_name> {
                /// Get metadata about this circuit
                pub fn circuit_metadata() -> cosmwasm_vm::zk::CircuitMetadata {
                    cosmwasm_vm::zk::CircuitMetadata {
                        circuit_type: cosmwasm_vm::zk::CircuitType::from_u8(#circuit_type_byte)
                            .expect("Valid circuit type"),
                        instances: #instances,
                        k: #k,
                        name: stringify!(#circuit_name),
                    }
                }

                /// Build the verifying key for this circuit
                pub fn verifying_key() -> cosmwasm_vm::zk::VerifyingKey {
                    let circuit = #circuit_name::without_witnesses(&Self {
                        /* circuit will be instantiated by user impl */
                    });
                    cosmwasm_vm::zk::VerifyingKey::build(circuit, #k, #instances as usize)
                }

                /// Get the circuit type byte for serialization
                pub fn circuit_type() -> cosmwasm_vm::zk::CircuitType {
                    cosmwasm_vm::zk::CircuitType::from_u8(#circuit_type_byte)
                        .expect("Valid circuit type")
                }

                /// Get the instance count
                pub fn instance_count() -> u8 {
                    #instances
                }

                /// Get the k parameter
                pub fn k_parameter() -> u32 {
                    #k
                }

                /// Validate instance compatibility
                pub fn is_compatible(instances: &[pasta_curves::vesta::Scalar]) -> bool {
                    instances.len() == #instances as usize
                }
            }
        }
    }

    /// Generate compile-time constants
    fn generate_constants(&self) -> TokenStream {
        let circuit_name = &self.circuit_name;
        let const_name = format!("{}_METADATA", circuit_name.to_string().to_uppercase());
        let const_ident = syn::Ident::new(&const_name, circuit_name.span());

        let k = self.attrs.k;
        let instances = self.attrs.instances;

        quote! {
            /// Circuit metadata available at compile time
            pub const #const_ident: cosmwasm_vm::zk::CircuitMetadata = cosmwasm_vm::zk::CircuitMetadata {
                circuit_type: cosmwasm_vm::zk::CircuitType::Generic,
                instances: #instances,
                k: #k,
                name: stringify!(#circuit_name),
            };
        }
    }

    /// Convert circuit type string to u8
    fn circuit_type_to_u8(&self, circuit_type: &str) -> u8 {
        match circuit_type {
            "Generic" => 0x00,
            _ => 0x00, // Default fallback
        }
    }
}

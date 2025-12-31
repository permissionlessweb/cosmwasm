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

        let i = self.attrs.i;
        let ct_byte = self.ct_to_u8(&self.attrs.ct);

        quote! {
            /// Automatically generated trait implementation for CosmWasm circuit compatibility
            impl cosmwasm_vm::zk::CosmwasmCircuitFor<#circuit_name> {
                /// Get metadata about this circuit
                pub fn circuit_metadata() -> cosmwasm_vm::zk::PlonkishCircuitMetadata {
                    cosmwasm_vm::zk::PlonkishCircuitMetadata {
                        ct: cosmwasm_vm::zk::CircuitType::from_u8(#ct_byte)
                            .expect("Valid circuit type"),
                        i: #i,

                        name: stringify!(#circuit_name),
                    }
                }

                /// Build the verifying key for this circuit
                pub fn verifying_key() -> cosmwasm_vm::zk::VerifyingKey {
                    let circuit = #circuit_name::without_witnesses(&Self {
                        /* circuit will be instantiated by user impl */
                    });
                    cosmwasm_vm::zk::VerifyingKey::build(circuit, #i as usize)
                }

                /// Get the circuit type byte for serialization
                pub fn ct() -> cosmwasm_vm::zk::CircuitType {
                    cosmwasm_vm::zk::CircuitType::from_u8(#ct_byte)
                        .expect("Valid circuit type")
                }

                /// Get the instance count
                pub fn instance_count() -> u8 {
                    #i
                }

                /// Validate instance compatibility
                pub fn is_compatible(i: &[pasta_curves::vesta::Scalar]) -> bool {
                    i.len() == #i as usize
                }
            }
        }
    }

    /// Generate compile-time constants
    fn generate_constants(&self) -> TokenStream {
        let circuit_name = &self.circuit_name;
        let const_name = format!("{}_METADATA", circuit_name.to_string().to_uppercase());
        let const_ident = syn::Ident::new(&const_name, circuit_name.span());

        let i = self.attrs.i;

        quote! {
            /// Circuit metadata available at compile time
            pub const #const_ident: cosmwasm_vm::zk::PlonkishCircuitMetadata = cosmwasm_vm::zk::PlonkishCircuitMetadata {
                ct: cosmwasm_vm::zk::CircuitType::Plonkish,
                i: #i,
                // name: stringify!(#circuit_name),
            };
        }
    }

    /// Convert circuit type string to u8
    fn ct_to_u8(&self, ct: &str) -> u8 {
        match ct {
            "Generic" => 0x00,
            _ => 0x00, // Default fallback
        }
    }
}

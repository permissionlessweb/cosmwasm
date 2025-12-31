use proc_macro2::Span;
use syn::Error;

use crate::parsers::CircuitAttributes;

/// Validation result containing any errors that occurred
#[derive(Debug)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<Error>,
}

impl ValidationResult {
    /// Create a new valid validation result
    pub fn new() -> Self {
        ValidationResult {
            is_valid: true,
            errors: Vec::new(),
        }
    }

    /// Add an error to the validation result
    pub fn add_error(&mut self, error: Error) {
        self.is_valid = false;
        self.errors.push(error);
    }

    /// Convert all errors into a single compile error TokenStream
    pub fn to_compile_error(&self) -> proc_macro2::TokenStream {
        self.errors
            .iter()
            .fold(proc_macro2::TokenStream::new(), |mut acc, err| {
                acc.extend(err.to_compile_error());
                acc
            })
    }
}

/// Validate circuit attributes against semantic constraints
pub fn validate_attributes(attrs: &CircuitAttributes, span: Span) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Validate instances: must be in range [1, 255]
    if attrs.i == 0 || attrs.i > 255 {
        result.add_error(Error::new(
            span,
            format!("Instance count must be in range [1, 255], got {}", attrs.i),
        ));
    }

    // Validate circuit type
    if !is_valid_ct(&attrs.ct) {
        result.add_error(Error::new(
            span,
            format!("Unknown circuit type '{}'. Valid types: Generic", attrs.ct),
        ));
    }

    result
}

/// Check if a circuit type string is valid
fn is_valid_ct(ct: &str) -> bool {
    matches!(ct, "Generic")
}

/// Verify that the struct can be used as a circuit
pub fn validate_circuit_struct(input: &syn::DeriveInput) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check that it's a struct
    match input {
        syn::DeriveInput {
            data: syn::Data::Struct(_),
            ..
        } => {
            // Valid struct
        }
        _ => {
            result.add_error(Error::new_spanned(
                input,
                "#[cosmwasm_circuit] can only be applied to structs",
            ));
        }
    }

    result
}

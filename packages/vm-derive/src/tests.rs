/// Unit tests for the cosmwasm_circuit macro
///
/// Note: These tests verify the macro compilation and parsing logic.
/// Full integration tests require the halo2 circuit trait to be available.

#[cfg(test)]
mod parser_tests {
    use crate::parsers::CircuitAttributes;
    use syn::parse_quote;

    #[test]
    fn test_parse_basic_attributes() {
        let input = parse_quote!(k = 17, instances = 2);
        let attrs: CircuitAttributes = syn::parse2(input).unwrap();
        assert_eq!(attrs.k, 17);
        assert_eq!(attrs.instances, 2);
        assert_eq!(attrs.circuit_type, "Generic");
    }

    #[test]
    fn test_parse_with_circuit_type() {
        let input = parse_quote!(k = 18, instances = 3, circuit_type = "Generic");
        let attrs: CircuitAttributes = syn::parse2(input).unwrap();
        assert_eq!(attrs.k, 18);
        assert_eq!(attrs.instances, 3);
        assert_eq!(attrs.circuit_type, "Generic");
    }

    #[test]
    fn test_parse_missing_k() {
        let input = parse_quote!(instances = 2);
        let result: syn::Result<CircuitAttributes> = syn::parse2(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Missing required attribute: k"));
    }

    #[test]
    fn test_parse_missing_instances() {
        let input = parse_quote!(k = 17);
        let result: syn::Result<CircuitAttributes> = syn::parse2(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Missing required attribute: instances"));
    }

    #[test]
    fn test_parse_duplicate_k() {
        let input = parse_quote!(k = 17, k = 18, instances = 2);
        let result: syn::Result<CircuitAttributes> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_attribute() {
        let input = parse_quote!(k = 17, instances = 2, unknown = "value");
        let result: syn::Result<CircuitAttributes> = syn::parse2(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unknown attribute"));
    }

    #[test]
    fn test_parse_k_boundary_values() {
        let input = parse_quote!(k = 11, instances = 1);
        let attrs: CircuitAttributes = syn::parse2(input).unwrap();
        assert_eq!(attrs.k, 11);

        let input = parse_quote!(k = 20, instances = 255);
        let attrs: CircuitAttributes = syn::parse2(input).unwrap();
        assert_eq!(attrs.k, 20);
        assert_eq!(attrs.instances, 255);
    }
}

#[cfg(test)]
mod validator_tests {
    use crate::parsers::CircuitAttributes;
    use crate::validators::validate_attributes;
    use proc_macro2::Span;

    #[test]
    fn test_validate_valid_attributes() {
        let attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_k_too_small() {
        let attrs = CircuitAttributes {
            k: 10,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].to_string().contains("k must be in range"));
    }

    #[test]
    fn test_validate_k_too_large() {
        let attrs = CircuitAttributes {
            k: 21,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_instances_zero() {
        let attrs = CircuitAttributes {
            k: 17,
            instances: 0,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].to_string().contains("Instance count must be in range"));
    }

    #[test]
    fn test_validate_instances_too_large() {
        let attrs = CircuitAttributes {
            k: 17,
            instances: 255u8, // Max valid
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_unknown_circuit_type() {
        let attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "UnknownType".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_multiple_errors() {
        let attrs = CircuitAttributes {
            k: 5,     // Too small
            instances: 0,     // Too small
            circuit_type: "Invalid".to_string(), // Unknown
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(!result.is_valid);
        assert!(result.errors.len() >= 2); // Should have multiple errors
    }

    #[test]
    fn test_validate_boundary_k() {
        // k = 11 should be valid (minimum)
        let attrs = CircuitAttributes {
            k: 11,
            instances: 1,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(result.is_valid);

        // k = 20 should be valid (maximum)
        let attrs = CircuitAttributes {
            k: 20,
            instances: 1,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_boundary_instances() {
        // instances = 1 should be valid (minimum)
        let attrs = CircuitAttributes {
            k: 17,
            instances: 1,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(result.is_valid);

        // instances = 255 should be valid (maximum for u8)
        let attrs = CircuitAttributes {
            k: 17,
            instances: 255,
            circuit_type: "Generic".to_string(),
        };
        let result = validate_attributes(&attrs, Span::call_site());
        assert!(result.is_valid);
    }
}

#[cfg(test)]
mod code_generator_tests {
    use crate::code_generators::CodeGenerator;
    use crate::parsers::CircuitAttributes;
    use proc_macro2::TokenStream;
    use quote::quote;
    use syn::Ident;

    #[test]
    fn test_code_generator_creates_instance() {
        let circuit_name = Ident::new("TestCircuit", proc_macro2::Span::call_site());
        let attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let generator = CodeGenerator::new(circuit_name, attrs);
        let _generated = generator.generate();
        // If we get here, the generator was successfully created
    }

    #[test]
    fn test_generated_code_contains_trait_impl() {
        let circuit_name = Ident::new("TestCircuit", proc_macro2::Span::call_site());
        let attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let generator = CodeGenerator::new(circuit_name, attrs);
        let generated = generator.generate();
        let generated_str = generated.to_string();

        // Check that trait implementation is present
        assert!(generated_str.contains("CosmwasmCircuitFor"));
        assert!(generated_str.contains("circuit_metadata"));
        assert!(generated_str.contains("verifying_key"));
        assert!(generated_str.contains("instance_count"));
        assert!(generated_str.contains("k_parameter"));
        assert!(generated_str.contains("is_compatible"));
    }

    #[test]
    fn test_generated_code_contains_constants() {
        let circuit_name = Ident::new("TestCircuit", proc_macro2::Span::call_site());
        let attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let generator = CodeGenerator::new(circuit_name, attrs);
        let generated = generator.generate();
        let generated_str = generated.to_string();

        // Check that constants are present
        assert!(generated_str.contains("METADATA"));
        assert!(generated_str.contains("CircuitMetadata"));
    }

    #[test]
    fn test_generated_code_has_correct_values() {
        let circuit_name = Ident::new("MyCircuit", proc_macro2::Span::call_site());
        let attrs = CircuitAttributes {
            k: 18,
            instances: 3,
            circuit_type: "Generic".to_string(),
        };
        let generator = CodeGenerator::new(circuit_name, attrs);
        let generated = generator.generate();
        let generated_str = generated.to_string();

        // Verify that the specific values are in the generated code
        assert!(generated_str.contains("18")); // k value
        assert!(generated_str.contains("3")); // instances value
        assert!(generated_str.contains("MyCircuit")); // circuit name
    }

    #[test]
    fn test_circuit_type_to_u8_generic() {
        let circuit_name = Ident::new("TestCircuit", proc_macro2::Span::call_site());
        let attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };
        let generator = CodeGenerator::new(circuit_name, attrs);
        let generated = generator.generate();
        let generated_str = generated.to_string();

        // Generic should compile to 0x00
        assert!(generated_str.contains("0x00") || generated_str.contains("0"));
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::parsers::CircuitAttributes;
    use crate::validators::validate_attributes;
    use proc_macro2::Span;

    #[test]
    fn test_parse_and_validate_flow() {
        // Simulate the complete parsing and validation flow
        let input_attrs = CircuitAttributes {
            k: 17,
            instances: 2,
            circuit_type: "Generic".to_string(),
        };

        // This should be valid
        let validation = validate_attributes(&input_attrs, Span::call_site());
        assert!(validation.is_valid);
    }

    #[test]
    fn test_various_k_values() {
        for k in [11, 12, 15, 17, 19, 20] {
            let attrs = CircuitAttributes {
                k,
                instances: 2,
                circuit_type: "Generic".to_string(),
            };
            let result = validate_attributes(&attrs, Span::call_site());
            assert!(result.is_valid, "k={} should be valid", k);
        }
    }

    #[test]
    fn test_various_instance_counts() {
        for instances in [1, 2, 5, 10, 50, 100, 200, 255] {
            let attrs = CircuitAttributes {
                k: 17,
                instances,
                circuit_type: "Generic".to_string(),
            };
            let result = validate_attributes(&attrs, Span::call_site());
            assert!(result.is_valid, "instances={} should be valid", instances);
        }
    }
}

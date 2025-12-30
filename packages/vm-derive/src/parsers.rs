use proc_macro2::Span;
use syn::{parse::ParseStream, Error, LitInt, LitStr, Token};

/// Parsed circuit attributes from the #[cosmwasm_circuit(...)] macro
#[derive(Debug, Clone)]
pub struct CircuitAttributes {
    pub k: u32,
    pub instances: u8,
    pub circuit_type: String,
}

impl syn::parse::Parse for CircuitAttributes {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut k: Option<u32> = None;
        let mut instances: Option<u8> = None;
        let mut circuit_type = String::from("Generic");

        // Parse comma-separated key=value pairs
        loop {
            if input.is_empty() {
                break;
            }

            let ident = input.parse::<syn::Ident>()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "k" => {
                    if k.is_some() {
                        return Err(Error::new_spanned(&ident, "Duplicate attribute: k"));
                    }
                    let lit = input.parse::<LitInt>()?;
                    k = Some(lit.base10_parse::<u32>()?);
                }
                "instances" => {
                    if instances.is_some() {
                        return Err(Error::new_spanned(&ident, "Duplicate attribute: instances"));
                    }
                    let lit = input.parse::<LitInt>()?;
                    instances = Some(lit.base10_parse::<u8>()?);
                }
                "circuit_type" => {
                    let lit = input.parse::<LitStr>()?;
                    circuit_type = lit.value();
                }
                _ => {
                    return Err(Error::new_spanned(
                        &ident,
                        format!("Unknown attribute: {}", ident),
                    ));
                }
            }

            // Check for comma
            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        let k = k.ok_or_else(|| {
            Error::new(input.span(), "Missing required attribute: k")
        })?;

        let instances = instances.ok_or_else(|| {
            Error::new(input.span(), "Missing required attribute: instances")
        })?;

        Ok(CircuitAttributes {
            k,
            instances,
            circuit_type,
        })
    }
}

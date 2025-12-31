use proc_macro2::Span;
use syn::{parse::ParseStream, Error, LitInt, LitStr, Token};

/// Parsed circuit attributes from the #[cosmwasm_circuit(...)] macro
#[derive(Debug, Clone)]
pub struct CircuitAttributes {
    pub i: u8,
    pub ct: String,
}

impl syn::parse::Parse for CircuitAttributes {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut i: Option<u8> = None;
        let mut ct = String::from("Generic");

        // Parse comma-separated key=value pairs
        loop {
            if input.is_empty() {
                break;
            }

            let ident = input.parse::<syn::Ident>()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "i" => {
                    if i.is_some() {
                        return Err(Error::new_spanned(&ident, "Duplicate attribute: i"));
                    }
                    let lit = input.parse::<LitInt>()?;
                    i = Some(lit.base10_parse::<u8>()?);
                }
                "ct" => {
                    let lit = input.parse::<LitStr>()?;
                    ct = lit.value();
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

        let i = i.ok_or_else(|| Error::new(input.span(), "Missing required attribute: i"))?;

        Ok(CircuitAttributes { i, ct })
    }
}

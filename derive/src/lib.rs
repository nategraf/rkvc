use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use proc_macro_crate::FoundCrate;
use quote::{quote, quote_spanned};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
    punctuated::Punctuated,
    spanned::Spanned,
    token::Comma,
    Data, DeriveInput, Field, Fields, LitStr, Type,
};

// TODO: Fill this in, copying from below.
fn is_primitive_type(ty: &syn::TypePath) -> bool {
    match ty.path.get_ident() {
        Some(id) => matches!(
            id.to_string().as_ref(),
            "u8" | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "bool"
                | "char"
        ),
        None => false,
    }
}

struct DeriveAttributesInput {
    /// Path to the rkvc crate (e.g. "rkvc" or "crate").
    crate_path: Ident,
    /// Identifier for the struct to which the derive macro is being applied.
    ident: Ident,
    /// List of fields on the parsed struct.
    ///
    /// Only named fields are currently supported.
    fields: Punctuated<Field, Comma>,
}

impl Parse for DeriveAttributesInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let input = DeriveInput::parse(input)?;

        let mut custom_crate_path = None;

        for attr in &input.attrs {
            if !attr.path().is_ident("rkvc") {
                continue;
            }

            // Require that the attribute use the list notation (i.e. disallow "#[rkvc]").
            attr.meta.require_list()?;

            attr.parse_nested_meta(|meta| match meta {
                meta if meta.path.is_ident("crate_path") => {
                    let lit_str = meta.value()?.parse::<LitStr>()?;
                    custom_crate_path = Some(Ident::new(&lit_str.value(), meta.path.span()));
                    Ok(())
                }
                _ => Err(meta.error("unknown attribute name")),
            })?;
        }

        // Set the crate path - use custom path if provided, otherwise auto-detect.
        let crate_path = custom_crate_path.unwrap_or_else(|| {
            match proc_macro_crate::crate_name("rkvc")
                .expect("rkvc must be a direct dependency in Cargo.toml")
            {
                FoundCrate::Itself => Ident::new("crate", Span::call_site()),
                FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
            }
        });

        // Extract the list of named fields.
        let fields = match input.data {
            Data::Struct(data) => match data.fields {
                Fields::Named(fields) => fields.named,
                _ => unimplemented!("Only named fields are supported"),
            },
            _ => unimplemented!("Only structs are supported"),
        };
        if fields.is_empty() {
            unimplemented!("Not implemented for empty structs");
        }

        Ok(DeriveAttributesInput {
            crate_path,
            fields,
            ident: input.ident,
        })
    }
}

#[proc_macro_derive(Attributes, attributes(rkvc))]
pub fn derive_attributes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveAttributesInput);
    let rkvc_path = input.crate_path;
    let fields = input.fields;
    let struct_name = input.ident;

    // Collect all the types found on fields in the struct, as they will presented to the encoder.
    // Primitve types (i.e. uints, ints, bool, char) passed by value, others passed by reference.
    let attribute_types_res: Result<Vec<_>, _> = fields
        .iter()
        .map(|f| -> Result<Type, _> {
            match f.ty {
                Type::Path(ref p) => match is_primitive_type(p) {
                    true => Ok(f.ty.clone()),
                    false => {
                        let ty = f.ty.clone();
                        Ok(parse_quote!(&#ty))
                    }
                },
                _ => Err(
                    quote_spanned!(f.ty.span() => compile_error!("Only type paths are supported")),
                ),
            }
        })
        .collect();

    let attribute_types = match attribute_types_res {
        Ok(a) => a,
        Err(compile_err) => {
            return compile_err.into();
        }
    };

    // Construct the argument(s) to the encode methods. Take a refernce if
    let encode_value_args: Vec<_> = std::iter::zip(
        fields
        .iter(),
        attribute_types.iter())
        .map(|(f, attr_ty)| {
            let ident = f.ident.as_ref().unwrap();
            match attr_ty {
                Type::Path(_) => quote_spanned!(f.span() => self.#ident),
                Type::Reference(_) => quote_spanned!(f.span() => &self.#ident),
                _ => unreachable!("macro implementation error: checks failed to ensure exhaustive handling of field types"),
            }
        })
        .collect();

    // Collect all the unique types found on fields in the struct, and render them into the type
    // bounds that will be applied to the encoder type on the Attributes implementation. Generate a
    // type bound on e.g. Encoder<u64> for primitive types Encoder<&T> for all other types.
    let encoder_type_bounds: Vec<_> = {
        let mut bounds: Vec<_> = std::iter::zip(
            fields.iter().map(|f| f.ty.clone()),
            attribute_types.iter().cloned(),
        )
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

        // Sort the type bounds to ensure deterministic code generation.
        bounds.sort_by_key(|(ty, attr_ty)| format!("{ty:?} : {attr_ty:?}"));

        bounds.into_iter()
        .map(|(ty, attr_ty)|
            match attr_ty {
                Type::Path(_) => quote_spanned!(ty.span() => #rkvc_path::attributes::Encoder<#ty>),
                Type::Reference(_) => quote_spanned!(ty.span() => for<'a> #rkvc_path::attributes::Encoder<&'a #ty>),
                _ => unreachable!("macro implementation error: checks failed to ensure exhaustive handling of field types"),
            }
        )
        .collect()
    };

    // TODO: Add a #[label = "foo"] attribute that can be used to specify the field label manually.
    let indices: Vec<usize> = (0..fields.len()).collect();
    let field_labels: Vec<_> = fields
        .iter()
        .map(|f| f.ident.as_ref().unwrap())
        .map(|name| format!("{}::{}", struct_name, name))
        .collect();

    let attribute_count = fields.len();

    quote! {
        impl #rkvc_path::AttributeCount for #struct_name {
            type N = #rkvc_path::attributes::typenum::U::<#attribute_count>;
        }

        impl #rkvc_path::AttributeLabels for #struct_name {
            fn label_at(i: usize) -> Option<&'static str> {
                match i {
                    #(#indices => Some(#field_labels),)*
                    _ => None,
                }
            }
        }

        impl<E> #rkvc_path::Attributes<E> for #struct_name
        where
            E: #rkvc_path::attributes::EncoderOutput,
            #(E: #encoder_type_bounds,)*
        {
            fn attribute_at(&self, i: usize, encoder: &mut E) -> Option<E::Output> {
                match i {
                    #(#indices => Some(encoder.encode_value(#encode_value_args)),)*
                    _ => None,
                }
            }

            fn attribute_type_at(i: usize, encoder: &mut E) -> Option<E::TypeOutput> {
                match i {
                    #(#indices => Some(<E as #rkvc_path::attributes::Encoder<#attribute_types>>::encode_type(encoder)),)*
                    _ => None,
                }
            }
        }
    }.into()
}

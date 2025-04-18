use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::FoundCrate;
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
    punctuated::Punctuated,
    spanned::Spanned,
    token::Comma,
    Data, DeriveInput, Field, Fields, Ident, LitStr, Type,
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

        // Parse macro attributes (e.g. #[rkvc(crate_path = "foo")]).
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
                _ => Err(meta.error("Unknown attribute name")),
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
                _ => {
                    return Err(syn::Error::new(
                        data.fields.span(),
                        "Only named fields are supported",
                    ))
                }
            },
            _ => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "Only structs are supported",
                ))
            }
        };
        if fields.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                "Empty structs are not supported",
            ));
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
    let attribute_types_res: syn::Result<Vec<_>> = fields
        .iter()
        .map(|f| -> syn::Result<Type> {
            match f.ty {
                Type::Path(ref p) => match is_primitive_type(p) {
                    true => Ok(f.ty.clone()),
                    false => {
                        let ty = f.ty.clone();
                        Ok(parse_quote!(&#ty))
                    }
                },
                // TODO: Move this fallible step into the parse impl.
                _ => Err(syn::Error::new(
                    f.ty.span(),
                    "Only type paths are supported",
                )),
            }
        })
        .collect();

    let attribute_types = match attribute_types_res {
        Ok(a) => a,
        Err(err) => return err.into_compile_error().into(),
    };

    // Construct the argument(s) to the encode methods. Take a refernce if the field is a
    // non-primitive type.
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
    // TODO: Support numerical index assignment other than sequential and adjust accordingly.
    let indices: Vec<usize> = (0..fields.len()).collect();
    let field_labels: Vec<String> = fields
        .iter()
        .map(|f| f.ident.as_ref().unwrap())
        .map(|name| format!("{}::{}", struct_name, name))
        .collect();

    // Collect the information needed to build the Index trait.
    // TODO: How should this deal with non-pub fields?
    let index_trait_name: Ident = format_ident!("{struct_name}Index");
    let field_idents: Vec<Ident> = fields
        .iter()
        .map(|f| {
            f.ident
                .clone()
                .expect("macro implementation error: failed to get ident for field")
        })
        .collect();

    let index_fn_docs: Vec<String> = field_idents.iter().map(|field_ident| {
        format!("Index into the container to access the element associated with [{struct_name}::{field_ident}]")
    }).collect();

    // FIXME: The way this is done means that if there were a struct Foo { a: _, a_mut: _ }, this
    // would result in an indicipherable compiler error.
    let field_mut_idents: Vec<Ident> = field_idents
        .iter()
        .map(|field_ident| format_ident!("{field_ident}_mut"))
        .collect();

    let index_fn_mut_docs: Vec<String> = field_idents.iter().map(|field_ident| {
        format!("Mutably index into the container to modify the element associated with [{struct_name}::{field_ident}]")
    }).collect();

    // TODO: This breaks if the struct is generic.
    let attribute_count = fields.len();
    quote! {
        trait #index_trait_name {
            type Value;

            #(#[doc = #index_fn_docs] fn #field_idents(&self) -> &Self::Value;)*

            #(#[doc = #index_fn_mut_docs] fn #field_mut_idents(&mut self) -> &mut Self::Value;)*
        }

        impl<T> #index_trait_name for #rkvc_path::AttributeArray<T, #struct_name> {
            type Value = T;

            #(fn #field_idents(&self) -> &Self::Value { &self.0[#indices] })*

            #(fn #field_mut_idents(&mut self) -> &mut Self::Value { &mut self.0[#indices] })*
        }

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

use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use proc_macro_crate::FoundCrate;
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Fields, Type};

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

#[proc_macro_derive(Attributes)]
pub fn derive_attributes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident;

    // Get the crate name - we'll use the current module path
    let rkvc_path =
        match proc_macro_crate::crate_name("rkvc").expect("rkvc must be a direct dependency") {
            FoundCrate::Itself => Ident::new("crate", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };

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

    let visit_field_args: Vec<_> = fields
        .iter()
        .map(|f| {
            let ident = f.ident.as_ref().unwrap();
            match f.ty {
                Type::Path(ref p) => match is_primitive_type(p) {
                    true => quote_spanned!(f.span() => self.#ident),
                    false => quote_spanned!(f.span() => &self.#ident),
                },
                _ => quote_spanned!(f.ty.span() => compile_error!("Only type paths are supported")),
            }
        })
        .collect();

    // Collect all the unique types found on fields in the struct, and render them into the type
    // bounds that will be applied to the visitor type on the Attributes implementation.
    let visitor_type_bounds: Vec<_> = fields
        .iter()
        .map(|f| f.ty.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|ty| match ty {
            Type::Path(ref p) => match is_primitive_type(p) {
                // Generate a type bound on e.g. Visitor<u64> for small primitive types
                // Visitor<&T> for all other types.
                true => quote_spanned!(ty.span() => #rkvc_path::attributes::Visitor<#ty>),
                false => {
                    quote_spanned!(ty.span() => for<'a> #rkvc_path::attributes::Visitor<&'a #ty>)
                }
            },
            _ => quote_spanned!(ty.span() => compile_error!("Only type paths are supported")),
        })
        .collect();

    // TODO: Add a #[label = "foo"] attribute that can be used to specify the field label manually.
    let indices: Vec<usize> = (0..fields.len()).collect();
    let field_labels: Vec<_> = fields
        .iter()
        .map(|f| f.ident.as_ref().unwrap())
        .map(|name| format!("{}::{}", struct_name, name))
        .collect();

    // Generate the Labels implementation
    let labels_impl = quote! {
        impl #rkvc_path::AttributeLabels for #struct_name {
            fn label_at(i: usize) -> Option<&'static str> {
                match i {
                    #(#indices => Some(#field_labels),)*
                    _ => None,
                }
            }
        }
    };

    // Generate the Elems implementation
    let elems_impl = quote! {
        impl<V> #rkvc_path::Attributes<V> for #struct_name
            where
                V: #rkvc_path::attributes::VisitorOutput,
                #(V: #visitor_type_bounds,)*
            {
            fn elem_at(&self, i: usize, visitor: &mut V) -> Option<V::Output> {
                match i {
                    #(#indices => Some(visitor.visit(#visit_field_args)),)*
                    _ => None,
                }
            }
        }
    };

    quote! {
        #labels_impl
        #elems_impl
    }
    .into()
}

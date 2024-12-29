use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use proc_macro_crate::FoundCrate;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type};

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
            _ => panic!("Only named fields are supported"),
        },
        _ => panic!("Only structs are supported"),
    };
    if fields.is_empty() {
        panic!("Not implemented for empty structs");
    }

    let field_names: Vec<&Ident> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    // Collect all the unique types found on fields in the struct.
    // TODO: This does not have very strong guarentees that something sensible will be generated.
    let field_types: Vec<Type> = fields
        .iter()
        .map(|f| f.ty.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    // TODO: Add a #[label = "foo"] attribute that can be used to specify the field label manually.
    let indices: Vec<usize> = (0..field_names.len()).collect();
    let field_labels: Vec<_> = field_names
        .iter()
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
        impl<V, O> #rkvc_path::Attributes<V, O> for #struct_name
            where
                #(V: #rkvc_path::attributes::Visitor<#field_types, Output = O>,)*
            {
            fn elem_at(&self, i: usize, visitor: &mut V) -> Option<O> {
                match i {
                    #(#indices => Some(visitor.visit(&self.#field_names)),)*
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

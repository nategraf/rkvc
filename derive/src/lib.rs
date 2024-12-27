// In attributes_derive/lib.rs
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use proc_macro_crate::FoundCrate;
use quote::{format_ident, quote};
use syn::parse::Result as ParseResult;
use syn::{parse::Parse, parse::ParseStream, parse_macro_input, Data, DeriveInput, Fields, Token};

// Parser for field = type attribute syntax
struct FieldAttr {
    field_type: syn::Type,
}

impl Parse for FieldAttr {
    fn parse(input: ParseStream) -> ParseResult<Self> {
        let _: syn::Ident = input.parse()?; // Parse "field"
        let _: Token![=] = input.parse()?; // Parse "="
        let field_type: syn::Type = input.parse()?; // Parse the type
        Ok(FieldAttr { field_type })
    }
}

#[proc_macro_derive(Attributes, attributes(rkvc))]
pub fn derive_attributes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident;

    // Get the crate name - we'll use the current module path
    let rkvc_path =
        match proc_macro_crate::crate_name("rkvc").expect("rkvc must be a direct dependency") {
            FoundCrate::Itself => Ident::new("crate", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };

    // Get the field type from attributes, e.g.:
    // #[rkvc(field = curve25519_dalek::Scalar)]
    let field_type = input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("rkvc"))
        .expect("rkvc attribute must be specified with field type")
        .parse_args::<FieldAttr>()
        .expect("failed to parse field type, expected: #[rkvc(field = TypeName)]")
        .field_type;

    // Create the labels struct name
    let labels_struct_name = format_ident!("{}Labels", struct_name);
    // Create the elems struct name
    let elems_struct_name = format_ident!("{}Elems", struct_name);

    let fields = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => panic!("Only named fields are supported"),
        },
        _ => panic!("Only structs are supported"),
    };

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();

    let indices: Vec<_> = (0..field_names.len()).collect();
    let field_labels: Vec<_> = field_names
        .iter()
        .map(|name| format!("{}::{}", struct_name, name))
        .collect();

    // Generate the Labels implementation
    let labels_impl = quote! {
        struct #labels_struct_name;

        impl #rkvc_path::AttributeLabels for #labels_struct_name {
            fn at(&self, i: usize) -> Option<&'static str> {
                match i {
                    #(#indices => Some(#field_labels),)*
                    _ => None,
                }
            }
        }
    };

    // Generate the Elems implementation
    let elems_impl = quote! {
        struct #elems_struct_name<'a>(&'a #struct_name);

        // you seeing this?!
        impl<'a> #rkvc_path::AttributeElems<#field_type> for #elems_struct_name<'a> {
            fn at(&self, i: usize) -> Option<#field_type> {
                match i {
                    #(#indices => Some(#field_type::from(self.0.#field_names)),)*
                    _ => None,
                }
            }
        }
    };

    // Generate the Attributes implementation
    let attributes_impl = quote! {
        impl #rkvc_path::Attributes<#field_type> for #struct_name {
            type Labels = #labels_struct_name;

            fn attribute_labels() -> Self::Labels {
                #labels_struct_name
            }

            fn attribute_elems(&self) -> impl #rkvc_path::AttributeElems<#field_type> {
                #elems_struct_name(self)
            }
        }
    };

    let expanded = quote! {
        #labels_impl
        #elems_impl
        #attributes_impl
    };

    TokenStream::from(expanded)
}

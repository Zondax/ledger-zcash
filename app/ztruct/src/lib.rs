extern crate proc_macro;

use quote::{quote};
use syn::{parse_macro_input, DeriveInput};

#[proc_macro]
pub fn create_ztruct(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident; // Struct name
    let visibility = input.vis; // This captures the visibility specified in the macro input
    let fields = match input.data {
        syn::Data::Struct(s) => s.fields,
        _ => panic!("Expected a struct"),
    };

    let mut total_size = quote! { 0 };
    let mut field_initializers = proc_macro2::TokenStream::new();
    let mut constructor_params = proc_macro2::TokenStream::new();
    let mut field_accessors = proc_macro2::TokenStream::new();
    let mut mutable_field_accessors = proc_macro2::TokenStream::new();
    let mut offsets = vec![];

    for (i, f) in fields.iter().enumerate() {
        let field_name = f.ident.clone().unwrap();
        let field_type = &f.ty;
        let field_size = quote! { ::core::mem::size_of::<#field_type>() };

        total_size = quote! { #total_size + #field_size };
        let offset = quote! { #total_size - #field_size };
        offsets.push((field_name.clone(), field_type.clone(), offset.clone()));

        let param = quote! { #field_name: #field_type };
        constructor_params.extend(param);
        if i < fields.len() - 1 {
            constructor_params.extend(quote! { , });
        }

        // Generate accessor for each field
        let accessor = quote! {
            pub fn #field_name(&self) -> #field_type {
                let ptr = self.data.as_ptr() as *const u8;
                unsafe { *(ptr.add(#offset) as *const #field_type) }
            }
        };
        field_accessors.extend(accessor);

        // Generate mutable accessor for each field with 'mut' suffix
        let mutable_accessor_name = quote! { #field_name }.to_string() + "_mut";
        let mutable_accessor_ident = syn::Ident::new(&mutable_accessor_name, proc_macro2::Span::call_site());
        let mutable_accessor = quote! {
            pub fn #mutable_accessor_ident(&mut self) -> &mut #field_type {
                let ptr = self.data.as_mut_ptr() as *mut u8;
                unsafe { &mut *(ptr.add(#offset) as *mut #field_type) }
            }
        };
        mutable_field_accessors.extend(mutable_accessor);
    }

    for (field_name, field_type, offset) in &offsets {
        let initializer = quote! {
            let ptr = instance.data.as_mut_ptr() as *mut u8;
            unsafe {
                ::core::ptr::write(ptr.add(#offset) as *mut #field_type, #field_name);
            }
        };
        field_initializers.extend(initializer);
    }
    let from_bytes_method = quote! {
        pub fn from_bytes(bytes: &[u8]) -> Self {
            assert!(bytes.len() == #total_size, "Byte slice length does not match struct size");
            let mut instance = Self { data: [0u8; #total_size] };
            instance.data.copy_from_slice(bytes);
            instance
        }
    };

    let buffer_accessors = quote! {
        pub fn to_bytes(&self) -> &[u8] {
            &self.data
        }

        pub fn to_bytes_mut(&mut self) -> &mut [u8] {
            &mut self.data
        }
    };

    let empty_constructor = quote! {
        pub fn empty() -> Self {
            Self { data: [0u8; #total_size] }
        }
    };

    let expanded = quote! {
        #visibility struct #name {
            data: [u8; #total_size],
        }

        impl #name {
            pub fn new(#constructor_params) -> Self {
                let mut instance = Self { data: [0u8; #total_size] };
                #field_initializers
                instance
            }

            #empty_constructor

            #from_bytes_method

            #field_accessors
            #mutable_field_accessors
            #buffer_accessors
        }
    };

    proc_macro::TokenStream::from(proc_macro2::TokenStream::from(expanded))
}
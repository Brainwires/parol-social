//! `#[clause("PNP-XXX-LEVEL-NNN", ...)]` attribute.
//!
//! Pins a test function to one or more PNP specification clause IDs. Expansion
//! is a verbatim pass-through of the decorated item plus a `#[doc(hidden)]`
//! sibling const whose identifier encodes the clause IDs. `cargo xtask clauses`
//! regex-scans sources for the attribute invocations; the const exists so the
//! compiler enforces uniqueness per source file and so dead-code lints do not
//! fire on orphaned clause registrations.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, punctuated::Punctuated, Item, LitStr, Token};

const CLAUSE_RE: &str = r"^PNP-\d{3}-(MUST|SHOULD|MAY)-\d{3}$";

fn validate(id: &str) -> Result<(), String> {
    // Hand-rolled matcher: spec=PNP-DDD, level in {MUST,SHOULD,MAY}, serial=DDD.
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() != 4 {
        return Err(format!("clause id {id:?} must have 4 dash-separated parts"));
    }
    if parts[0] != "PNP" {
        return Err(format!("clause id {id:?} must begin with `PNP`"));
    }
    if parts[1].len() != 3 || !parts[1].bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("clause id {id:?} spec number must be 3 digits"));
    }
    if !matches!(parts[2], "MUST" | "SHOULD" | "MAY") {
        return Err(format!("clause id {id:?} level must be MUST|SHOULD|MAY"));
    }
    if parts[3].len() != 3 || !parts[3].bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("clause id {id:?} serial must be 3 digits"));
    }
    let _ = CLAUSE_RE;
    Ok(())
}

#[proc_macro_attribute]
pub fn clause(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args =
        parse_macro_input!(attr with Punctuated::<LitStr, Token![,]>::parse_terminated);
    let item2 = parse_macro_input!(item as Item);

    let ids: Vec<String> = args.iter().map(|s| s.value()).collect();
    if ids.is_empty() {
        return syn::Error::new_spanned(
            TokenStream2::new(),
            "#[clause(...)] requires at least one clause id literal",
        )
        .to_compile_error()
        .into();
    }
    for id in &ids {
        if let Err(e) = validate(id) {
            return syn::Error::new_spanned(TokenStream2::new(), e)
                .to_compile_error()
                .into();
        }
    }

    let name = match &item2 {
        Item::Fn(f) => f.sig.ident.clone(),
        _ => {
            return syn::Error::new_spanned(
                TokenStream2::new(),
                "#[clause(...)] may only annotate functions",
            )
            .to_compile_error()
            .into();
        }
    };

    let id_refs = ids.iter().map(|s| quote!(#s));
    let const_name = quote::format_ident!("__PNP_CLAUSE_{}", name.to_string().to_uppercase());

    let expanded = quote! {
        #[doc(hidden)]
        #[allow(non_upper_case_globals, dead_code)]
        const #const_name: &[&str] = &[ #( #id_refs ),* ];
        #item2
    };
    expanded.into()
}

//! Parsing a Solana/Anchor program's Rust source into the handful of shapes
//! the rules care about: `#[derive(Accounts)]` context structs (with their
//! fields + per-field `#[account(...)]` constraints) and the instruction
//! handler functions inside the `#[program]` module.
//!
//! This is deliberately AST-based (via `syn`) rather than regex, so rules can
//! reason about real structure. It is NOT a full Anchor semantic model — it is
//! the pragmatic subset a static linter needs.

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, ExprLit, Fields, Item, Lit, Meta};

/// One field of a `#[derive(Accounts)]` struct.
#[derive(Debug, Clone)]
pub struct AccountField {
    pub name: String,
    /// Stringified type, e.g. "Account < 'info , Vault >".
    pub ty: String,
    pub line: usize,
    /// Raw token string inside `#[account(...)]`, if the attr is present.
    /// `Some("")` means a bare `#[account]`; `None` means no account attr.
    pub account_attr: Option<String>,
    /// Whether the field carries a `/// CHECK:` safety doc comment.
    pub has_check_doc: bool,
}

impl AccountField {
    /// Case-insensitive, whitespace-insensitive test on the stringified type.
    pub fn ty_contains(&self, needle: &str) -> bool {
        self.ty.replace(' ', "").contains(needle)
    }

    /// Does the `#[account(...)]` constraint mention `needle`?
    pub fn attr_contains(&self, needle: &str) -> bool {
        self.account_attr
            .as_deref()
            .map(|a| a.contains(needle))
            .unwrap_or(false)
    }
}

/// A `#[derive(Accounts)]` context struct.
#[derive(Debug, Clone)]
pub struct AccountsStruct {
    pub name: String,
    /// Line of the struct declaration (used by struct-level rules in v2).
    #[allow(dead_code)]
    pub line: usize,
    pub fields: Vec<AccountField>,
}

/// An instruction handler function (from inside `#[program]`).
#[derive(Debug, Clone)]
pub struct InstructionFn {
    pub name: String,
    /// Line of the handler (used for fn-level reporting in v2).
    #[allow(dead_code)]
    pub line: usize,
    pub block: syn::Block,
}

/// Everything the rules receive for one source file.
pub struct Parsed {
    pub accounts: Vec<AccountsStruct>,
    pub instructions: Vec<InstructionFn>,
}

pub fn parse_source(src: &str) -> syn::Result<syn::File> {
    syn::parse_file(src)
}

pub fn extract(file: &syn::File) -> Parsed {
    let mut accounts = Vec::new();
    let mut instructions = Vec::new();
    walk_items(&file.items, &mut accounts, &mut instructions);
    Parsed {
        accounts,
        instructions,
    }
}

fn walk_items(
    items: &[Item],
    accounts: &mut Vec<AccountsStruct>,
    instructions: &mut Vec<InstructionFn>,
) {
    for item in items {
        match item {
            Item::Struct(s) if has_derive(&s.attrs, "Accounts") => {
                accounts.push(parse_accounts_struct(s));
            }
            // Instruction handlers live inside a `#[program]` module.
            Item::Mod(m) if has_attr(&m.attrs, "program") => {
                if let Some((_, inner)) = &m.content {
                    for it in inner {
                        if let Item::Fn(f) = it {
                            instructions.push(InstructionFn {
                                name: f.sig.ident.to_string(),
                                line: f.sig.ident.span().start().line,
                                block: (*f.block).clone(),
                            });
                        }
                    }
                }
            }
            // Recurse into any nested module so we don't miss structs/handlers.
            Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    walk_items(inner, accounts, instructions);
                }
            }
            _ => {}
        }
    }
}

fn parse_accounts_struct(s: &syn::ItemStruct) -> AccountsStruct {
    let mut fields = Vec::new();
    if let Fields::Named(named) = &s.fields {
        for f in &named.named {
            let name = f
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default();
            fields.push(AccountField {
                name,
                ty: f.ty.to_token_stream().to_string(),
                line: f.span().start().line,
                account_attr: account_attr_tokens(&f.attrs),
                has_check_doc: has_check_doc(&f.attrs),
            });
        }
    }
    AccountsStruct {
        name: s.ident.to_string(),
        line: s.ident.span().start().line,
        fields,
    }
}

/// True if `attrs` contains `#[derive(... ident ...)]`.
fn has_derive(attrs: &[Attribute], ident: &str) -> bool {
    for attr in attrs {
        if attr.path().is_ident("derive") {
            let mut found = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident(ident) {
                    found = true;
                }
                Ok(())
            });
            if found {
                return true;
            }
        }
    }
    false
}

/// True if `attrs` contains a bare `#[ident]` or `#[ident(...)]`.
fn has_attr(attrs: &[Attribute], ident: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(ident))
}

/// Returns the token string inside `#[account(...)]`, `Some("")` for bare
/// `#[account]`, or `None` if there is no account attribute.
fn account_attr_tokens(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("account") {
            return match &attr.meta {
                Meta::List(list) => Some(list.tokens.to_string()),
                _ => Some(String::new()),
            };
        }
    }
    None
}

/// True if any doc comment contains "CHECK" (Anchor's required safety note for
/// unchecked accounts).
fn has_check_doc(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("doc") {
            if let Meta::NameValue(nv) = &attr.meta {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(s), ..
                }) = &nv.value
                {
                    if s.value().to_uppercase().contains("CHECK") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

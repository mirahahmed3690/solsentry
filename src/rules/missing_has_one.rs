//! Rule: mutable custom state account not bound to its authority.
//!
//! If a context mutates a typed *custom* state account but nothing ties it to
//! the signer/authority present in the same context (`has_one`, `seeds`, or a
//! constraint), one user may be able to act on another user's account.
//!
//! PRECISION NOTE (v2): token accounts (`TokenAccount` / `Mint` /
//! `InterfaceAccount`) are validated by the SPL-Token program plus
//! `token::` / `associated_token` constraints, NOT by `has_one`, so flagging
//! every mutable token account produces huge false-positive noise on real
//! programs. We exclude token/mint types and any field already pinned by a
//! token constraint. What remains is the high-signal case: a mutable *custom*
//! `Account<'info, MyState>` with no owner binding.

use super::{looks_like_authority, Context, Rule};
use crate::finding::{Finding, Severity};

pub struct MissingHasOne;

impl Rule for MissingHasOne {
    fn id(&self) -> &'static str {
        "missing-has-one"
    }

    fn description(&self) -> &'static str {
        "Mutable custom state account not bound to an authority via has_one/seeds"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for s in &ctx.parsed.accounts {
            let has_authority_field = s
                .fields
                .iter()
                .any(|f| looks_like_authority(&f.name) || f.ty_contains("Signer"));
            if !has_authority_field {
                continue;
            }
            for f in &s.fields {
                let is_typed_account = f.ty_contains("Account<") && !f.ty_contains("AccountInfo");
                let is_mut = f.attr_contains("mut");
                if !is_typed_account || !is_mut {
                    continue;
                }
                if f.ty_contains("TokenAccount")
                    || f.ty_contains("Mint")
                    || f.ty_contains("InterfaceAccount")
                {
                    continue;
                }
                if f.attr_contains("has_one")
                    || f.attr_contains("seeds")
                    || f.attr_contains("token::")
                    || f.attr_contains("associated_token")
                    || f.attr_contains("constraint")
                {
                    continue;
                }
                out.push(Finding::new(
                    self.id(),
                    Severity::Medium,
                    ctx.path,
                    f.line,
                    format!(
                        "`{}` in `{}` is a mutable custom state account not tied to the \
                         context's authority — no `has_one`, `seeds`, or constraint.",
                        f.name, s.name
                    ),
                    "Add `has_one = authority` (or a PDA `seeds`/`bump` derivation, or a \
                     `constraint`) so only the owning authority can mutate this account."
                        .to_string(),
                ));
            }
        }
    }
}

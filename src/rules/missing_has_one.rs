//! Rule: mutable state account not bound to its authority via `has_one`.
//!
//! If a context mutates a typed state account but no `has_one = authority`
//! (or equivalent) ties that state to the signer present in the same context,
//! one user may be able to act on another user's account. Heuristic: a
//! mutable `Account<'info, T>` with an authority field in scope but no
//! `has_one` / `seeds` binding.

use super::{looks_like_authority, Context, Rule};
use crate::finding::{Finding, Severity};

pub struct MissingHasOne;

impl Rule for MissingHasOne {
    fn id(&self) -> &'static str {
        "missing-has-one"
    }

    fn description(&self) -> &'static str {
        "Mutable state account not bound to an authority via has_one/seeds"
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
                // typed state account, mutable...
                let is_typed_account = f.ty_contains("Account<") && !f.ty_contains("AccountInfo");
                let is_mut = f.attr_contains("mut");
                if !is_typed_account || !is_mut {
                    continue;
                }
                // ...but no binding to the authority.
                let bound = f.attr_contains("has_one") || f.attr_contains("seeds");
                if bound {
                    continue;
                }
                out.push(Finding::new(
                    self.id(),
                    Severity::Medium,
                    ctx.path,
                    f.line,
                    format!(
                        "`{}` in `{}` is mutated but is not tied to the context's \
                         authority — no `has_one` or `seeds` binding.",
                        f.name, s.name
                    ),
                    "Add `has_one = authority` (or a PDA `seeds`/`bump` derivation) \
                     so only the owning authority can mutate this account."
                        .to_string(),
                ));
            }
        }
    }
}

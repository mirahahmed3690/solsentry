//! Rule: missing signer check.
//!
//! An account that names an authority but is never required to sign (and is not
//! otherwise pinned) can be supplied by anyone. This is the #1 Solana bug class
//! (Neodyme "Missing signer check").
//!
//! PRECISION NOTE (v2): we deliberately do NOT flag `UncheckedAccount` /
//! `AccountInfo` authorities. In real Anchor programs those are almost always
//! PDAs that the program signs for via `invoke_signed` (seeds), so treating
//! every `*_authority: UncheckedAccount` as a missing-signer produces a flood
//! of false positives on audited code. Unconstrained raw accounts are the
//! `unchecked-account` rule's job. We also skip accounts already pinned by
//! `seeds` / `address` / `constraint`. What remains is the high-signal case: a
//! *typed* authority account with no signer and no binding.

use super::{looks_like_authority, Context, Rule};
use crate::finding::{Finding, Severity};

pub struct MissingSigner;

impl Rule for MissingSigner {
    fn id(&self) -> &'static str {
        "missing-signer"
    }

    fn description(&self) -> &'static str {
        "Typed authority account is neither a Signer nor otherwise pinned"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for s in &ctx.parsed.accounts {
            for f in &s.fields {
                if !looks_like_authority(&f.name) {
                    continue;
                }
                if f.ty_contains("Signer") || f.attr_contains("signer") {
                    continue;
                }
                if f.ty_contains("UncheckedAccount") || f.ty_contains("AccountInfo") {
                    continue;
                }
                if f.attr_contains("seeds")
                    || f.attr_contains("address")
                    || f.attr_contains("constraint")
                {
                    continue;
                }
                out.push(Finding::new(
                    self.id(),
                    Severity::High,
                    ctx.path,
                    f.line,
                    format!(
                        "`{}` in `{}` acts as an authority (type `{}`) but is not a Signer \
                         and has no seeds/address/constraint binding; verify it cannot be \
                         supplied by an attacker.",
                        f.name,
                        s.name,
                        f.ty.replace(' ', "")
                    ),
                    format!(
                        "Make it `Signer<'info>`, add a `signer` constraint, or pin it with \
                         `has_one`/`seeds`/`address` so it can't be substituted — \
                         e.g. `#[account(signer)] pub {}: ...`.",
                        f.name
                    ),
                ));
            }
        }
    }
}

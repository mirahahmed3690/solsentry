//! Rule: missing signer check.
//!
//! An account that names an authority (authority/owner/admin/...) but is not a
//! `Signer` and is not marked `signer` in its `#[account(...)]` constraint can
//! be supplied by anyone — the program never proves the caller controls it.
//! This is the #1 Solana bug class (see Neodyme "Missing signer check").

use super::{looks_like_authority, Context, Rule};
use crate::finding::{Finding, Severity};

pub struct MissingSigner;

impl Rule for MissingSigner {
    fn id(&self) -> &'static str {
        "missing-signer"
    }

    fn description(&self) -> &'static str {
        "Authority-like account is not enforced as a Signer"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for s in &ctx.parsed.accounts {
            for f in &s.fields {
                if !looks_like_authority(&f.name) {
                    continue;
                }
                let is_signer_type = f.ty_contains("Signer");
                let is_signer_constraint = f.attr_contains("signer");
                if !is_signer_type && !is_signer_constraint {
                    out.push(Finding::new(
                        self.id(),
                        Severity::High,
                        ctx.path,
                        f.line,
                        format!(
                            "`{}` in `{}` acts as an authority but is not a Signer \
                             (type `{}`); anyone can supply this account.",
                            f.name,
                            s.name,
                            f.ty.replace(' ', "")
                        ),
                        format!(
                            "Change the type to `Signer<'info>`, or add a `signer` \
                             constraint: `#[account(signer)] pub {}: ...`.",
                            f.name
                        ),
                    ));
                }
            }
        }
    }
}

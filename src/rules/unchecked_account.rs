//! Rule: unvalidated account (`UncheckedAccount` / `AccountInfo`).
//!
//! `UncheckedAccount` and `AccountInfo` skip Anchor's owner + type checks. If
//! the field has no constraint pinning it down (address/seeds/owner/constraint)
//! and no `/// CHECK:` justification, an attacker can substitute an arbitrary
//! account. (See Neodyme "Account data matching" / "Owner checks".)

use super::{Context, Rule};
use crate::finding::{Finding, Severity};

pub struct UncheckedAccount;

const PINNING_CONSTRAINTS: &[&str] = &[
    "address",
    "seeds",
    "owner",
    "constraint",
    "token::",
    "associated_token",
    "has_one",
];

impl Rule for UncheckedAccount {
    fn id(&self) -> &'static str {
        "unchecked-account"
    }

    fn description(&self) -> &'static str {
        "AccountInfo/UncheckedAccount without a constraint or /// CHECK: doc"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for s in &ctx.parsed.accounts {
            for f in &s.fields {
                let is_raw = f.ty_contains("UncheckedAccount") || f.ty_contains("AccountInfo");
                if !is_raw {
                    continue;
                }
                let pinned = PINNING_CONSTRAINTS.iter().any(|c| f.attr_contains(c));
                if pinned || f.has_check_doc {
                    continue;
                }
                out.push(Finding::new(
                    self.id(),
                    Severity::Medium,
                    ctx.path,
                    f.line,
                    format!(
                        "`{}` in `{}` is a raw `{}` with no constraint and no \
                         `/// CHECK:` doc — its owner and contents are never verified.",
                        f.name,
                        s.name,
                        f.ty.replace(' ', "")
                    ),
                    "Use a typed `Account<'info, T>`, or pin it with a constraint \
                     (address/seeds/owner), or document why it is safe with a \
                     `/// CHECK:` comment."
                        .to_string(),
                ));
            }
        }
    }
}

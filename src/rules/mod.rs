//! The rule engine. Every vulnerability class is a `Rule`. Adding a new class
//! = add one file in `rules/`, implement `Rule`, and register it in
//! `all_rules()`. Nothing else changes.

use crate::finding::Finding;
use crate::parse::anchor::Parsed;

mod arbitrary_cpi;
mod missing_has_one;
mod missing_signer;
mod unchecked_account;
mod unchecked_math;

/// What each rule gets to inspect for one source file.
pub struct Context<'a> {
    pub path: &'a str,
    pub parsed: &'a Parsed,
}

pub trait Rule {
    /// Stable short id, e.g. "missing-signer".
    fn id(&self) -> &'static str;
    /// One-line description of the class (shown in `--list`).
    fn description(&self) -> &'static str;
    /// Inspect the file and push any findings.
    fn check(&self, ctx: &Context, out: &mut Vec<Finding>);
}

/// The registry. Order here is the order rules run.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(missing_signer::MissingSigner),
        Box::new(unchecked_account::UncheckedAccount),
        Box::new(missing_has_one::MissingHasOne),
        Box::new(unchecked_math::UncheckedMath),
        Box::new(arbitrary_cpi::ArbitraryCpi),
    ]
}

/// Names that conventionally denote an authority/owner account.
pub(crate) const AUTHORITY_NAMES: &[&str] = &[
    "authority", "owner", "admin", "signer", "user", "payer", "creator", "delegate",
];

pub(crate) fn looks_like_authority(name: &str) -> bool {
    let n = name.to_lowercase();
    AUTHORITY_NAMES.iter().any(|a| n == *a || n.ends_with(a))
}

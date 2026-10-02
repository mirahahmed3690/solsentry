//! Rule: arbitrary / unverified CPI.
//!
//! When a program performs a cross-program invocation (`invoke` /
//! `invoke_signed`), the callee program must be pinned to a known program id.
//! If the program being called is taken from a caller-supplied account without
//! verification, an attacker can substitute their own malicious program and
//! have it run with this program's authority. This is one of the classic
//! Solana bug classes (Sealevel Attacks: "arbitrary CPI").
//!
//! v1 heuristic: flag every raw `invoke` / `invoke_signed` call site for manual
//! review — "is the target program id checked against a constant?" Anchor's
//! typed `Program<'info, T>` enforces this automatically, so idiomatic Anchor
//! CPI is lower risk; raw `invoke` is where this bug lives. v2 will add
//! data-flow to suppress the verified cases.

use super::{Context, Rule};
use crate::finding::{Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall};

pub struct ArbitraryCpi;

#[derive(Default)]
struct CpiVisitor {
    hits: Vec<usize>,
}

fn is_cpi_name(name: &str) -> bool {
    name == "invoke" || name == "invoke_signed"
}

impl<'ast> Visit<'ast> for CpiVisitor {
    // free-function form: `invoke(&ix, accounts)` / `program::invoke(...)`
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(p) = node.func.as_ref() {
            if let Some(last) = p.path.segments.last() {
                if is_cpi_name(&last.ident.to_string()) {
                    self.hits.push(node.span().start().line);
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    // method form: `ix.invoke(...)` (less common, caught for completeness)
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if is_cpi_name(&node.method.to_string()) {
            self.hits.push(node.span().start().line);
        }
        visit::visit_expr_method_call(self, node);
    }
}

impl Rule for ArbitraryCpi {
    fn id(&self) -> &'static str {
        "arbitrary-cpi"
    }

    fn description(&self) -> &'static str {
        "Raw invoke/invoke_signed CPI whose target program may be unverified"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for f in &ctx.parsed.instructions {
            let mut v = CpiVisitor::default();
            v.visit_block(&f.block);
            for line in v.hits {
                out.push(Finding::new(
                    self.id(),
                    Severity::Medium,
                    ctx.path,
                    line,
                    format!(
                        "CPI (`invoke`/`invoke_signed`) in instruction `{}` — confirm the \
                         target program id is verified, not taken from a caller-supplied account.",
                        f.name
                    ),
                    "Check the program account against a known id \
                     (e.g. `require_keys_eq!(program.key(), expected::ID)`), or use Anchor's \
                     typed `Program<'info, T>` which enforces the program id for you."
                        .to_string(),
                ));
            }
        }
    }
}

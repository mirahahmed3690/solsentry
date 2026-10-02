//! Rule: unchecked integer arithmetic in instruction handlers.
//!
//! Raw `+ - *` (and their `+= -= *=` forms) on-chain can silently overflow or
//! underflow, draining or inflating balances. Solana programs should use
//! `checked_add` / `checked_sub` / `checked_mul` (method calls, which this rule
//! deliberately does NOT flag). v1 heuristic: flag binary arithmetic ops inside
//! instruction bodies; refine with type-awareness in v2.

use super::{Context, Rule};
use crate::finding::{Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, ExprBinary};

pub struct UncheckedMath;

#[derive(Default)]
struct MathVisitor {
    hits: Vec<usize>,
}

impl<'ast> Visit<'ast> for MathVisitor {
    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        let is_arith = matches!(
            node.op,
            BinOp::Add(_)
                | BinOp::Sub(_)
                | BinOp::Mul(_)
                | BinOp::AddAssign(_)
                | BinOp::SubAssign(_)
                | BinOp::MulAssign(_)
        );
        if is_arith {
            self.hits.push(node.span().start().line);
        }
        // keep descending so nested expressions are covered
        visit::visit_expr_binary(self, node);
    }
}

impl Rule for UncheckedMath {
    fn id(&self) -> &'static str {
        "unchecked-math"
    }

    fn description(&self) -> &'static str {
        "Raw +/-/* arithmetic in an instruction (use checked_* instead)"
    }

    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) {
        for f in &ctx.parsed.instructions {
            let mut v = MathVisitor::default();
            v.visit_block(&f.block);
            for line in v.hits {
                out.push(Finding::new(
                    self.id(),
                    Severity::High,
                    ctx.path,
                    line,
                    format!(
                        "Unchecked arithmetic in instruction `{}` may overflow/underflow.",
                        f.name
                    ),
                    "Replace with `checked_add` / `checked_sub` / `checked_mul` and \
                     handle the `None` case, or use a safe-math wrapper."
                        .to_string(),
                ));
            }
        }
    }
}

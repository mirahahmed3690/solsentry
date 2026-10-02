# solsentry

**A static analyzer for Solana/Anchor programs — "Slither for Anchor."**

Point it at an Anchor program and it flags Solana-specific vulnerability classes
with file, line, severity, and a concrete fix. Open source, CLI-native, zero
config.

The EVM world has mature open-source linters (Slither, Aderyn). Solana does not.
`solsentry` is a first step toward closing that gap — a developer-side tool you
can run before you ship and in CI.

```
$ solsentry ./programs/vault/src

+----------+-------------------+----------------------+--------------------------------------------------+
| SEVERITY | RULE              | LOCATION             | ISSUE                                             |
+----------+-------------------+----------------------+--------------------------------------------------+
| HIGH     | missing-signer    | lib.rs:26            | `authority` acts as an authority but is not a     |
|          |                   |                      | Signer; anyone can supply this account.          |
| HIGH     | unchecked-math    | lib.rs:13            | Unchecked arithmetic may overflow/underflow.     |
| MEDIUM   | missing-has-one   | lib.rs:21            | `vault` is mutated but not tied to an authority. |
| MEDIUM   | unchecked-account | lib.rs:26            | Raw AccountInfo with no constraint / CHECK doc.  |
+----------+-------------------+----------------------+--------------------------------------------------+
4 finding(s): 2 high, 2 medium, 0 low, 0 info
```

## Why these classes?

Each rule maps to a well-documented, real-world Solana bug class — the kind that
has drained live programs. References: [Neodyme's Solana security
workshop](https://workshop.neodyme.io/) and the [Sealevel Attacks
repo](https://github.com/coral-xyz/sealevel-attacks).

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `missing-signer` | High | An authority account that is never required to sign — anyone can pass it in. |
| `unchecked-account` | Medium | `AccountInfo` / `UncheckedAccount` with no constraint and no `/// CHECK:` doc. Owner and type go unverified. |
| `missing-has-one` | Medium | A mutable state account not bound to the context's authority via `has_one` / `seeds`. |
| `unchecked-math` | High | Raw `+ - *` (and `+= -= *=`) in an instruction. Use `checked_*`. |

> **v1 status:** these are AST-based heuristics, not a full semantic model. They
> aim for high signal on the common cases; expect to tune. The roadmap below
> adds the harder classes and reduces false positives.

## Install

```bash
git clone https://github.com/<you>/solsentry
cd solsentry
cargo install --path .
```

Requires a Rust toolchain ([rustup](https://rustup.rs)).

## Usage

```bash
solsentry ./programs/my_program/src   # scan a directory
solsentry src/lib.rs                   # scan one file
solsentry --json ./src                 # machine-readable output
solsentry --list                       # list all rules
solsentry --fail-on medium ./src       # exit 1 if any Medium+ finding (for CI)
```

Exit code is `1` when a finding at or above `--fail-on` (default `high`) is
present — drop it into CI to block vulnerable merges.

## How it works

1. **Load** — walk the path for `.rs` files (skipping `target/`, `.git/`).
2. **Parse** — `syn` turns each file into an AST; the Anchor layer extracts
   `#[derive(Accounts)]` structs (with per-field `#[account(...)]` constraints)
   and the instruction handlers inside `#[program]`.
3. **Check** — every rule implements a small `Rule` trait and inspects that
   structure.
4. **Report** — a colored table, or JSON.

### Adding a rule

Adding a vulnerability class is one file:

```rust
// src/rules/my_rule.rs
use super::{Context, Rule};
use crate::finding::{Finding, Severity};

pub struct MyRule;
impl Rule for MyRule {
    fn id(&self) -> &'static str { "my-rule" }
    fn description(&self) -> &'static str { "..." }
    fn check(&self, ctx: &Context, out: &mut Vec<Finding>) { /* ... */ }
}
```

...then register it in `src/rules/mod.rs::all_rules()`. That's the whole
extension surface.

## Roadmap

- **v2** — arbitrary-CPI, PDA bump checks, duplicate mutable accounts, account
  closing/revival, type confusion (discriminator); inline `// sentry:ignore`;
  rule config; **SARIF output** for GitHub code scanning.
- **v3** — detection-rate **benchmark** against Sealevel-Attacks / Neodyme
  examples (published in this README); optional AI pass that explains the
  exploit and suggests a fix; GitHub Action that comments on PRs.

## License

MIT.

//! solsentry — an open-source static analyzer for Solana/Anchor programs.
//! "Slither for Anchor." Point it at a program and it flags Solana-specific
//! vulnerability classes with file:line, severity, and a fix.

mod finding;
mod loader;
mod parse;
mod report;
mod rules;

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

use finding::{Finding, Severity};
use rules::Context;

#[derive(Parser)]
#[command(
    name = "solsentry",
    version,
    about = "Static analyzer for Solana/Anchor programs (Slither for Anchor)"
)]
struct Cli {
    /// Path to a program directory or a single .rs file.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit findings as JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// List the available rules and exit.
    #[arg(long)]
    list: bool,

    /// Exit with code 1 if any finding at this severity or above is present.
    /// One of: high, medium, low, info. Default: high.
    #[arg(long, default_value = "high")]
    fail_on: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.list {
        for r in rules::all_rules() {
            println!("{:<22} {}", r.id(), r.description());
        }
        return ExitCode::SUCCESS;
    }

    let files = loader::collect_rs_files(&cli.path);
    if files.is_empty() {
        eprintln!("No .rs files found under {}", cli.path.display());
        return ExitCode::SUCCESS;
    }

    let registry = rules::all_rules();
    let mut findings: Vec<Finding> = Vec::new();

    for file in &files {
        let src = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: could not read {}: {e}", file.display());
                continue;
            }
        };
        let syntax = match parse::anchor::parse_source(&src) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("warning: skipping {} (parse error: {e})", file.display());
                continue;
            }
        };
        let parsed = parse::anchor::extract(&syntax);
        let path_str = file.display().to_string();
        let ctx = Context {
            path: &path_str,
            parsed: &parsed,
        };
        for rule in &registry {
            rule.check(&ctx, &mut findings);
        }
    }

    // Stable ordering: by file, then line, then severity.
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then((a.severity as u8).cmp(&(b.severity as u8)))
    });

    if cli.json {
        if report::print_json(&findings).is_err() {
            return ExitCode::FAILURE;
        }
    } else {
        report::print_table(&findings);
        report::print_summary(&findings);
    }

    let threshold = parse_severity(&cli.fail_on);
    let tripped = findings
        .iter()
        .any(|f| (f.severity as u8) <= (threshold as u8));
    if tripped {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::High,
    }
}

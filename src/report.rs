//! Output: a colored terminal table, or machine-readable JSON.

use crate::finding::{Finding, Severity};
use comfy_table::{Cell, Color, ContentArrangement, Table};
use owo_colors::OwoColorize;

pub fn print_table(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", "No issues found.".green().bold());
        return;
    }

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["SEVERITY", "RULE", "LOCATION", "ISSUE"]);

    for f in findings {
        let sev_cell = match f.severity {
            Severity::High => Cell::new(f.severity.label()).fg(Color::Red),
            Severity::Medium => Cell::new(f.severity.label()).fg(Color::Yellow),
            Severity::Low => Cell::new(f.severity.label()).fg(Color::Blue),
            Severity::Info => Cell::new(f.severity.label()).fg(Color::Grey),
        };
        table.add_row(vec![
            sev_cell,
            Cell::new(&f.rule),
            Cell::new(format!("{}:{}", f.file, f.line)),
            Cell::new(format!("{}\n↳ fix: {}", f.message, f.fix)),
        ]);
    }

    println!("{table}");
}

pub fn print_json(findings: &[Finding]) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}

pub fn print_summary(findings: &[Finding]) {
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    let high = count(Severity::High);
    let med = count(Severity::Medium);
    let low = count(Severity::Low);
    let info = count(Severity::Info);

    let line = format!(
        "{} finding(s): {} high, {} medium, {} low, {} info",
        findings.len(),
        high,
        med,
        low,
        info
    );
    if high > 0 {
        eprintln!("{}", line.red().bold());
    } else if med > 0 {
        eprintln!("{}", line.yellow().bold());
    } else {
        eprintln!("{}", line.green().bold());
    }
}

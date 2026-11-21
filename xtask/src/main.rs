//! xtask — workspace tooling.
//!
//! Current commands:
//!   * `clauses` — compute spec-clause coverage across the PNP specs: for each level, how
//!     many clauses have a `#[clause(...)]` test in `crates/parolnet-conformance`.
//!   * `clauses --check` — fail unless every MUST and every SHOULD clause has a test and
//!     every `#[clause]` id is one a spec publishes. MAY clauses are reported, not required.
//!     Clauses marked `[DEPRECATED]` in a spec are not counted. Used in CI.
//!   * `clauses --report` — regenerate the registry table of specs/SPEC-INDEX.md (versions,
//!     statuses, clause counts, coverage) and its date.
//!   * `clauses --check-index` — fail if `--report` would change specs/SPEC-INDEX.md. Used
//!     in CI.
//!   * `vectors --validate` — parse every specs/vectors/PNP-XXX/*.json and
//!     ensure its declared `clause` field references a real clause ID.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(about = "ParolNet workspace tooling", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compute spec-clause coverage.
    Clauses {
        /// Fail with exit code 1 unless every MUST and every SHOULD clause has a test.
        #[arg(long)]
        check: bool,
        /// Regenerate the registry table of specs/SPEC-INDEX.md.
        #[arg(long)]
        report: bool,
        /// Fail with exit code 1 if specs/SPEC-INDEX.md is not what `--report` writes.
        #[arg(long)]
        check_index: bool,
    },
    /// Validate that every specs/vectors/PNP-XXX/*.json parses and
    /// references a real clause ID.
    Vectors {
        #[arg(long)]
        validate: bool,
    },
}

fn workspace_root() -> PathBuf {
    // xtask binary runs with CWD set to workspace root when invoked via alias.
    // Fall back to CARGO_MANIFEST_DIR/.. for manual `cargo run -p xtask` calls.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if cwd.join("specs").is_dir() && cwd.join("Cargo.toml").is_file() {
        return cwd;
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p
}

// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Clauses {
            check,
            report,
            check_index,
        } => run_clauses(check, report, check_index),
        Cmd::Vectors { validate } => run_vectors(validate),
    }
}

// ---- clause coverage ------------------------------------------------------

/// The normative clauses of one spec, by level.
#[derive(Debug, Default, Clone)]
struct ClauseSet {
    must: BTreeSet<String>,
    should: BTreeSet<String>,
    may: BTreeSet<String>,
    /// Clauses marked `[DEPRECATED]` in the spec text: still published (ids are never
    /// recycled), no longer normative, so not counted and not required to have a test.
    deprecated: BTreeSet<String>,
}

impl ClauseSet {
    fn insert(&mut self, id: &str) {
        if id.contains("-MUST-") {
            self.must.insert(id.to_string());
        } else if id.contains("-SHOULD-") {
            self.should.insert(id.to_string());
        } else if id.contains("-MAY-") {
            self.may.insert(id.to_string());
        }
    }

    fn retire(&mut self, id: &str) {
        self.must.remove(id);
        self.should.remove(id);
        self.may.remove(id);
        self.deprecated.insert(id.to_string());
    }

    fn all(&self) -> impl Iterator<Item = &String> {
        self.must
            .iter()
            .chain(&self.should)
            .chain(&self.may)
            .chain(&self.deprecated)
    }
}

fn clause_regex() -> Regex {
    Regex::new(r"\bPNP-(\d{3})-(MUST|SHOULD|MAY)-(\d{3})\b").unwrap()
}

/// `**PNP-001-MUST-042** [DEPRECATED]` (the bold markers are optional): the marker follows
/// the clause id directly, as SPEC-INDEX.md's "Clause ID Grammar" prescribes.
fn deprecated_regex() -> Regex {
    Regex::new(r"\b(PNP-\d{3}-(?:MUST|SHOULD|MAY)-\d{3})\b\**\s*\[DEPRECATED\]").unwrap()
}

/// Version, status and date as a spec's header states them.
#[derive(Debug, Default, Clone)]
struct SpecMeta {
    heading: String,
    version: String,
    status: String,
    date: String,
}

fn parse_meta(text: &str) -> SpecMeta {
    // Two header styles are in use: `### Version: 0.14` and `**Version:** 0.7`; the date is
    // `Date` or `Last-Updated`. Only the header (the lines before the first `---` or `## `)
    // is searched.
    let field =
        Regex::new(r"^(?:###\s*|\*\*)(Status|Version|Date|Last-Updated):\**\s*(.+?)\s*$").unwrap();
    let mut meta = SpecMeta::default();
    for line in text.lines() {
        if line.starts_with("---") || line.starts_with("## ") {
            break;
        }
        if let Some(h) = line.strip_prefix("# ") {
            let title = h.split_once(':').map(|(_, t)| t).unwrap_or(h);
            meta.heading = title.trim().to_string();
        } else if let Some(c) = field.captures(line) {
            let value = c[2].to_string();
            match &c[1] {
                "Status" => meta.status = value,
                "Version" => meta.version = value,
                _ => meta.date = value,
            }
        }
    }
    meta
}

struct Spec {
    clauses: ClauseSet,
    meta: SpecMeta,
}

fn collect_specs(root: &Path) -> Result<BTreeMap<String, Spec>> {
    let re = clause_regex();
    let dep = deprecated_regex();
    let name_re = Regex::new(r"^(PNP-\d{3})-").unwrap();
    let mut clauses: BTreeMap<String, ClauseSet> = BTreeMap::new();
    let mut metas: BTreeMap<String, SpecMeta> = BTreeMap::new();
    let mut retired: Vec<String> = Vec::new();
    let specs = root.join("specs");
    for e in WalkDir::new(&specs).max_depth(1).sort_by_file_name() {
        let e = e?;
        let path = e.path();
        if path.extension().and_then(|s| s.to_str()) != Some("md") {
            continue;
        }
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let Some(own) = name_re.captures(fname).map(|c| c[1].to_string()) else {
            continue;
        };
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        metas.insert(own.clone(), parse_meta(&text));
        clauses.entry(own).or_default();
        // A clause id belongs to the spec its number names, wherever it is mentioned.
        for cap in re.captures_iter(&text) {
            let spec = format!("PNP-{}", &cap[1]);
            clauses.entry(spec).or_default().insert(&cap[0]);
        }
        for cap in dep.captures_iter(&text) {
            retired.push(cap[1].to_string());
        }
    }
    for id in &retired {
        if let Some(set) = clauses.get_mut(&id[..7]) {
            set.retire(id);
        }
    }
    Ok(clauses
        .into_iter()
        .map(|(name, set)| {
            let meta = metas.remove(&name).unwrap_or_default();
            (name, Spec { clauses: set, meta })
        })
        .collect())
}

fn collect_spec_clauses(root: &Path) -> Result<BTreeMap<String, ClauseSet>> {
    Ok(collect_specs(root)?
        .into_iter()
        .map(|(name, spec)| (name, spec.clauses))
        .collect())
}

fn collect_conformance_clauses(root: &Path) -> Result<BTreeSet<String>> {
    // Scan only the conformance crate's tests/ and src/ for #[clause(...)].
    let re = Regex::new(r#"#\[clause\(([^)]*)\)\]"#).unwrap();
    let id_re = clause_regex();
    let mut out = BTreeSet::new();
    let dirs = [
        root.join("crates/parolnet-conformance/tests"),
        root.join("crates/parolnet-conformance/src"),
    ];
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for e in WalkDir::new(&dir) {
            let e = e?;
            if !e.file_type().is_file() {
                continue;
            }
            if e.path().extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(e.path())
                .with_context(|| format!("read {}", e.path().display()))?;
            for cap in re.captures_iter(&text) {
                for id_cap in id_re.captures_iter(&cap[1]) {
                    out.insert(id_cap[0].to_string());
                }
            }
        }
    }
    Ok(out)
}

/// Covered / total for one level.
#[derive(Clone, Copy, Default)]
struct Tally {
    covered: usize,
    total: usize,
}

impl Tally {
    fn of(ids: &BTreeSet<String>, covered: &BTreeSet<String>) -> Tally {
        Tally {
            covered: ids.iter().filter(|id| covered.contains(*id)).count(),
            total: ids.len(),
        }
    }

    fn pct(self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            100.0 * self.covered as f64 / self.total as f64
        }
    }

    fn add(&mut self, other: Tally) {
        self.covered += other.covered;
        self.total += other.total;
    }
}

impl std::fmt::Display for Tally {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.covered, self.total)
    }
}

struct Coverage {
    spec: String,
    meta: SpecMeta,
    must: Tally,
    should: Tally,
    may: Tally,
    deprecated: usize,
}

fn coverage_rows(specs: &BTreeMap<String, Spec>, covered: &BTreeSet<String>) -> Vec<Coverage> {
    specs
        .iter()
        .map(|(name, spec)| Coverage {
            spec: name.clone(),
            meta: spec.meta.clone(),
            must: Tally::of(&spec.clauses.must, covered),
            should: Tally::of(&spec.clauses.should, covered),
            may: Tally::of(&spec.clauses.may, covered),
            deprecated: spec.clauses.deprecated.len(),
        })
        .collect()
}

fn totals(rows: &[Coverage]) -> (Tally, Tally, Tally) {
    let mut t = (Tally::default(), Tally::default(), Tally::default());
    for r in rows {
        t.0.add(r.must);
        t.1.add(r.should);
        t.2.add(r.may);
    }
    t
}

fn print_ids(label: &str, ids: &[&String]) {
    if ids.is_empty() {
        return;
    }
    let full = std::env::var("XTASK_FULL").is_ok();
    let shown = if full { ids.len() } else { ids.len().min(40) };
    eprintln!("{label} ({}):", ids.len());
    for id in &ids[..shown] {
        eprintln!("  {id}");
    }
    if shown < ids.len() {
        eprintln!(
            "  ... {} more (set XTASK_FULL=1 to see all)",
            ids.len() - shown
        );
    }
}

fn run_clauses(check: bool, report: bool, check_index: bool) -> Result<()> {
    let root = workspace_root();
    let specs = collect_specs(&root)?;
    let covered = collect_conformance_clauses(&root)?;
    let rows = coverage_rows(&specs, &covered);

    println!(
        "{:<10}  {:>14}  {:>14}  {:>12}",
        "Spec", "MUST", "SHOULD", "MAY"
    );
    println!("{}", "-".repeat(58));
    for r in &rows {
        println!(
            "{:<10}  {:>9} {:>3.0}%  {:>9} {:>3.0}%  {:>7} {:>3.0}%",
            r.spec,
            r.must.to_string(),
            r.must.pct().floor(),
            r.should.to_string(),
            r.should.pct().floor(),
            r.may.to_string(),
            r.may.pct().floor(),
        );
    }
    println!("{}", "-".repeat(58));
    let (must, should, may) = totals(&rows);
    println!(
        "{:<10}  {:>9} {:>3.0}%  {:>9} {:>3.0}%  {:>7} {:>3.0}%",
        "TOTAL",
        must.to_string(),
        must.pct().floor(),
        should.to_string(),
        should.pct().floor(),
        may.to_string(),
        may.pct().floor(),
    );
    let deprecated: usize = rows.iter().map(|r| r.deprecated).sum();
    if deprecated > 0 {
        println!("({deprecated} clause(s) marked [DEPRECATED] are not counted)");
    }

    let uncovered = |pick: fn(&ClauseSet) -> &BTreeSet<String>| -> Vec<&String> {
        specs
            .values()
            .flat_map(|s| pick(&s.clauses).iter())
            .filter(|id| !covered.contains(*id))
            .collect()
    };
    let uncovered_must = uncovered(|c| &c.must);
    let uncovered_should = uncovered(|c| &c.should);
    let uncovered_may = uncovered(|c| &c.may);
    // A test pinned to an id no spec publishes proves nothing about any clause.
    let published: BTreeSet<&String> = specs.values().flat_map(|s| s.clauses.all()).collect();
    let unknown: Vec<&String> = covered
        .iter()
        .filter(|id| !published.contains(id))
        .collect();

    if !uncovered_may.is_empty() {
        // Informational: an implementation need not take an option, and an option it does not
        // take has nothing to test.
        println!(
            "\nMAY clauses without a test ({}): {}",
            uncovered_may.len(),
            uncovered_may
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    if report {
        let p = root.join("specs/SPEC-INDEX.md");
        let text = std::fs::read_to_string(&p)?;
        std::fs::write(&p, render_spec_index(&text, &rows))?;
        println!("\nRewrote specs/SPEC-INDEX.md (registry table and date).");
    }

    let mut failed = false;
    if check_index {
        let p = root.join("specs/SPEC-INDEX.md");
        let text = std::fs::read_to_string(&p)?;
        if render_spec_index(&text, &rows) != text {
            eprintln!(
                "\nindex check FAILED: specs/SPEC-INDEX.md is out of date; run \
                 `cargo xtask clauses --report` and commit the result"
            );
            failed = true;
        } else {
            println!("\nindex check PASSED");
        }
    }

    if check {
        // The gate: every MUST and every SHOULD has a conformance test, and every test names
        // a published clause. MAY coverage is reported above, never required.
        if uncovered_must.is_empty() && uncovered_should.is_empty() && unknown.is_empty() {
            println!("\nclause check PASSED");
        } else {
            eprintln!("\nclause check FAILED");
            print_ids("MUST clauses without a conformance test", &uncovered_must);
            print_ids(
                "SHOULD clauses without a conformance test",
                &uncovered_should,
            );
            print_ids("#[clause] ids that no spec publishes", &unknown);
            failed = true;
        }
    }
    if failed {
        std::process::exit(1);
    }
    Ok(())
}

// ---- SPEC-INDEX.md --------------------------------------------------------

fn registry_spec(line: &str) -> Option<String> {
    let re = Regex::new(r"^\|\s*(PNP-\d{3})\s*\|").unwrap();
    re.captures(line).map(|c| c[1].to_string())
}

fn coverage_cell(must: Tally, should: Tally, may: Tally) -> String {
    format!("M {must} · S {should} · MAY {may}")
}

/// The index with its generated parts rewritten: the `Last-Updated` line (the newest spec
/// date, so the output depends on the specs and the tests alone) and the registry table
/// (one row per spec file, then the totals). Titles are kept from the existing rows; a spec
/// with no row yet takes its own heading. Everything else is prose and is left alone.
fn render_spec_index(text: &str, rows: &[Coverage]) -> String {
    let mut titles: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        if let Some(spec) = registry_spec(line) {
            let cols: Vec<&str> = line.split('|').collect();
            if let Some(title) = cols.get(2) {
                titles.insert(spec, title.trim().to_string());
            }
        }
    }
    let newest = rows
        .iter()
        .map(|r| r.meta.date.as_str())
        .max()
        .unwrap_or_default();
    let mut table: Vec<String> = rows
        .iter()
        .map(|r| {
            let title = titles
                .get(&r.spec)
                .cloned()
                .unwrap_or_else(|| r.meta.heading.clone());
            format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                r.spec,
                title,
                r.meta.version,
                r.meta.status,
                r.must.total,
                r.should.total,
                r.may.total,
                r.must.total + r.should.total + r.may.total,
                coverage_cell(r.must, r.should, r.may),
            )
        })
        .collect();
    let (must, should, may) = totals(rows);
    table.push(format!(
        "| **Totals** | — | — | — | **{}** | **{}** | **{}** | **{}** | **{}** |",
        must.total,
        should.total,
        may.total,
        must.total + should.total + may.total,
        coverage_cell(must, should, may),
    ));

    let mut out: Vec<String> = Vec::new();
    let mut table_written = false;
    for line in text.lines() {
        if line.starts_with("**Last-Updated:**") {
            out.push(format!("**Last-Updated:** {newest}"));
        } else if registry_spec(line).is_some() || line.starts_with("| **Totals** |") {
            if !table_written {
                out.append(&mut table);
                table_written = true;
            }
        } else {
            out.push(line.to_string());
        }
    }
    let mut out = out.join("\n");
    out.push('\n');
    out
}

// ---- vectors --------------------------------------------------------------

fn run_vectors(_validate: bool) -> Result<()> {
    let root = workspace_root();
    let vectors_root = root.join("specs/vectors");
    if !vectors_root.is_dir() {
        println!("no specs/vectors directory yet — skipping");
        return Ok(());
    }
    let clause_ids: BTreeSet<String> = collect_spec_clauses(&root)?
        .into_values()
        .flat_map(|cs| {
            cs.must
                .into_iter()
                .chain(cs.should)
                .chain(cs.may)
                .chain(cs.deprecated)
        })
        .collect();

    let mut count = 0usize;
    let mut bad = 0usize;
    for e in WalkDir::new(&vectors_root) {
        let e = e?;
        if !e.file_type().is_file() {
            continue;
        }
        if e.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let raw = std::fs::read_to_string(e.path())?;
        let v: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("{}: parse failed — {err}", e.path().display());
                bad += 1;
                continue;
            }
        };
        // Accept either a single `clause` string field or a `clauses` array.
        let mut clauses: Vec<String> = Vec::new();
        if let Some(s) = v.get("clause").and_then(|c| c.as_str()) {
            clauses.push(s.to_string());
        }
        if let Some(arr) = v.get("clauses").and_then(|c| c.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    clauses.push(s.to_string());
                }
            }
        }
        if clauses.is_empty() {
            eprintln!(
                "{}: missing `clause` or `clauses` field",
                e.path().display()
            );
            bad += 1;
            continue;
        }
        let mut file_bad = false;
        for clause in &clauses {
            if !clause_regex().is_match(clause) {
                eprintln!("{}: invalid clause id {clause:?}", e.path().display());
                file_bad = true;
                continue;
            }
            if !clause_ids.contains(clause) {
                eprintln!(
                    "{}: clause {clause} does not match any published spec clause",
                    e.path().display()
                );
                file_bad = true;
            }
        }
        if file_bad {
            bad += 1;
        }
    }
    println!("scanned {count} vectors — {bad} failed");
    if bad > 0 {
        std::process::exit(1);
    }
    Ok(())
}

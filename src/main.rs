use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::Command,
};
use uuid::Uuid;
use walkdir::WalkDir;
use zip::{
    CompressionMethod, DateTime as ZipDateTime, ZipArchive, ZipWriter, write::SimpleFileOptions,
};

const PLAYBOOK_ID: &str = "DD-v0";
const RUNLOG_SCHEMA: &str = "epi.runlog.v1";
const SEAL_SCHEMA: &str = "epi.seal.v1";
const RUNLOG_FILE: &str = "epi.runlog.v1.json";
const SEAL_FILE: &str = "epi.seal.v1.json";
const DECISION_PACK_SCHEMA: &str = "epi.decision_pack.v1";
const CLAIMS_SCHEMA: &str = "epi.claims.v1";
const DRIFT_REPORT_SCHEMA: &str = "epi.drift_report.v1";
const DECISION_PACK_FILE: &str = "epi.decision_pack.v1.json";
const CLAIMS_FILE: &str = "epi.claims.v1.json";
const DRIFT_REPORT_FILE: &str = "epi.drift_report.v1.json";
const DRIFT_MARKDOWN_FILE: &str = "DRIFT.md";
const DECISION_PACK_MANIFEST_FILE: &str = "DecisionPack.manifest.json";
const DECISION_PACK_SEAL_FILE: &str = "DecisionPack.seal.json";
const DECISION_PACK_HTML_FILE: &str = "DecisionPack.html";
const DECISION_PACK_PDF_FILE: &str = "DecisionPack.pdf";
const DECISION_PACK_PDF_SHA256_FILE: &str = "SHA256.txt";
const QUOTE_JSON_FILE: &str = "Quote.json";
const DECISION_PACK_ARTIFACT_BASENAMES: [&str; 10] = [
    DECISION_PACK_MANIFEST_FILE,
    DECISION_PACK_SEAL_FILE,
    DECISION_PACK_HTML_FILE,
    DECISION_PACK_PDF_FILE,
    DECISION_PACK_PDF_SHA256_FILE,
    "REPLAY.md",
    QUOTE_JSON_FILE,
    "Quote.md",
    "DataShareChecklist.md",
    "cupola.manifest.json",
];
const PACK_FILE: &str = "pack.zip";
const VERIFY_FILE: &str = "verify.json";
const MIN_DECISION_PACK_PDF_BYTES: u64 = 50_000;
const PDF_RENDER_SCRIPT_REL: &str = "scripts/render_decision_pack_pdf.mjs";

#[derive(Parser, Debug)]
#[command(name = "leo", version, about = "Local EPI orchestration harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run(RunArgs),
    Pack(PackArgs),
    Diff(DiffArgs),
    Doctor(DoctorArgs),
}

#[derive(Args, Debug, Clone, Default)]
struct ToolPathArgs {
    #[arg(long)]
    cupola_bin: Option<PathBuf>,
    #[arg(long)]
    aegis_bin: Option<PathBuf>,
    #[arg(long)]
    epi_bin: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
struct RunArgs {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    intake: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = "alpha")]
    query: String,
    #[arg(long, default_value_t = 20)]
    limit: u32,
    #[command(flatten)]
    tools: ToolPathArgs,
}

#[derive(Args, Debug, Clone)]
struct PackArgs {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    intake: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = "alpha")]
    query: String,
    #[arg(long, default_value_t = 20)]
    limit: u32,
    #[command(flatten)]
    tools: ToolPathArgs,
}

#[derive(Args, Debug, Clone)]
struct DiffArgs {
    /// Baseline pack zip path.
    #[arg(long)]
    a: PathBuf,
    /// Candidate pack zip path.
    #[arg(long)]
    b: PathBuf,
    /// Output directory for epi.drift_report.v1.json.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug, Clone)]
struct DoctorArgs {
    #[arg(long)]
    out: Option<PathBuf>,
    #[command(flatten)]
    tools: ToolPathArgs,
}

#[derive(Serialize)]
struct RunLogV1 {
    schema_version: String,
    schema: String,
    run_id: String,
    created_at: String,
    inputs: RunInputs,
    steps: Vec<RunStep>,
    stop_reason: String,
}

#[derive(Serialize)]
struct RunInputs {
    vault: String,
    intake: String,
    out_dir: String,
    playbook_id: String,
    tool_versions: ToolVersions,
}

#[derive(Serialize)]
struct ToolVersions {
    cupola_cli: String,
    aegis: String,
    epi_cli: String,
}

#[derive(Serialize)]
struct RunStep {
    step_id: String,
    tool: String,
    argv: Vec<String>,
    started_at: String,
    finished_at: String,
    status: String,
    stdout_path: String,
    stderr_path: String,
    outputs: Vec<StepOutput>,
}

#[derive(Serialize)]
struct StepOutput {
    path: String,
    sha256: String,
}

#[derive(Serialize)]
struct SealV1 {
    schema_version: String,
    schema: String,
    created_at: String,
    pack_sha256: String,
    pack_files: Vec<PackFileHash>,
    replay: ReplayInstructions,
}

#[derive(Serialize)]
struct PackFileHash {
    rel_path: String,
    sha256: String,
}

#[derive(Serialize)]
struct ReplayInstructions {
    commands: Vec<String>,
}

#[derive(Serialize)]
struct DecisionPackV1 {
    schema_version: String,
    generated_at: String,
    pack_meta: DecisionPackMeta,
    toolchain: DecisionPackToolchain,
    artifacts: Vec<DecisionPackArtifact>,
}

#[derive(Serialize)]
struct DecisionPackHeaderV1 {
    schema_version: String,
    pack_meta: DecisionPackMeta,
}

#[derive(Serialize)]
struct DecisionPackMeta {
    pack_type: String,
    library: String,
    client: String,
    engagement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pack_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    ok: bool,
    pack_zip: String,
    pack_type: String,
    library: String,
    client: String,
    engagement: String,
    pack_meta: VerifyPackMeta,
    missing_files: Vec<String>,
    schema_errors: Vec<String>,
    mismatches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_status_success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_error: Option<String>,
    verifier_json: Value,
}

#[derive(Debug, Serialize)]
struct VerifyPackMeta {
    pack_type: String,
    library: String,
    client: String,
    engagement: String,
}

#[derive(Serialize)]
struct DecisionPackToolchain {
    leo: String,
    aegis: String,
    cupola: String,
}

#[derive(Serialize)]
struct DecisionPackArtifact {
    rel_path: String,
    sha256: String,
}

#[derive(Serialize)]
struct ClaimsV1 {
    schema_version: String,
    generated_at: String,
    claims: Vec<ClaimV1>,
}

#[derive(Serialize)]
struct ClaimV1 {
    claim_id: String,
    title: String,
    status: String,
    impact: String,
    evidence: Vec<ClaimEvidenceRefV1>,
    evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Serialize)]
struct ClaimEvidenceRefV1 {
    rel_path: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize)]
struct DriftReportV1 {
    schema_version: String,
    generated_at: String,
    a_sha256: String,
    b_sha256: String,
    changes: Vec<DriftChange>,
    drift_summary: DriftSummaryV1,
}

#[derive(Serialize)]
struct DriftChange {
    kind: String,
    entry_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    a_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<DriftJsonSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    affected_claims: Vec<String>,
}

#[derive(Serialize)]
struct DriftJsonSummary {
    metric: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    a_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b_count: Option<usize>,
}

#[derive(Serialize)]
struct DriftSummaryV1 {
    counts: DriftSummaryCounts,
    claims_affected_count: usize,
    by_impact: DriftSummaryByImpact,
}

#[derive(Serialize)]
struct DriftSummaryCounts {
    added: usize,
    removed: usize,
    modified: usize,
}

#[derive(Serialize)]
struct DriftSummaryByImpact {
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Clone)]
struct ZipEntrySnapshot {
    sha256: String,
    summary_bytes: Option<Vec<u8>>,
}

struct ClaimSeed {
    title: String,
    status: String,
    impact: String,
    evidence_rel_paths: Vec<String>,
    notes: Option<String>,
}

struct DriftClaimRef {
    claim_id: String,
    impact: String,
    evidence_rel_paths: Vec<String>,
}

struct ImpactedClaimSummary {
    claim_id: String,
    impact: String,
    changed_paths: Vec<String>,
}

struct StepSpec {
    step_id: &'static str,
    tool: &'static str,
    cwd: PathBuf,
    argv: Vec<String>,
}

struct BundleContext {
    out_dir: PathBuf,
    pack_dir: PathBuf,
    vault: PathBuf,
    intake: PathBuf,
    cupola_bin: PathBuf,
    cupola_repo: PathBuf,
    aegis_bin: PathBuf,
    aegis_data_dir: PathBuf,
    query: String,
    limit: u32,
}

#[derive(Default)]
struct DecisionPackMetaDraft {
    pack_type: Option<String>,
    library: Option<String>,
    client: Option<String>,
    engagement: Option<String>,
    pack_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct LeoConfig {
    cupola_repo: Option<PathBuf>,
    cupola_bin: Option<PathBuf>,
    aegis_bin: Option<PathBuf>,
    epi_bin: Option<PathBuf>,
}

#[derive(Clone)]
struct ToolResolution {
    tool_name: &'static str,
    env_var: &'static str,
    selected_path: PathBuf,
    selected_source: &'static str,
    selected_exists: bool,
    candidates: Vec<ToolCandidate>,
}

#[derive(Clone)]
struct ToolCandidate {
    source: &'static str,
    path: PathBuf,
    exists: bool,
}

struct ResolvedTools {
    leo_root: PathBuf,
    config_path: PathBuf,
    config: LeoConfig,
    cupola: ToolResolution,
    aegis: ToolResolution,
    epi: ToolResolution,
}

fn main() {
    if let Err(err) = run_cli() {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => run(args),
        Commands::Pack(args) => pack_only(args),
        Commands::Diff(args) => diff(args),
        Commands::Doctor(args) => doctor(args),
    }
}

fn run(args: RunArgs) -> Result<()> {
    let tools = resolve_tools(&args.tools)?;
    let cupola_bin = require_tool_binary(&tools.cupola)?;
    let aegis_bin = require_tool_binary(&tools.aegis)?;
    let epi_bin = require_tool_binary(&tools.epi)?;
    let out_dir = absolutize(&args.out)?;
    let cupola_repo_for_aegis = resolve_cupola_repo_for_aegis(&cupola_bin);
    let aegis_data_dir = resolve_aegis_data_dir(&aegis_bin)?;
    ensure_outside_vault(&args.vault, &out_dir)?;

    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create out dir: {}", out_dir.display()))?;

    let logs_dir = out_dir.join("_logs");
    let pack_dir = out_dir.join("pack");
    fs::create_dir_all(&logs_dir)
        .with_context(|| format!("failed to create logs dir: {}", logs_dir.display()))?;
    fs::create_dir_all(&pack_dir)
        .with_context(|| format!("failed to create pack dir: {}", pack_dir.display()))?;

    let tool_versions = ToolVersions {
        cupola_cli: detect_tool_version(&cupola_bin),
        aegis: detect_tool_version(&aegis_bin),
        epi_cli: detect_tool_version(&epi_bin),
    };

    let cupola_argv = vec![
        path_to_string(&cupola_bin),
        "export-epi".to_string(),
        "--vault".to_string(),
        path_to_string(&args.vault),
        "--out".to_string(),
        path_to_string(&pack_dir),
        "--query".to_string(),
        args.query.clone(),
        "--limit".to_string(),
        args.limit.to_string(),
    ];

    let aegis_argv = vec![
        path_to_string(&aegis_bin),
        "run".to_string(),
        "--vault".to_string(),
        path_to_string(&args.vault),
        "--cupola-repo".to_string(),
        path_to_string(&cupola_repo_for_aegis),
        "--intake".to_string(),
        path_to_string(&args.intake),
        "--out".to_string(),
        path_to_string(&pack_dir),
        "--data-dir".to_string(),
        path_to_string(&aegis_data_dir),
    ];
    let cupola_cwd = command_working_dir_for_binary(&cupola_bin)?;
    let aegis_cwd = out_dir.clone();
    let epi_cwd = command_working_dir_for_binary(&epi_bin)?;

    let mut steps = Vec::new();
    let cupola_step = execute_step(
        StepSpec {
            step_id: "step-01-cupola-export-epi",
            tool: "cupola-cli",
            cwd: cupola_cwd,
            argv: cupola_argv.clone(),
        },
        &out_dir,
        &logs_dir,
        &pack_dir,
    )?;
    let mut any_failed = cupola_step.status != "ok";
    steps.push(cupola_step);

    let aegis_step = execute_step(
        StepSpec {
            step_id: "step-02-aegis-run",
            tool: "aegis",
            cwd: aegis_cwd,
            argv: aegis_argv.clone(),
        },
        &out_dir,
        &logs_dir,
        &pack_dir,
    )?;
    let aegis_ok = aegis_step.status == "ok";
    any_failed |= !aegis_ok;
    steps.push(aegis_step);

    let render_step = execute_render_pdf_step(
        &tools.leo_root,
        &args.intake,
        aegis_ok,
        StepSpec {
            step_id: "step-03-render-pdf",
            tool: "node",
            cwd: tools.leo_root.clone(),
            argv: vec!["node".to_string(), PDF_RENDER_SCRIPT_REL.to_string()],
        },
        &out_dir,
        &logs_dir,
        &pack_dir,
    )?;
    any_failed |= render_step.status != "ok";
    steps.push(render_step);

    let runlog = RunLogV1 {
        schema_version: RUNLOG_SCHEMA.to_string(),
        schema: RUNLOG_SCHEMA.to_string(),
        run_id: Uuid::new_v4().to_string(),
        created_at: now_rfc3339_utc(),
        inputs: RunInputs {
            vault: path_to_string(&absolutize(&args.vault)?),
            intake: path_to_string(&absolutize(&args.intake)?),
            out_dir: path_to_string(&out_dir),
            playbook_id: PLAYBOOK_ID.to_string(),
            tool_versions,
        },
        steps,
        stop_reason: if any_failed {
            "tool_failed".to_string()
        } else {
            "success".to_string()
        },
    };

    write_json_pretty(&pack_dir.join(RUNLOG_FILE), &runlog)?;

    let bundle_context = BundleContext {
        out_dir: out_dir.clone(),
        pack_dir: pack_dir.clone(),
        vault: args.vault.clone(),
        intake: args.intake.clone(),
        cupola_bin,
        cupola_repo: cupola_repo_for_aegis,
        aegis_bin,
        aegis_data_dir: aegis_data_dir.clone(),
        query: args.query.clone(),
        limit: args.limit,
    };
    let mut package_error: Option<String> = None;
    if any_failed {
        package_error = Some(bundle_skip_reason_for_failed_steps(&pack_dir));
    } else if let Err(err) = package_bundle(&bundle_context) {
        package_error = Some(format!("{err:#}"));
    }

    let pack_zip = out_dir.join(PACK_FILE);
    let verify_step = execute_verify_pack_step(
        StepSpec {
            step_id: "step-04-verify",
            tool: "epi-cli",
            cwd: epi_cwd,
            argv: vec![
                path_to_string(&epi_bin),
                "verify".to_string(),
                path_to_string(&pack_zip),
                "--json".to_string(),
            ],
        },
        &out_dir,
        &logs_dir,
        &pack_dir,
        &pack_zip,
        package_error.as_deref(),
    )?;
    any_failed |= package_error.is_some() || verify_step.status != "ok";

    if any_failed {
        bail!("one or more tool steps failed; stop_reason=tool_failed");
    }

    Ok(())
}

fn pack_only(args: PackArgs) -> Result<()> {
    let tools = resolve_tools(&args.tools)?;
    let cupola_bin = require_tool_binary(&tools.cupola)?;
    let aegis_bin = require_tool_binary(&tools.aegis)?;
    let aegis_data_dir = resolve_aegis_data_dir(&aegis_bin)?;
    let out_dir = absolutize(&args.out)?;
    let cupola_repo_for_aegis = resolve_cupola_repo_for_aegis(&cupola_bin);
    ensure_outside_vault(&args.vault, &out_dir)?;
    let pack_dir = out_dir.join("pack");
    if !pack_dir.exists() {
        bail!("pack staging folder is missing: {}", pack_dir.display());
    }

    let bundle_context = BundleContext {
        out_dir,
        pack_dir,
        vault: args.vault,
        intake: args.intake,
        cupola_bin,
        cupola_repo: cupola_repo_for_aegis,
        aegis_bin,
        aegis_data_dir,
        query: args.query,
        limit: args.limit,
    };
    package_bundle(&bundle_context)
}

fn diff(args: DiffArgs) -> Result<()> {
    let a_zip = absolutize(&args.a)?;
    if !a_zip.exists() {
        bail!("--a path does not exist: {}", a_zip.display());
    }
    if !is_zip_path(&a_zip) {
        bail!("--a must point to a .zip file: {}", a_zip.display());
    }

    let b_zip = absolutize(&args.b)?;
    if !b_zip.exists() {
        bail!("--b path does not exist: {}", b_zip.display());
    }
    if !is_zip_path(&b_zip) {
        bail!("--b must point to a .zip file: {}", b_zip.display());
    }

    let out_dir = absolutize(&args.out)?;
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create output dir: {}", out_dir.display()))?;

    let report = build_drift_report_from_zip_paths(&a_zip, &b_zip)?;
    write_json_pretty(&out_dir.join(DRIFT_REPORT_FILE), &report)?;

    let markdown = render_drift_markdown(&report, &a_zip, &b_zip);
    fs::write(out_dir.join(DRIFT_MARKDOWN_FILE), markdown)
        .with_context(|| format!("failed to write {}", DRIFT_MARKDOWN_FILE))?;

    Ok(())
}

fn doctor(args: DoctorArgs) -> Result<()> {
    let default_out_dir = std::env::temp_dir().join("leo-doctor-out");
    let out_dir = absolutize(args.out.as_ref().unwrap_or(&default_out_dir))?;
    let tools = resolve_tools(&args.tools)?;
    let exe_path = std::env::current_exe().context("failed to resolve current executable path")?;

    println!("LEO Doctor");
    println!("exe_path: {}", exe_path.display());
    println!("leo_root: {}", tools.leo_root.display());
    println!(
        "config: {} ({})",
        tools.config_path.display(),
        if tools.config_path.exists() {
            "present"
        } else {
            "missing"
        }
    );
    if let Some(repo) = &tools.config.cupola_repo {
        println!(
            "config.cupola_repo: {}",
            resolve_relative_to_root(&tools.leo_root, repo).display()
        );
    }

    let mut failed = false;
    failed |= print_writable_check("%TEMP%", &std::env::temp_dir());
    failed |= print_writable_check("out_dir", &out_dir);
    failed |= print_tool_check(&tools.cupola);
    failed |= print_tool_check(&tools.aegis);
    failed |= print_tool_check(&tools.epi);
    if tools.aegis.selected_exists {
        match resolve_aegis_data_dir(&tools.aegis.selected_path) {
            Ok(aegis_data_dir) => {
                let packs_dir = aegis_data_dir.join("packs");
                println!(
                    "aegis_data_dir: {} [packs={} path={}]",
                    aegis_data_dir.display(),
                    if packs_dir.is_dir() { "ok" } else { "missing" },
                    packs_dir.display()
                );
            }
            Err(err) => {
                println!("aegis_data_dir: [error] {err:#}");
                failed = true;
            }
        }
    } else {
        println!("aegis_data_dir: unresolved [skipped: aegis binary missing]");
    }

    if failed {
        bail!("doctor checks failed");
    }

    println!("doctor: OK");
    Ok(())
}

fn resolve_tools(args: &ToolPathArgs) -> Result<ResolvedTools> {
    let leo_root = detect_leo_root()?;
    let config_path = leo_root.join("config").join("leo.toml");
    let config = load_leo_config(&config_path)?;

    let cupola = resolve_tool_path(
        "cupola-cli.exe",
        "CUPOLA_CLI",
        leo_root.join("tools").join("cupola").join("cupola-cli.exe"),
        args.cupola_bin.as_ref(),
        config.cupola_bin.as_ref(),
        &leo_root,
    );
    let aegis = resolve_tool_path(
        "aegis.exe",
        "AEGIS_EXE",
        leo_root.join("tools").join("aegis").join("aegis.exe"),
        args.aegis_bin.as_ref(),
        config.aegis_bin.as_ref(),
        &leo_root,
    );
    let epi = resolve_tool_path(
        "epi-cli.exe",
        "EPI_CLI",
        leo_root.join("tools").join("epi").join("epi-cli.exe"),
        args.epi_bin.as_ref(),
        config.epi_bin.as_ref(),
        &leo_root,
    );

    Ok(ResolvedTools {
        leo_root,
        config_path,
        config,
        cupola,
        aegis,
        epi,
    })
}

fn detect_leo_root() -> Result<PathBuf> {
    let exe_path = std::env::current_exe().context("failed to resolve current executable path")?;
    let parent = exe_path.parent().context(format!(
        "failed to resolve executable parent directory: {}",
        exe_path.display()
    ))?;
    Ok(parent.to_path_buf())
}

fn resolve_tool_path(
    tool_name: &'static str,
    env_var: &'static str,
    embedded_path: PathBuf,
    cli_override: Option<&PathBuf>,
    config_path: Option<&PathBuf>,
    leo_root: &Path,
) -> ToolResolution {
    let cli_path = cli_override.map(|path| resolve_relative_to_cwd(path));
    let config_candidate = config_path.map(|path| resolve_relative_to_root(leo_root, path));
    let env_candidate = read_env_path(env_var).map(|path| resolve_relative_to_cwd(&path));

    let mut candidates = Vec::new();
    if let Some(path) = &cli_path {
        candidates.push(ToolCandidate {
            source: "cli",
            path: path.clone(),
            exists: path.is_file(),
        });
    }
    candidates.push(ToolCandidate {
        source: "tools",
        path: embedded_path.clone(),
        exists: embedded_path.is_file(),
    });
    if let Some(path) = &config_candidate {
        candidates.push(ToolCandidate {
            source: "config",
            path: path.clone(),
            exists: path.is_file(),
        });
    }
    if let Some(path) = &env_candidate {
        candidates.push(ToolCandidate {
            source: "env",
            path: path.clone(),
            exists: path.is_file(),
        });
    }

    let (selected_source, selected_path) = if let Some(path) = cli_path {
        ("cli", path)
    } else if embedded_path.is_file() {
        ("tools", embedded_path.clone())
    } else if let Some(path) = &config_candidate
        && path.is_file()
    {
        ("config", path.clone())
    } else if let Some(path) = &env_candidate
        && path.is_file()
    {
        ("env", path.clone())
    } else if let Some(path) = config_candidate {
        ("config", path)
    } else if let Some(path) = env_candidate {
        ("env", path)
    } else {
        ("tools", embedded_path.clone())
    };

    ToolResolution {
        tool_name,
        env_var,
        selected_exists: selected_path.is_file(),
        selected_path,
        selected_source,
        candidates,
    }
}

fn read_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn resolve_relative_to_cwd(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return normalize_lexical(path);
    }
    match std::env::current_dir() {
        Ok(cwd) => normalize_lexical(&cwd.join(path)),
        Err(_) => path.to_path_buf(),
    }
}

fn resolve_relative_to_root(leo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return normalize_lexical(path);
    }
    normalize_lexical(&leo_root.join(path))
}

fn load_leo_config(path: &Path) -> Result<LeoConfig> {
    if !path.exists() {
        return Ok(LeoConfig::default());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    toml::from_str::<LeoConfig>(&raw)
        .with_context(|| format!("failed to parse TOML config: {}", path.display()))
}

fn require_tool_binary(tool: &ToolResolution) -> Result<PathBuf> {
    if tool.selected_exists {
        return Ok(tool.selected_path.clone());
    }

    let attempted = tool
        .candidates
        .iter()
        .map(|candidate| {
            format!(
                "  - {}: {} [{}]",
                candidate.source,
                candidate.path.display(),
                if candidate.exists { "ok" } else { "missing" }
            )
        })
        .collect::<Vec<String>>()
        .join("\n");

    bail!(
        "missing tool '{}'\nselected: {} (source={})\nattempted paths:\n{}\nfix: {}",
        tool.tool_name,
        tool.selected_path.display(),
        tool.selected_source,
        attempted,
        tool_fix_hint(tool)
    );
}

fn print_writable_check(label: &str, path: &Path) -> bool {
    match verify_writable_dir(path) {
        Ok(()) => {
            println!("{label}: {} [ok]", path.display());
            false
        }
        Err(err) => {
            println!("{label}: {} [error] {err:#}", path.display());
            true
        }
    }
}

fn verify_writable_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory for check: {}", path.display()))?;
    let probe_path = path.join(format!(".leo-doctor-write-{}.tmp", Uuid::new_v4()));
    fs::write(&probe_path, b"leo-doctor")
        .with_context(|| format!("failed to write probe file: {}", probe_path.display()))?;
    fs::remove_file(&probe_path)
        .with_context(|| format!("failed to remove probe file: {}", probe_path.display()))?;
    Ok(())
}

fn print_tool_check(tool: &ToolResolution) -> bool {
    let selected_ok = tool.selected_exists;

    println!(
        "{}: selected={} (source={})",
        tool.tool_name,
        tool.selected_path.display(),
        tool.selected_source
    );
    for candidate in &tool.candidates {
        println!(
            "  candidate[{source}]={path} [{status}]",
            source = candidate.source,
            path = candidate.path.display(),
            status = if candidate.exists { "ok" } else { "missing" }
        );
    }
    println!("  env_var={}", tool.env_var);

    if selected_ok {
        let version = detect_tool_version(&tool.selected_path);
        if let Some(commit) = extract_git_commit_hash(&version) {
            println!("  version={version} (git={commit})");
        } else {
            println!("  version={version}");
        }
    } else {
        println!("  version=unknown");
        println!("  fix={}", tool_fix_hint(tool));
    }

    !selected_ok
}

fn tool_fix_hint(tool: &ToolResolution) -> String {
    let cli_flag = match tool.tool_name {
        "cupola-cli.exe" => "--cupola-bin",
        "aegis.exe" => "--aegis-bin",
        "epi-cli.exe" => "--epi-bin",
        _ => "--tool-bin",
    };
    format!(
        "pass {cli_flag} <PATH> or set {} to a valid executable path",
        tool.env_var
    )
}

fn command_working_dir_for_binary(binary_path: &Path) -> Result<PathBuf> {
    match binary_path.parent() {
        Some(parent) => Ok(parent.to_path_buf()),
        None => std::env::current_dir().context(format!(
            "failed to resolve working directory for {}",
            binary_path.display()
        )),
    }
}

fn resolve_cupola_repo_for_aegis(cupola_bin: &Path) -> PathBuf {
    let Some(binary_dir) = cupola_bin.parent() else {
        return PathBuf::from(".");
    };

    let is_release_dir = binary_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("release"));
    if is_release_dir && let Some(target_dir) = binary_dir.parent() {
        let is_target_dir = target_dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("target"));
        if is_target_dir && let Some(repo_root) = target_dir.parent() {
            return repo_root.to_path_buf();
        }
    }

    binary_dir.to_path_buf()
}

fn resolve_aegis_data_dir(aegis_bin: &Path) -> Result<PathBuf> {
    let mut attempts = Vec::new();

    if let Some(env_path) = read_env_path("AEGIS_DATA_DIR") {
        let candidate = resolve_relative_to_cwd(&env_path);
        attempts.push(format_aegis_data_dir_attempt(
            "env AEGIS_DATA_DIR",
            &candidate,
        ));
        if candidate.is_dir() {
            return validate_aegis_data_dir(&candidate, "env AEGIS_DATA_DIR", &attempts);
        }
    }

    if let Some(repo_data_dir) = infer_repo_data_dir_from_aegis_bin(aegis_bin) {
        attempts.push(format_aegis_data_dir_attempt(
            "repo inference <repo>\\target\\{release|debug}\\aegis.exe -> <repo>\\data",
            &repo_data_dir,
        ));
        return validate_aegis_data_dir(
            &repo_data_dir,
            "aegis binary at <repo>\\target\\{release|debug}\\aegis.exe",
            &attempts,
        );
    }

    if let Some(bin_dir) = aegis_bin.parent() {
        let candidate = normalize_lexical(&bin_dir.join("data"));
        attempts.push(format_aegis_data_dir_attempt(
            "packaged inference <exe_dir>\\data",
            &candidate,
        ));
        if candidate.is_dir() {
            return validate_aegis_data_dir(
                &candidate,
                "aegis binary packaged alongside <exe_dir>\\data",
                &attempts,
            );
        }
    } else {
        attempts.push(format!(
            "packaged inference <exe_dir>\\data => skipped [missing executable parent for {}]",
            aegis_bin.display()
        ));
    }

    bail!(
        "unable to resolve AEGIS data directory for {}\nattempted:\n  - {}\nfix: set AEGIS_DATA_DIR to a valid <DATA_DIR> containing a 'packs' directory",
        aegis_bin.display(),
        attempts.join("\n  - ")
    );
}

fn infer_repo_data_dir_from_aegis_bin(aegis_bin: &Path) -> Option<PathBuf> {
    let binary_name = aegis_bin.file_name()?.to_str()?;
    if !binary_name.eq_ignore_ascii_case("aegis.exe") && !binary_name.eq_ignore_ascii_case("aegis")
    {
        return None;
    }

    let exe_dir = aegis_bin.parent()?;
    let profile = exe_dir.file_name()?.to_str()?;
    if !profile.eq_ignore_ascii_case("release") && !profile.eq_ignore_ascii_case("debug") {
        return None;
    }

    let target_dir = exe_dir.parent()?;
    if !target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("target"))
    {
        return None;
    }

    let repo_root = target_dir.parent()?;
    Some(normalize_lexical(&repo_root.join("data")))
}

fn format_aegis_data_dir_attempt(label: &str, candidate: &Path) -> String {
    let normalized = normalize_lexical(candidate);
    let packs = normalized.join("packs");
    format!(
        "{label}: {} [data_dir={}, packs={} ({})]",
        normalized.display(),
        if normalized.is_dir() { "ok" } else { "missing" },
        if packs.is_dir() { "ok" } else { "missing" },
        packs.display()
    )
}

fn validate_aegis_data_dir(candidate: &Path, source: &str, attempts: &[String]) -> Result<PathBuf> {
    let normalized = normalize_lexical(candidate);
    let packs_dir = normalized.join("packs");
    if !normalized.is_dir() || !packs_dir.is_dir() {
        bail!(
            "invalid AEGIS data directory from {source}: {}\nexpected an existing data directory with a 'packs' subdirectory ({})\nattempted:\n  - {}\nfix: set AEGIS_DATA_DIR to a valid <DATA_DIR> containing a 'packs' directory",
            normalized.display(),
            packs_dir.display(),
            attempts.join("\n  - ")
        );
    }
    Ok(normalized)
}

fn resolve_pdf_render_script(leo_root: &Path) -> Result<PathBuf> {
    let mut candidates = vec![normalize_lexical(&leo_root.join(PDF_RENDER_SCRIPT_REL))];
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(normalize_lexical(&cwd.join(PDF_RENDER_SCRIPT_REL)));
    }
    candidates.push(normalize_lexical(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PDF_RENDER_SCRIPT_REL),
    ));

    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }

    let attempted = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<String>>()
        .join(", ");
    bail!(
        "missing pdf renderer script '{}' (attempted: {})",
        PDF_RENDER_SCRIPT_REL,
        attempted
    );
}

fn execute_step(
    spec: StepSpec,
    out_dir: &Path,
    logs_dir: &Path,
    pack_dir: &Path,
) -> Result<RunStep> {
    execute_internal_step(spec, out_dir, logs_dir, pack_dir, |spec, stdout, stderr| {
        let output = run_command_capture(&spec.cwd, &spec.argv)?;
        stdout.extend_from_slice(&output.stdout);
        stderr.extend_from_slice(&output.stderr);
        if output.status.success() {
            Ok(())
        } else {
            bail!(
                "command exited with status {}",
                output
                    .status
                    .code()
                    .map_or_else(|| "unknown".to_string(), |code| code.to_string())
            );
        }
    })
}

fn execute_render_pdf_step(
    leo_root: &Path,
    intake_path: &Path,
    write_prerender_stub: bool,
    spec: StepSpec,
    out_dir: &Path,
    logs_dir: &Path,
    pack_dir: &Path,
) -> Result<RunStep> {
    execute_internal_step(spec, out_dir, logs_dir, pack_dir, |_, stdout, stderr| {
        if write_prerender_stub {
            write_prerender_decision_pack_stub(pack_dir, intake_path)?;
        }
        let script_path = resolve_pdf_render_script(leo_root)?;
        let html_rel = resolve_required_decision_pack_html_rel(pack_dir)?;
        let html_path = pack_dir.join(&html_rel);
        let pdf_dir = html_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "failed to resolve parent directory for {}",
                html_path.display()
            )
        })?;
        let pdf_path = pdf_dir.join(DECISION_PACK_PDF_FILE);
        let sha_path = pdf_dir.join(DECISION_PACK_PDF_SHA256_FILE);

        let argv = vec![
            "node".to_string(),
            path_to_string(&script_path),
            "--html".to_string(),
            path_to_string(&html_path),
            "--pdf".to_string(),
            path_to_string(&pdf_path),
        ];

        let output = run_command_capture(leo_root, &argv)?;
        stdout.extend_from_slice(&output.stdout);
        stderr.extend_from_slice(&output.stderr);
        if !output.status.success() {
            bail!(
                "pdf render command failed with status {}",
                output
                    .status
                    .code()
                    .map_or_else(|| "unknown".to_string(), |code| code.to_string())
            );
        }

        if !pdf_path.is_file() {
            bail!(
                "{} is missing next to {} after render: {}",
                DECISION_PACK_PDF_FILE,
                DECISION_PACK_HTML_FILE,
                pdf_path.display()
            );
        }

        let pdf_size = fs::metadata(&pdf_path)
            .with_context(|| format!("failed to stat rendered pdf: {}", pdf_path.display()))?
            .len();
        if pdf_size < MIN_DECISION_PACK_PDF_BYTES {
            bail!(
                "{} is too small ({} bytes, expected >= {} bytes): {}",
                DECISION_PACK_PDF_FILE,
                pdf_size,
                MIN_DECISION_PACK_PDF_BYTES,
                pdf_path.display()
            );
        }

        let pdf_sha = sha256_file(&pdf_path)?;
        fs::write(&sha_path, format!("{pdf_sha}  {}\n", pdf_path.display()))
            .with_context(|| format!("failed to write {}", sha_path.display()))?;
        if !sha_path.is_file() {
            bail!(
                "{} is missing next to {}: {}",
                DECISION_PACK_PDF_SHA256_FILE,
                DECISION_PACK_PDF_FILE,
                sha_path.display()
            );
        }
        Ok(())
    })
}

fn resolve_required_decision_pack_html_rel(pack_dir: &Path) -> Result<PathBuf> {
    find_first_file_by_basename(pack_dir, DECISION_PACK_HTML_FILE)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is missing in {}",
            DECISION_PACK_HTML_FILE,
            pack_dir.display()
        )
    })
}

fn write_prerender_decision_pack_stub(pack_dir: &Path, intake_path: &Path) -> Result<()> {
    let _ = resolve_required_decision_pack_html_rel(pack_dir)?;
    let intake_bytes = fs::read(intake_path)
        .with_context(|| format!("failed to read intake: {}", intake_path.display()))?;
    let intake_json: Value = serde_json::from_slice(&intake_bytes)
        .with_context(|| format!("failed to parse intake JSON: {}", intake_path.display()))?;

    let stub = DecisionPackHeaderV1 {
        schema_version: DECISION_PACK_SCHEMA.to_string(),
        pack_meta: DecisionPackMeta {
            pack_type: required_intake_metadata_field(
                &intake_json,
                intake_path,
                "pack_type",
                &["/pack_type", "/intake/pack_type"],
            )?,
            library: required_intake_metadata_field(
                &intake_json,
                intake_path,
                "library_pack",
                &["/library_pack", "/intake/library_pack"],
            )?,
            client: required_intake_metadata_field(
                &intake_json,
                intake_path,
                "client_id",
                &["/client_id", "/intake/client_id"],
            )?,
            engagement: required_intake_metadata_field(
                &intake_json,
                intake_path,
                "engagement_id",
                &["/engagement_id", "/intake/engagement_id"],
            )?,
            pack_id: None,
        },
    };
    write_json_pretty(&pack_dir.join(DECISION_PACK_FILE), &stub)
}

fn required_intake_metadata_field(
    intake_json: &Value,
    intake_path: &Path,
    field_name: &str,
    pointers: &[&str],
) -> Result<String> {
    first_non_empty_json_pointer(intake_json, pointers)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing required intake metadata field '{}' in {}",
                field_name,
                intake_path.display()
            )
        })
}

fn execute_verify_pack_step(
    spec: StepSpec,
    out_dir: &Path,
    logs_dir: &Path,
    pack_dir: &Path,
    pack_zip: &Path,
    package_error: Option<&str>,
) -> Result<RunStep> {
    execute_internal_step(spec, out_dir, logs_dir, pack_dir, |spec, stdout, stderr| {
        let verify_path = out_dir.join(VERIFY_FILE);
        if let Some(err) = package_error {
            let message = format!("pack bundling failed before verify: {err}");
            stderr.extend_from_slice(message.as_bytes());
            stderr.push(b'\n');
            let report =
                build_verify_report(pack_zip, pack_dir, &Value::Null, false, Some(message));
            write_json_pretty(&verify_path, &report)?;
            bail!("pack bundling failed before verifier execution");
        }

        if !pack_zip.is_file() {
            let message = format!("missing pack zip: {}", pack_zip.display());
            stderr.extend_from_slice(message.as_bytes());
            stderr.push(b'\n');
            let report =
                build_verify_report(pack_zip, pack_dir, &Value::Null, false, Some(message));
            write_json_pretty(&verify_path, &report)?;
            bail!("pack zip is missing");
        }

        let output = run_command_capture(&spec.cwd, &spec.argv)?;
        stdout.extend_from_slice(&output.stdout);
        stderr.extend_from_slice(&output.stderr);

        let mut verifier_error = if output.status.success() {
            None
        } else {
            Some(format!(
                "epi verifier exited with status {}",
                output
                    .status
                    .code()
                    .map_or_else(|| "unknown".to_string(), |code| code.to_string())
            ))
        };

        let verifier_json = if output.stdout.is_empty() {
            verifier_error = merge_error(
                verifier_error,
                "epi verifier returned empty JSON output".to_string(),
            );
            Value::Null
        } else {
            match serde_json::from_slice::<Value>(&output.stdout) {
                Ok(value) => value,
                Err(err) => {
                    verifier_error = merge_error(
                        verifier_error,
                        format!("epi verifier emitted invalid JSON: {err}"),
                    );
                    Value::Null
                }
            }
        };

        let report = build_verify_report(
            pack_zip,
            pack_dir,
            &verifier_json,
            output.status.success(),
            verifier_error,
        );
        write_json_pretty(&verify_path, &report)?;
        if report.ok {
            Ok(())
        } else {
            bail!(
                "verification failed (ok=false). details written to {}",
                verify_path.display()
            );
        }
    })
}

fn execute_internal_step<F>(
    spec: StepSpec,
    out_dir: &Path,
    logs_dir: &Path,
    pack_dir: &Path,
    runner: F,
) -> Result<RunStep>
where
    F: FnOnce(&StepSpec, &mut Vec<u8>, &mut Vec<u8>) -> Result<()>,
{
    let before = snapshot_hashes(pack_dir)?;
    let started_at = now_rfc3339_utc();

    let stdout_path = logs_dir.join(format!("{}.stdout.log", spec.step_id));
    let stderr_path = logs_dir.join(format!("{}.stderr.log", spec.step_id));
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();

    let status = match runner(&spec, &mut stdout_bytes, &mut stderr_bytes) {
        Ok(()) => "ok".to_string(),
        Err(err) => {
            if !stderr_bytes.is_empty() && !stderr_bytes.ends_with(b"\n") {
                stderr_bytes.push(b'\n');
            }
            stderr_bytes.extend_from_slice(format!("{err:#}\n").as_bytes());
            "error".to_string()
        }
    };
    let finished_at = now_rfc3339_utc();

    fs::write(&stdout_path, &stdout_bytes)
        .with_context(|| format!("failed to write stdout log: {}", stdout_path.display()))?;
    fs::write(&stderr_path, &stderr_bytes)
        .with_context(|| format!("failed to write stderr log: {}", stderr_path.display()))?;

    let after = snapshot_hashes(pack_dir)?;
    let outputs = diff_outputs(&before, &after);

    Ok(RunStep {
        step_id: spec.step_id.to_string(),
        tool: spec.tool.to_string(),
        argv: spec.argv,
        started_at,
        finished_at,
        status,
        stdout_path: relative_or_absolute_slash_path(&stdout_path, out_dir),
        stderr_path: relative_or_absolute_slash_path(&stderr_path, out_dir),
        outputs,
    })
}

fn package_bundle(context: &BundleContext) -> Result<()> {
    ensure_final_decision_pack_assets(&context.pack_dir)?;
    write_supporting_epi_files(context)?;

    let replay = ReplayInstructions {
        commands: build_replay_commands(context),
    };

    // We derive seal coverage from pack payload files excluding the seal itself to avoid
    // recursive self-hashing constraints.
    let pack_files = collect_pack_file_hashes(&context.pack_dir, true)?;
    let payload_zip = context.out_dir.join("pack.payload.tmp.zip");
    build_zip(&context.pack_dir, &payload_zip, true)?;
    let pack_sha256 = sha256_file(&payload_zip)?;
    if payload_zip.exists() {
        fs::remove_file(&payload_zip)
            .with_context(|| format!("failed to remove temp file: {}", payload_zip.display()))?;
    }

    let seal = SealV1 {
        schema_version: SEAL_SCHEMA.to_string(),
        schema: SEAL_SCHEMA.to_string(),
        created_at: now_rfc3339_utc(),
        pack_sha256,
        pack_files,
        replay,
    };
    write_json_pretty(&context.pack_dir.join(SEAL_FILE), &seal)?;

    let pack_zip = context.out_dir.join(PACK_FILE);
    bundle_pack_directory(&context.pack_dir, &pack_zip)?;
    Ok(())
}

fn bundle_skip_reason_for_failed_steps(pack_dir: &Path) -> String {
    match ensure_final_decision_pack_assets(pack_dir) {
        Ok(_) => "skipped pack bundling because a prior step failed".to_string(),
        Err(err) => format!("skipped pack bundling because a prior step failed: {err:#}"),
    }
}

fn ensure_final_decision_pack_assets(pack_dir: &Path) -> Result<PathBuf> {
    let html_rel = resolve_required_decision_pack_html_rel(pack_dir)?;
    let decision_pack_rel_dir = html_rel.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "failed to resolve parent directory for {}",
            pack_dir.join(&html_rel).display()
        )
    })?;

    let pdf_rel = decision_pack_rel_dir.join(DECISION_PACK_PDF_FILE);
    if !pack_dir.join(&pdf_rel).is_file() {
        bail!(
            "{} is missing next to {}: {}",
            DECISION_PACK_PDF_FILE,
            DECISION_PACK_HTML_FILE,
            pack_dir.join(&pdf_rel).display()
        );
    }

    let sha_rel = decision_pack_rel_dir.join(DECISION_PACK_PDF_SHA256_FILE);
    if !pack_dir.join(&sha_rel).is_file() {
        bail!(
            "{} is missing next to {}: {}",
            DECISION_PACK_PDF_SHA256_FILE,
            DECISION_PACK_PDF_FILE,
            pack_dir.join(&sha_rel).display()
        );
    }

    Ok(decision_pack_rel_dir.to_path_buf())
}

fn bundle_pack_directory(pack_dir: &Path, zip_path: &Path) -> Result<()> {
    ensure_final_decision_pack_assets(pack_dir)?;
    let staged_zip = zip_path.with_extension("tmp.zip");
    build_zip(pack_dir, &staged_zip, false)?;
    if zip_path.exists() {
        fs::remove_file(zip_path)
            .with_context(|| format!("failed to overwrite zip: {}", zip_path.display()))?;
    }
    fs::rename(&staged_zip, zip_path).with_context(|| {
        format!(
            "failed to move staged zip {} to {}",
            staged_zip.display(),
            zip_path.display()
        )
    })?;
    Ok(())
}

fn write_supporting_epi_files(context: &BundleContext) -> Result<()> {
    let decision_pack = build_decision_pack(context)?;
    write_json_pretty(&context.pack_dir.join(DECISION_PACK_FILE), &decision_pack)?;

    let claims = build_claims_from_pack_dir(&context.pack_dir)?;
    write_json_pretty(&context.pack_dir.join(CLAIMS_FILE), &claims)?;

    let drift_report = build_self_drift_report(&context.pack_dir)?;
    write_json_pretty(&context.pack_dir.join(DRIFT_REPORT_FILE), &drift_report)?;

    Ok(())
}

fn build_claims_from_pack_dir(pack_dir: &Path) -> Result<ClaimsV1> {
    let manifest_rel = find_first_file_by_basename(pack_dir, DECISION_PACK_MANIFEST_FILE)?;
    let html_rel = find_first_file_by_basename(pack_dir, DECISION_PACK_HTML_FILE)?;
    let quote_rel = find_first_file_by_basename(pack_dir, QUOTE_JSON_FILE)?;
    let manifest_ref = manifest_rel.as_ref().map(|path| normalize_rel_path(path));
    let html_ref = html_rel.as_ref().map(|path| normalize_rel_path(path));
    let quote_ref = quote_rel.as_ref().map(|path| normalize_rel_path(path));

    let mut claim_seeds = if let Some(manifest_rel_path) = &manifest_rel {
        let manifest_path = pack_dir.join(manifest_rel_path);
        let bytes = fs::read(&manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(manifest) => extract_claims_from_manifest(
                &manifest,
                manifest_ref
                    .as_deref()
                    .unwrap_or(DECISION_PACK_MANIFEST_FILE),
            ),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    if claim_seeds.is_empty()
        && let Some(html_rel_path) = &html_rel
    {
        let html_path = pack_dir.join(html_rel_path);
        let html = fs::read_to_string(&html_path)
            .with_context(|| format!("failed to read {}", html_path.display()))?;
        claim_seeds = extract_claims_from_html(
            &html,
            html_ref.as_deref().unwrap_or(DECISION_PACK_HTML_FILE),
        );
    }

    if claim_seeds.is_empty()
        && let Some(quote_rel_path) = &quote_rel
    {
        let quote_path = pack_dir.join(quote_rel_path);
        let bytes = fs::read(&quote_path)
            .with_context(|| format!("failed to read {}", quote_path.display()))?;
        if let Ok(quote) = serde_json::from_slice::<Value>(&bytes) {
            claim_seeds =
                extract_claims_from_quote(&quote, quote_ref.as_deref().unwrap_or(QUOTE_JSON_FILE));
        }
    }

    if claim_seeds.is_empty() {
        let mut evidence_rel_paths = Vec::new();
        if let Some(manifest_ref) = &manifest_ref {
            evidence_rel_paths.push(manifest_ref.clone());
        } else if let Some(html_ref) = &html_ref {
            evidence_rel_paths.push(html_ref.clone());
        } else if let Some(quote_ref) = &quote_ref {
            evidence_rel_paths.push(quote_ref.clone());
        }

        claim_seeds.push(ClaimSeed {
            title: "Decision pack claim".to_string(),
            status: "unknown".to_string(),
            impact: "low".to_string(),
            evidence_rel_paths,
            notes: Some("No structured claims were found in DecisionPack artifacts.".to_string()),
        });
    }

    let pack_hashes = snapshot_hashes(pack_dir)?;
    let mut claims = Vec::new();
    for seed in claim_seeds {
        let status = normalize_claim_status(&seed.status);
        let impact = normalize_or_infer_claim_impact(&seed.impact, &seed.title, &status);
        let evidence = resolve_claim_evidence(&seed.evidence_rel_paths, &pack_hashes);
        let evidence_refs = if evidence.is_empty() {
            stable_unique_sorted_strings(seed.evidence_rel_paths)
        } else {
            evidence
                .iter()
                .map(|item| item.rel_path.clone())
                .collect::<Vec<String>>()
        };
        let primary_evidence_ref = evidence_refs.first().map(String::as_str).unwrap_or("");

        claims.push(ClaimV1 {
            claim_id: deterministic_claim_id(&seed.title, primary_evidence_ref),
            title: normalize_claim_title(&seed.title),
            status,
            impact,
            evidence,
            evidence_refs,
            notes: normalize_claim_notes(seed.notes),
        });
    }
    sort_claims_deterministically(&mut claims);

    Ok(ClaimsV1 {
        schema_version: CLAIMS_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
        claims,
    })
}

fn build_decision_pack(context: &BundleContext) -> Result<DecisionPackV1> {
    let mut rel_paths = list_relative_files(&context.pack_dir)?;
    sort_paths_deterministically(&mut rel_paths);

    let mut artifacts = Vec::new();
    let mut pack_meta_source_rel: Option<PathBuf> = None;
    for rel in rel_paths {
        let file_name = rel.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if !DECISION_PACK_ARTIFACT_BASENAMES.contains(&file_name) {
            continue;
        }

        if pack_meta_source_rel.is_none() {
            pack_meta_source_rel = Some(rel.clone());
        }

        let rel_path = normalize_rel_path(&rel);
        let sha256 = sha256_file(&context.pack_dir.join(&rel))?;
        artifacts.push(DecisionPackArtifact { rel_path, sha256 });
    }

    let pack_meta = build_decision_pack_meta(context, pack_meta_source_rel.as_deref())?;

    Ok(DecisionPackV1 {
        schema_version: DECISION_PACK_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
        pack_meta,
        toolchain: DecisionPackToolchain {
            leo: option_env!("CARGO_PKG_VERSION")
                .unwrap_or("dev")
                .to_string(),
            aegis: "run".to_string(),
            cupola: "export-epi".to_string(),
        },
        artifacts,
    })
}

fn build_decision_pack_meta(
    context: &BundleContext,
    fallback_rel: Option<&Path>,
) -> Result<DecisionPackMeta> {
    let mut meta = DecisionPackMetaDraft::default();

    merge_pack_meta_from_json_file(&mut meta, &context.intake);
    merge_pack_meta_from_json_file(&mut meta, &context.pack_dir.join(DECISION_PACK_FILE));

    let manifest_rel = find_first_file_by_basename(&context.pack_dir, DECISION_PACK_MANIFEST_FILE)?;
    if let Some(rel_path) = &manifest_rel {
        merge_pack_meta_from_json_file(&mut meta, &context.pack_dir.join(rel_path));
    }

    let seal_rel = find_first_file_by_basename(&context.pack_dir, DECISION_PACK_SEAL_FILE)?;
    if let Some(rel_path) = &seal_rel {
        merge_pack_meta_from_json_file(&mut meta, &context.pack_dir.join(rel_path));
    }

    if let Some(source_rel) = manifest_rel
        .as_deref()
        .or(seal_rel.as_deref())
        .or(fallback_rel)
    {
        merge_pack_meta_from_rel_path(&mut meta, source_rel);
    }

    Ok(DecisionPackMeta {
        pack_type: require_pack_meta_field(&meta.pack_type, "pack_type")?,
        library: require_pack_meta_field(&meta.library, "library")?,
        client: require_pack_meta_field(&meta.client, "client")?,
        engagement: require_pack_meta_field(&meta.engagement, "engagement")?,
        pack_id: meta.pack_id,
    })
}

fn merge_pack_meta_from_json_file(meta: &mut DecisionPackMetaDraft, path: &Path) {
    if let Ok(bytes) = fs::read(path)
        && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
    {
        merge_pack_meta_from_json(meta, &value);
    }
}

fn merge_pack_meta_from_json(meta: &mut DecisionPackMetaDraft, value: &Value) {
    set_pack_meta_if_missing(
        &mut meta.pack_type,
        first_non_empty_json_pointer(
            value,
            &["/pack_meta/pack_type", "/pack_type", "/intake/pack_type"],
        ),
    );
    set_pack_meta_if_missing(
        &mut meta.library,
        first_non_empty_json_pointer(
            value,
            &[
                "/pack_meta/library",
                "/library",
                "/library_pack",
                "/intake/library",
                "/intake/library_pack",
            ],
        ),
    );
    set_pack_meta_if_missing(
        &mut meta.client,
        first_non_empty_json_pointer(
            value,
            &[
                "/pack_meta/client",
                "/client",
                "/client_id",
                "/intake/client",
                "/intake/client_id",
            ],
        ),
    );
    set_pack_meta_if_missing(
        &mut meta.engagement,
        first_non_empty_json_pointer(
            value,
            &[
                "/pack_meta/engagement",
                "/engagement",
                "/engagement_id",
                "/intake/engagement",
                "/intake/engagement_id",
            ],
        ),
    );
    set_pack_meta_if_missing(
        &mut meta.pack_id,
        first_non_empty_json_pointer(
            value,
            &["/pack_meta/pack_id", "/pack_id", "/intake/pack_id"],
        ),
    );
}

fn first_non_empty_json_pointer<'a>(value: &'a Value, pointers: &[&str]) -> Option<&'a str> {
    for pointer in pointers {
        if let Some(text) = value.pointer(pointer).and_then(value_non_empty_string) {
            return Some(text);
        }
    }
    None
}

fn set_pack_meta_if_missing(slot: &mut Option<String>, candidate: Option<&str>) {
    if slot.is_none()
        && let Some(value) = normalize_non_empty_metadata_value(candidate)
    {
        *slot = Some(value);
    }
}

fn merge_pack_meta_from_rel_path(meta: &mut DecisionPackMetaDraft, rel_path: &Path) {
    let Some(parent) = rel_path.parent() else {
        return;
    };

    let segments = parent
        .components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(segment.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<String>>();

    if segments.len() < 3 {
        return;
    }

    let base = segments.len() - 3;
    set_pack_meta_if_missing(&mut meta.client, Some(segments[base].as_str()));
    set_pack_meta_if_missing(&mut meta.engagement, Some(segments[base + 1].as_str()));
    set_pack_meta_if_missing(&mut meta.pack_id, Some(segments[base + 2].as_str()));
}

fn require_pack_meta_field(value: &Option<String>, field_name: &str) -> Result<String> {
    normalize_non_empty_metadata_value(value.as_deref()).ok_or_else(|| {
        anyhow::anyhow!(
            "missing required decision pack metadata field '{}' (expected run context, manifest, or <client>/<engagement>/PACK-xxx path)",
            field_name
        )
    })
}

fn normalize_non_empty_metadata_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn build_verify_report(
    pack_zip: &Path,
    pack_dir: &Path,
    verifier_json: &Value,
    verifier_command_success: bool,
    verifier_error: Option<String>,
) -> VerifyReport {
    let missing_files =
        extract_verify_string_list(verifier_json, &["/missing_files", "/details/missing_files"]);
    let schema_errors = extract_verify_string_list(
        verifier_json,
        &[
            "/schema_errors",
            "/invalid_json",
            "/details/schema_errors",
            "/details/invalid_json",
        ],
    );
    let mismatches = extract_verify_string_list(
        verifier_json,
        &[
            "/mismatches",
            "/schema_version_mismatches",
            "/details/mismatches",
            "/details/schema_version_mismatches",
        ],
    );
    let verifier_ok = verifier_json.pointer("/ok").and_then(Value::as_bool);
    let verifier_status_success = verifier_json
        .pointer("/status/success")
        .and_then(Value::as_bool);

    let mut merged_error = verifier_error;
    let pack_meta = match read_verify_pack_meta(pack_dir) {
        Ok(meta) => meta,
        Err(pack_dir_err) => match read_verify_pack_meta_from_zip(pack_zip) {
            Ok(meta) => meta,
            Err(pack_zip_err) => {
                merged_error = merge_error(
                    merged_error,
                    format!(
                        "failed to read decision pack metadata from pack_dir: {pack_dir_err:#}; fallback zip read also failed: {pack_zip_err:#}"
                    ),
                );
                VerifyPackMeta {
                    pack_type: String::new(),
                    library: String::new(),
                    client: String::new(),
                    engagement: String::new(),
                }
            }
        },
    };

    let meta_complete = verify_pack_meta_complete(&pack_meta);
    let verifier_passed = verifier_ok
        .or(verifier_status_success)
        .unwrap_or(verifier_command_success);

    let ok = verifier_command_success
        && verifier_passed
        && merged_error.is_none()
        && meta_complete
        && missing_files.is_empty()
        && schema_errors.is_empty()
        && mismatches.is_empty();

    let pack_type = pack_meta.pack_type.clone();
    let library = pack_meta.library.clone();
    let client = pack_meta.client.clone();
    let engagement = pack_meta.engagement.clone();

    VerifyReport {
        ok,
        pack_zip: path_to_string(pack_zip),
        pack_type,
        library,
        client,
        engagement,
        pack_meta,
        missing_files,
        schema_errors,
        mismatches,
        verifier_ok,
        verifier_status_success,
        verifier_error: merged_error,
        verifier_json: verifier_json.clone(),
    }
}

fn read_verify_pack_meta(pack_dir: &Path) -> Result<VerifyPackMeta> {
    let decision_pack_path = pack_dir.join(DECISION_PACK_FILE);
    let bytes = fs::read(&decision_pack_path)
        .with_context(|| format!("failed to read {}", decision_pack_path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", decision_pack_path.display()))?;
    parse_verify_pack_meta(&value, &decision_pack_path.display().to_string())
}

fn read_verify_pack_meta_from_zip(pack_zip: &Path) -> Result<VerifyPackMeta> {
    let file = fs::File::open(pack_zip).with_context(|| {
        format!(
            "failed to read zip for pack metadata: {}",
            pack_zip.display()
        )
    })?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("failed to open zip archive: {}", pack_zip.display()))?;
    let mut decision_pack_index: Option<usize> = None;

    for idx in 0..archive.len() {
        let entry = archive.by_index(idx).with_context(|| {
            format!(
                "failed to scan zip entry index {idx} in {}",
                pack_zip.display()
            )
        })?;
        let entry_name = normalize_zip_entry_path(entry.name());
        if entry_file_name(&entry_name).eq_ignore_ascii_case(DECISION_PACK_FILE) {
            decision_pack_index = Some(idx);
            break;
        }
    }

    let index = decision_pack_index.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is missing from zip archive {}",
            DECISION_PACK_FILE,
            pack_zip.display()
        )
    })?;
    let mut entry = archive.by_index(index).with_context(|| {
        format!(
            "failed to read zip entry index {index} from {}",
            pack_zip.display()
        )
    })?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).with_context(|| {
        format!(
            "failed to read {} from zip archive {}",
            DECISION_PACK_FILE,
            pack_zip.display()
        )
    })?;
    let value: Value = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse {} from zip archive {}",
            DECISION_PACK_FILE,
            pack_zip.display()
        )
    })?;
    let source = format!("{}!{}", pack_zip.display(), DECISION_PACK_FILE);
    parse_verify_pack_meta(&value, &source)
}

fn parse_verify_pack_meta(value: &Value, source: &str) -> Result<VerifyPackMeta> {
    let read_field = |field: &str| -> Result<String> {
        normalize_non_empty_metadata_value(
            value
                .pointer(&format!("/pack_meta/{field}"))
                .and_then(Value::as_str),
        )
        .ok_or_else(|| {
            anyhow::anyhow!(
                "pack metadata field '{}' is missing/blank in {}",
                field,
                source
            )
        })
    };

    Ok(VerifyPackMeta {
        pack_type: read_field("pack_type")?,
        library: read_field("library")?,
        client: read_field("client")?,
        engagement: read_field("engagement")?,
    })
}

fn extract_verify_string_list(value: &Value, pointers: &[&str]) -> Vec<String> {
    for pointer in pointers {
        if let Some(items) = value.pointer(pointer).and_then(Value::as_array) {
            let values = items
                .iter()
                .filter_map(|item| match item {
                    Value::String(text) => normalize_non_empty_metadata_value(Some(text)),
                    Value::Object(map) => {
                        for key in ["message", "error", "path", "field"] {
                            if let Some(text) = map
                                .get(key)
                                .and_then(Value::as_str)
                                .and_then(|text| normalize_non_empty_metadata_value(Some(text)))
                            {
                                return Some(text);
                            }
                        }
                        let rendered = item.to_string();
                        normalize_non_empty_metadata_value(Some(rendered.as_str()))
                    }
                    _ => {
                        let rendered = item.to_string();
                        normalize_non_empty_metadata_value(Some(rendered.as_str()))
                    }
                })
                .collect::<Vec<String>>();
            return stable_unique_sorted_strings(values);
        }
    }
    Vec::new()
}

fn merge_error(current: Option<String>, next: String) -> Option<String> {
    let next = next.trim().to_string();
    if next.is_empty() {
        return current;
    }
    match current {
        Some(current) if current.trim().is_empty() => Some(next),
        Some(current) => Some(format!("{current}; {next}")),
        None => Some(next),
    }
}

fn verify_pack_meta_complete(meta: &VerifyPackMeta) -> bool {
    !meta.pack_type.trim().is_empty()
        && !meta.library.trim().is_empty()
        && !meta.client.trim().is_empty()
        && !meta.engagement.trim().is_empty()
}

fn build_self_drift_report(pack_dir: &Path) -> Result<DriftReportV1> {
    let listing = snapshot_hashes(pack_dir)?;
    let snapshot_sha = sha256_of_hash_listing(&listing);
    Ok(DriftReportV1 {
        schema_version: DRIFT_REPORT_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
        a_sha256: snapshot_sha.clone(),
        b_sha256: snapshot_sha,
        changes: Vec::new(),
        drift_summary: build_drift_summary(&[], &[]),
    })
}

fn extract_claims_from_manifest(manifest: &Value, manifest_ref: &str) -> Vec<ClaimSeed> {
    let mut claims = extract_claims_from_control_results(manifest, manifest_ref);
    if claims.is_empty() {
        claims = extract_claims_from_intake(manifest, manifest_ref);
    }
    if claims.is_empty() {
        claims = extract_claims_from_query_log(manifest, manifest_ref);
    }
    claims
}

fn extract_claims_from_control_results(manifest: &Value, manifest_ref: &str) -> Vec<ClaimSeed> {
    let Some(control_results) = manifest.get("control_results").and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut control_ids: Vec<&String> = control_results.keys().collect();
    control_ids.sort_by(|left, right| {
        left.to_ascii_lowercase()
            .cmp(&right.to_ascii_lowercase())
            .then_with(|| left.cmp(right))
    });

    let mut claims = Vec::new();
    for control_id in control_ids {
        let Some(control_result) = control_results.get(control_id) else {
            continue;
        };

        let title = control_result
            .get("title")
            .and_then(value_non_empty_string)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| control_id.to_string());
        let status = control_result
            .get("status")
            .and_then(value_non_empty_string)
            .map(normalize_claim_status)
            .unwrap_or_else(|| "unknown".to_string());
        let impact = control_result
            .get("impact")
            .and_then(value_non_empty_string)
            .map(normalize_claim_impact)
            .unwrap_or_else(|| infer_claim_impact(&title, &status));
        let mut evidence_rel_paths =
            extract_evidence_rel_paths(control_result.get("evidence_refs"));
        if evidence_rel_paths.is_empty() {
            evidence_rel_paths.push(manifest_ref.to_string());
        }

        claims.push(ClaimSeed {
            title,
            status,
            impact,
            evidence_rel_paths,
            notes: Some(format!("control_id={control_id}")),
        });
    }

    claims
}

fn extract_claims_from_intake(manifest: &Value, manifest_ref: &str) -> Vec<ClaimSeed> {
    let Some(intake_claims) = manifest
        .pointer("/intake/claims")
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };

    let mut claim_keys: Vec<&String> = intake_claims.keys().collect();
    claim_keys.sort_by(|left, right| {
        left.to_ascii_lowercase()
            .cmp(&right.to_ascii_lowercase())
            .then_with(|| left.cmp(right))
    });

    let mut claims = Vec::new();
    for claim_key in claim_keys {
        let status = match intake_claims.get(claim_key) {
            Some(Value::Bool(true)) => "supported",
            _ => "unknown",
        };
        let impact = infer_claim_impact(claim_key, status);
        claims.push(ClaimSeed {
            title: claim_key.to_string(),
            status: status.to_string(),
            impact,
            evidence_rel_paths: vec![manifest_ref.to_string()],
            notes: Some("derived from intake.claims".to_string()),
        });
    }
    claims
}

fn extract_claims_from_query_log(manifest: &Value, manifest_ref: &str) -> Vec<ClaimSeed> {
    let Some(query_log) = manifest.get("query_log").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut claims = Vec::new();
    for (idx, entry) in query_log.iter().enumerate() {
        let query_id = entry
            .get("query_id")
            .and_then(value_non_empty_string)
            .map(ToOwned::to_owned);
        let title = entry
            .get("query_text")
            .and_then(value_non_empty_string)
            .map(ToOwned::to_owned)
            .or_else(|| query_id.clone())
            .unwrap_or_else(|| format!("Query {}", idx + 1));
        let mut evidence_rel_paths = extract_evidence_rel_paths(entry.get("evidence_refs"));
        if evidence_rel_paths.is_empty() {
            evidence_rel_paths.push(manifest_ref.to_string());
        }
        let status = "unknown".to_string();
        let impact = infer_claim_impact(&title, &status);

        claims.push(ClaimSeed {
            title,
            status,
            impact,
            evidence_rel_paths,
            notes: query_id.map(|value| format!("query_id={value}")),
        });
    }

    claims
}

fn extract_claims_from_html(html: &str, html_ref: &str) -> Vec<ClaimSeed> {
    let mut claims = Vec::new();
    for token in extract_code_tokens(html) {
        let status = "unknown".to_string();
        claims.push(ClaimSeed {
            title: token.clone(),
            status: status.clone(),
            impact: infer_claim_impact(&token, &status),
            evidence_rel_paths: vec![html_ref.to_string()],
            notes: Some("derived from DecisionPack.html".to_string()),
        });
    }
    claims
}

fn extract_claims_from_quote(quote: &Value, quote_ref: &str) -> Vec<ClaimSeed> {
    let title = quote
        .get("title")
        .and_then(value_non_empty_string)
        .or_else(|| quote.get("summary").and_then(value_non_empty_string))
        .or_else(|| quote.get("quote_id").and_then(value_non_empty_string))
        .or_else(|| quote.get("decision").and_then(value_non_empty_string))
        .unwrap_or("Quote evidence available")
        .to_string();
    let status = quote
        .get("status")
        .and_then(value_non_empty_string)
        .map(normalize_claim_status)
        .unwrap_or_else(|| "unknown".to_string());
    let impact = quote
        .get("impact")
        .and_then(value_non_empty_string)
        .map(normalize_claim_impact)
        .unwrap_or_else(|| infer_claim_impact(&title, &status));

    vec![ClaimSeed {
        title,
        status,
        impact,
        evidence_rel_paths: vec![quote_ref.to_string()],
        notes: Some("derived from Quote.json fallback".to_string()),
    }]
}

fn extract_code_tokens(html: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = html;

    while let Some(start_idx) = cursor.find("<code>") {
        cursor = &cursor[start_idx + "<code>".len()..];
        let Some(end_idx) = cursor.find("</code>") else {
            break;
        };

        let token = decode_basic_html_entities(cursor[..end_idx].trim());
        if looks_like_claim_token(&token) && seen.insert(token.clone()) {
            tokens.push(token);
        }
        cursor = &cursor[end_idx + "</code>".len()..];
    }

    tokens
}

fn decode_basic_html_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn looks_like_claim_token(token: &str) -> bool {
    if token.len() < 3 || token.len() > 80 || !token.contains('-') {
        return false;
    }
    if token.contains('/') || token.contains('\\') || token.contains('.') || token.contains(' ') {
        return false;
    }
    let has_alpha = token.chars().any(|ch| ch.is_ascii_alphabetic());
    let valid_chars = token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
    has_alpha && valid_chars
}

fn normalize_claim_status(status: &str) -> String {
    match status.trim().to_ascii_lowercase().as_str() {
        "met" | "supported" => "supported".to_string(),
        "partial" => "partial".to_string(),
        "gap" | "unsupported" => "unsupported".to_string(),
        _ => "unknown".to_string(),
    }
}

fn normalize_claim_impact(impact: &str) -> String {
    match impact.trim().to_ascii_lowercase().as_str() {
        "high" | "critical" => "high".to_string(),
        "medium" | "med" => "medium".to_string(),
        "low" => "low".to_string(),
        _ => "low".to_string(),
    }
}

fn infer_claim_impact(title: &str, status: &str) -> String {
    let title_key = title.to_ascii_lowercase();
    let high_keywords = [
        "identity",
        "security",
        "compliance",
        "privacy",
        "risk",
        "ownership",
        "access",
        "encryption",
        "legal",
    ];
    if high_keywords
        .iter()
        .any(|keyword| title_key.contains(keyword))
    {
        return "high".to_string();
    }

    match normalize_claim_status(status).as_str() {
        "partial" | "unsupported" => "medium".to_string(),
        _ => "low".to_string(),
    }
}

fn normalize_or_infer_claim_impact(raw_impact: &str, title: &str, status: &str) -> String {
    match raw_impact.trim().to_ascii_lowercase().as_str() {
        "high" | "critical" | "medium" | "med" | "low" => normalize_claim_impact(raw_impact),
        _ => infer_claim_impact(title, status),
    }
}

fn normalize_claim_title(title: &str) -> String {
    let normalized = title.split_whitespace().collect::<Vec<&str>>().join(" ");
    if normalized.is_empty() {
        return "Untitled claim".to_string();
    }
    if normalized.chars().count() <= 120 {
        return normalized;
    }
    normalized.chars().take(120).collect()
}

fn normalize_claim_notes(notes: Option<String>) -> Option<String> {
    notes
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sort_claims_deterministically(claims: &mut [ClaimV1]) {
    claims.sort_by(|left, right| {
        left.claim_id
            .to_ascii_lowercase()
            .cmp(&right.claim_id.to_ascii_lowercase())
            .then_with(|| left.claim_id.cmp(&right.claim_id))
    });
}

fn deterministic_claim_id(title: &str, primary_evidence_rel_path: &str) -> String {
    let title_key = normalize_claim_id_component(title);
    let evidence_key = normalize_claim_id_component(primary_evidence_rel_path);
    let digest = sha256_bytes(format!("{title_key}|{evidence_key}").as_bytes());
    format!("CLAIM-{}", digest[..12].to_ascii_uppercase())
}

fn normalize_claim_id_component(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn resolve_claim_evidence(
    evidence_rel_paths: &[String],
    pack_hashes: &BTreeMap<String, String>,
) -> Vec<ClaimEvidenceRefV1> {
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();

    for candidate in stable_unique_sorted_strings(evidence_rel_paths.to_vec()) {
        let Some((rel_path, sha256)) = resolve_pack_rel_path(&candidate, pack_hashes) else {
            continue;
        };
        let rel_key = normalize_rel_path_key(&rel_path);
        if !seen.insert(rel_key) {
            continue;
        }
        evidence.push(ClaimEvidenceRefV1 {
            rel_path: rel_path.clone(),
            sha256,
            artifact_kind: infer_artifact_kind(&rel_path),
            note: None,
        });
    }

    if evidence.is_empty()
        && let Some((rel_path, sha256)) = pack_hashes.iter().next()
    {
        evidence.push(ClaimEvidenceRefV1 {
            rel_path: rel_path.clone(),
            sha256: sha256.clone(),
            artifact_kind: infer_artifact_kind(rel_path),
            note: Some("fallback to first available pack artifact".to_string()),
        });
    }

    evidence
}

fn resolve_pack_rel_path(
    candidate: &str,
    pack_hashes: &BTreeMap<String, String>,
) -> Option<(String, String)> {
    let candidate = sanitize_evidence_rel_path(candidate)?;
    let candidate_key = normalize_rel_path_key(&candidate);
    if candidate_key.is_empty() {
        return None;
    }

    for (rel_path, sha256) in pack_hashes {
        if normalize_rel_path_key(rel_path) == candidate_key {
            return Some((rel_path.clone(), sha256.clone()));
        }
    }

    let target_name = entry_file_name(&candidate_key).to_ascii_lowercase();
    let mut matched: Option<(String, String)> = None;
    for (rel_path, sha256) in pack_hashes {
        if entry_file_name(rel_path).to_ascii_lowercase() != target_name {
            continue;
        }
        if matched.is_some() {
            return None;
        }
        matched = Some((rel_path.clone(), sha256.clone()));
    }
    matched
}

fn infer_artifact_kind(rel_path: &str) -> Option<String> {
    let file_name = entry_file_name(rel_path);
    if file_name.eq_ignore_ascii_case(DECISION_PACK_MANIFEST_FILE) {
        return Some("decisionpack_manifest".to_string());
    }
    if file_name.eq_ignore_ascii_case(DECISION_PACK_HTML_FILE) {
        return Some("decisionpack_html".to_string());
    }
    if file_name.eq_ignore_ascii_case(QUOTE_JSON_FILE) {
        return Some("quote_json".to_string());
    }

    match Path::new(file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
    {
        Some(ext) if ext == "json" => Some("json".to_string()),
        Some(ext) if ext == "md" => Some("markdown".to_string()),
        Some(ext) if ext == "txt" => Some("text".to_string()),
        _ => None,
    }
}

fn extract_evidence_rel_paths(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut evidence_rel_paths = Vec::new();
    for item in items {
        if let Some(text) = value_non_empty_string(item)
            && let Some(path) = sanitize_evidence_rel_path(text)
        {
            evidence_rel_paths.push(path);
            continue;
        }

        if let Some(rel_path) = item
            .as_object()
            .and_then(|object| object.get("rel_path"))
            .and_then(value_non_empty_string)
            && let Some(path) = sanitize_evidence_rel_path(rel_path)
        {
            evidence_rel_paths.push(path);
        }
    }

    stable_unique_sorted_strings(evidence_rel_paths)
}

fn sanitize_evidence_rel_path(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("raw_blob_id:")
        || lower.starts_with("chunk_blob_id:")
        || lower.starts_with("chunk_id:")
        || lower.contains("://")
    {
        return None;
    }

    let core = trimmed.split('#').next().unwrap_or("").trim();
    if core.is_empty() {
        return None;
    }
    let normalized = core
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if normalized.is_empty() || normalized.contains(':') {
        return None;
    }
    Some(normalized)
}

fn normalize_rel_path_key(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn value_non_empty_string(value: &Value) -> Option<&str> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn find_first_file_by_basename(base_dir: &Path, basename: &str) -> Result<Option<PathBuf>> {
    let mut rel_paths = list_relative_files(base_dir)?;
    sort_paths_deterministically(&mut rel_paths);
    for rel in rel_paths {
        if rel
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(basename))
        {
            return Ok(Some(rel));
        }
    }
    Ok(None)
}

fn build_drift_report_from_zip_paths(a_zip: &Path, b_zip: &Path) -> Result<DriftReportV1> {
    let a_entries = read_zip_entry_snapshots(a_zip)?;
    let b_entries = read_zip_entry_snapshots(b_zip)?;
    let a_sha256 = sha256_file(a_zip)?;
    let b_sha256 = sha256_file(b_zip)?;
    Ok(build_drift_report_from_snapshots(
        a_sha256, b_sha256, &a_entries, &b_entries,
    ))
}

fn build_drift_report_from_snapshots(
    a_sha256: String,
    b_sha256: String,
    a_entries: &BTreeMap<String, ZipEntrySnapshot>,
    b_entries: &BTreeMap<String, ZipEntrySnapshot>,
) -> DriftReportV1 {
    let drift_claims = collect_drift_claims_from_snapshots(a_entries, b_entries);
    let mut changes = compute_drift_changes(a_entries, b_entries);
    annotate_drift_changes_with_claims(&mut changes, &drift_claims);
    let drift_summary = build_drift_summary(&changes, &drift_claims);

    DriftReportV1 {
        schema_version: DRIFT_REPORT_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
        a_sha256,
        b_sha256,
        changes,
        drift_summary,
    }
}

fn compute_drift_changes(
    a_entries: &BTreeMap<String, ZipEntrySnapshot>,
    b_entries: &BTreeMap<String, ZipEntrySnapshot>,
) -> Vec<DriftChange> {
    let mut entry_paths: BTreeSet<String> = a_entries.keys().cloned().collect();
    entry_paths.extend(b_entries.keys().cloned());

    let mut changes = Vec::new();
    for entry_path in entry_paths {
        let a_entry = a_entries.get(&entry_path);
        let b_entry = b_entries.get(&entry_path);

        match (a_entry, b_entry) {
            (None, Some(b_entry)) => changes.push(DriftChange {
                kind: "added".to_string(),
                entry_path: entry_path.clone(),
                a_sha256: None,
                b_sha256: Some(b_entry.sha256.clone()),
                summary: summarize_json_change(&entry_path, None, b_entry.summary_bytes.as_deref()),
                affected_claims: Vec::new(),
            }),
            (Some(a_entry), None) => changes.push(DriftChange {
                kind: "removed".to_string(),
                entry_path: entry_path.clone(),
                a_sha256: Some(a_entry.sha256.clone()),
                b_sha256: None,
                summary: summarize_json_change(&entry_path, a_entry.summary_bytes.as_deref(), None),
                affected_claims: Vec::new(),
            }),
            (Some(a_entry), Some(b_entry)) if a_entry.sha256 != b_entry.sha256 => {
                changes.push(DriftChange {
                    kind: "modified".to_string(),
                    entry_path: entry_path.clone(),
                    a_sha256: Some(a_entry.sha256.clone()),
                    b_sha256: Some(b_entry.sha256.clone()),
                    summary: summarize_json_change(
                        &entry_path,
                        a_entry.summary_bytes.as_deref(),
                        b_entry.summary_bytes.as_deref(),
                    ),
                    affected_claims: Vec::new(),
                });
            }
            _ => {}
        }
    }

    sort_drift_changes_deterministically(&mut changes);
    changes
}

fn collect_drift_claims_from_snapshots(
    a_entries: &BTreeMap<String, ZipEntrySnapshot>,
    b_entries: &BTreeMap<String, ZipEntrySnapshot>,
) -> Vec<DriftClaimRef> {
    let mut claims = extract_drift_claims_from_zip_entries(b_entries);
    if claims.is_empty() {
        claims = extract_drift_claims_from_zip_entries(a_entries);
    }
    claims
}

fn impact_rank(impact: &str) -> u8 {
    match normalize_claim_impact(impact).as_str() {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn extract_drift_claims_from_zip_entries(
    entries: &BTreeMap<String, ZipEntrySnapshot>,
) -> Vec<DriftClaimRef> {
    for (entry_path, snapshot) in entries {
        if !entry_file_name(entry_path).eq_ignore_ascii_case(CLAIMS_FILE) {
            continue;
        }
        let Some(bytes) = snapshot.summary_bytes.as_deref() else {
            continue;
        };
        let Some(value) = parse_json_value(bytes) else {
            continue;
        };
        return parse_claims_from_claims_file(&value);
    }
    Vec::new()
}

fn parse_claims_from_claims_file(value: &Value) -> Vec<DriftClaimRef> {
    let Some(claims) = value.get("claims").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut output = Vec::new();
    for claim in claims {
        let Some(claim_id) = claim
            .get("claim_id")
            .and_then(value_non_empty_string)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let title = claim
            .get("title")
            .and_then(value_non_empty_string)
            .unwrap_or("Untitled claim");
        let status = claim
            .get("status")
            .and_then(value_non_empty_string)
            .unwrap_or("unknown");
        let impact = claim
            .get("impact")
            .and_then(value_non_empty_string)
            .map(normalize_claim_impact)
            .unwrap_or_else(|| infer_claim_impact(title, status));
        let evidence_rel_paths = extract_claim_evidence_paths_from_claim_value(claim);

        output.push(DriftClaimRef {
            claim_id,
            impact,
            evidence_rel_paths,
        });
    }

    output.sort_by(|left, right| {
        left.claim_id
            .to_ascii_lowercase()
            .cmp(&right.claim_id.to_ascii_lowercase())
            .then_with(|| left.claim_id.cmp(&right.claim_id))
    });
    output
}

fn extract_claim_evidence_paths_from_claim_value(claim: &Value) -> Vec<String> {
    let mut evidence_rel_paths = Vec::new();

    if let Some(items) = claim.get("evidence").and_then(Value::as_array) {
        for item in items {
            if let Some(rel_path) = item.get("rel_path").and_then(value_non_empty_string)
                && let Some(path) = sanitize_evidence_rel_path(rel_path)
            {
                evidence_rel_paths.push(path);
            }
        }
    }

    if let Some(items) = claim.get("evidence_refs").and_then(Value::as_array) {
        for item in items {
            if let Some(value) = value_non_empty_string(item)
                && let Some(path) = sanitize_evidence_rel_path(value)
            {
                evidence_rel_paths.push(path);
            }
        }
    }

    stable_unique_sorted_strings(evidence_rel_paths)
}

fn annotate_drift_changes_with_claims(changes: &mut [DriftChange], claims: &[DriftClaimRef]) {
    for change in changes {
        let mut affected_claims = Vec::new();
        for claim in claims {
            if claim
                .evidence_rel_paths
                .iter()
                .any(|evidence_path| paths_share_directory_tree(&change.entry_path, evidence_path))
            {
                affected_claims.push(claim.claim_id.clone());
            }
        }
        change.affected_claims = stable_unique_sorted_strings(affected_claims);
    }
}

fn paths_share_directory_tree(left: &str, right: &str) -> bool {
    let left_key = normalize_rel_path_key(left);
    let right_key = normalize_rel_path_key(right);
    if left_key.is_empty() || right_key.is_empty() {
        return false;
    }

    if left_key == right_key || is_parent_or_child_path(&left_key, &right_key) {
        return true;
    }

    let left_parent = parent_rel_path(&left_key);
    if !left_parent.is_empty() && is_parent_or_child_path(&left_parent, &right_key) {
        return true;
    }

    let right_parent = parent_rel_path(&right_key);
    !right_parent.is_empty() && is_parent_or_child_path(&left_key, &right_parent)
}

fn is_parent_or_child_path(left: &str, right: &str) -> bool {
    left == right
        || left.starts_with(&(right.to_string() + "/"))
        || right.starts_with(&(left.to_string() + "/"))
}

fn parent_rel_path(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_default()
}

fn build_drift_summary(changes: &[DriftChange], claims: &[DriftClaimRef]) -> DriftSummaryV1 {
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut modified = 0usize;
    let mut affected_claim_ids = BTreeSet::new();
    let mut claim_impact_by_id = BTreeMap::new();

    for claim in claims {
        claim_impact_by_id.insert(
            claim.claim_id.to_ascii_lowercase(),
            normalize_claim_impact(&claim.impact),
        );
    }

    for change in changes {
        match change.kind.as_str() {
            "added" => added += 1,
            "removed" => removed += 1,
            "modified" => modified += 1,
            _ => {}
        }
        for claim_id in &change.affected_claims {
            affected_claim_ids.insert(claim_id.clone());
        }
    }

    let mut by_impact = DriftSummaryByImpact {
        high: 0,
        medium: 0,
        low: 0,
    };
    for claim_id in &affected_claim_ids {
        match claim_impact_by_id
            .get(&claim_id.to_ascii_lowercase())
            .map(String::as_str)
            .unwrap_or("low")
        {
            "high" => by_impact.high += 1,
            "medium" => by_impact.medium += 1,
            _ => by_impact.low += 1,
        }
    }

    DriftSummaryV1 {
        counts: DriftSummaryCounts {
            added,
            removed,
            modified,
        },
        claims_affected_count: affected_claim_ids.len(),
        by_impact,
    }
}

fn sort_drift_changes_deterministically(changes: &mut [DriftChange]) {
    changes.sort_by(|left, right| {
        left.entry_path
            .to_ascii_lowercase()
            .cmp(&right.entry_path.to_ascii_lowercase())
            .then_with(|| left.entry_path.cmp(&right.entry_path))
            .then_with(|| left.kind.cmp(&right.kind))
    });
}

fn summarize_json_change(
    entry_path: &str,
    a_bytes: Option<&[u8]>,
    b_bytes: Option<&[u8]>,
) -> Option<DriftJsonSummary> {
    if !is_summary_target_entry(entry_path) {
        return None;
    }

    let metric = summary_metric(entry_path)?;
    let a_count = a_bytes
        .and_then(parse_json_value)
        .and_then(|value| summary_count(entry_path, &value));
    let b_count = b_bytes
        .and_then(parse_json_value)
        .and_then(|value| summary_count(entry_path, &value));

    if a_count.is_none() && b_count.is_none() {
        return None;
    }

    Some(DriftJsonSummary {
        metric: metric.to_string(),
        a_count,
        b_count,
    })
}

fn parse_json_value(bytes: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(bytes).ok()
}

fn summary_metric(entry_path: &str) -> Option<&'static str> {
    let entry_name = entry_file_name(entry_path);
    if entry_name.eq_ignore_ascii_case(CLAIMS_FILE) {
        return Some("claims_count");
    }
    if entry_name.eq_ignore_ascii_case(DECISION_PACK_FILE) {
        return Some("artifacts_count");
    }
    if entry_name.eq_ignore_ascii_case("epi.evidence_pack.v1.json") {
        return Some("evidence_count");
    }
    None
}

fn summary_count(entry_path: &str, value: &Value) -> Option<usize> {
    let entry_name = entry_file_name(entry_path);
    if entry_name.eq_ignore_ascii_case(CLAIMS_FILE) {
        return value.get("claims").and_then(Value::as_array).map(Vec::len);
    }
    if entry_name.eq_ignore_ascii_case(DECISION_PACK_FILE) {
        return value
            .get("artifacts")
            .and_then(Value::as_array)
            .map(Vec::len);
    }
    if entry_name.eq_ignore_ascii_case("epi.evidence_pack.v1.json") {
        return value
            .get("hits")
            .and_then(Value::as_array)
            .map(Vec::len)
            .or_else(|| {
                value
                    .pointer("/source_manifest/files")
                    .and_then(Value::as_array)
                    .map(Vec::len)
            })
            .or_else(|| {
                value
                    .get("source_extracts")
                    .and_then(Value::as_array)
                    .map(Vec::len)
            })
            .or_else(|| {
                value
                    .get("artifacts")
                    .and_then(Value::as_array)
                    .map(Vec::len)
            })
            .or_else(|| {
                value
                    .get("evidence")
                    .and_then(Value::as_array)
                    .map(Vec::len)
            })
            .or_else(|| value.get("items").and_then(Value::as_array).map(Vec::len));
    }
    None
}

fn read_zip_entry_snapshots(zip_path: &Path) -> Result<BTreeMap<String, ZipEntrySnapshot>> {
    let file = fs::File::open(zip_path)
        .with_context(|| format!("failed to open zip file: {}", zip_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("failed to read zip archive: {}", zip_path.display()))?;

    let mut entries = BTreeMap::new();
    for idx in 0..archive.len() {
        let mut entry = archive.by_index(idx).with_context(|| {
            format!(
                "failed to read zip entry index {idx} from {}",
                zip_path.display()
            )
        })?;
        if entry.is_dir() || entry.name().ends_with('/') {
            continue;
        }

        let entry_path = normalize_zip_entry_path(entry.name());
        if entry_path.is_empty() {
            continue;
        }

        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).with_context(|| {
            format!(
                "failed to read zip entry {} from {}",
                entry_path,
                zip_path.display()
            )
        })?;

        let sha256 = sha256_bytes(&bytes);
        let summary_bytes = if is_summary_target_entry(&entry_path) {
            Some(bytes)
        } else {
            None
        };
        entries.insert(
            entry_path,
            ZipEntrySnapshot {
                sha256,
                summary_bytes,
            },
        );
    }

    Ok(entries)
}

fn normalize_zip_entry_path(name: &str) -> String {
    name.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn is_summary_target_entry(entry_path: &str) -> bool {
    let file_name = entry_file_name(entry_path);
    file_name.eq_ignore_ascii_case(CLAIMS_FILE)
        || file_name.eq_ignore_ascii_case(DECISION_PACK_FILE)
        || file_name.eq_ignore_ascii_case("epi.evidence_pack.v1.json")
}

fn entry_file_name(entry_path: &str) -> &str {
    entry_path.rsplit('/').next().unwrap_or(entry_path)
}

fn render_drift_markdown(report: &DriftReportV1, a_zip: &Path, b_zip: &Path) -> String {
    let mut output = String::new();
    output.push_str("# Drift Report\n\n");
    output.push_str(&format!("- generated_at: `{}`\n", report.generated_at));
    output.push_str(&format!("- a: `{}`\n", a_zip.display()));
    output.push_str(&format!("- b: `{}`\n", b_zip.display()));
    output.push_str(&format!("- a_sha256: `{}`\n", report.a_sha256));
    output.push_str(&format!("- b_sha256: `{}`\n", report.b_sha256));
    output.push_str(&format!(
        "- totals: added={}, removed={}, modified={}\n",
        report.drift_summary.counts.added,
        report.drift_summary.counts.removed,
        report.drift_summary.counts.modified
    ));
    output.push_str(&format!(
        "- claims_affected: {}\n",
        report.drift_summary.claims_affected_count
    ));
    output.push_str(&format!(
        "- by_impact: high={}, medium={}, low={}\n",
        report.drift_summary.by_impact.high,
        report.drift_summary.by_impact.medium,
        report.drift_summary.by_impact.low
    ));

    if report.changes.is_empty() {
        output.push_str("\nNo file-level changes detected.\n");
        return output;
    }

    let impacted_claims = collect_impacted_claim_summaries(a_zip, b_zip, &report.changes);
    if impacted_claims.is_empty() {
        output.push_str("\n## Top Impacted Claims\nNo affected claims were mapped.\n");
    } else {
        output.push_str("\n## Top Impacted Claims\n");
        let max_claims = 10usize;
        for claim in impacted_claims.iter().take(max_claims) {
            output.push_str(&format!(
                "- [{}] `{}` -> {}\n",
                claim.impact.to_ascii_uppercase(),
                claim.claim_id,
                markdown_links_for_paths(&claim.changed_paths)
            ));
        }
        if impacted_claims.len() > max_claims {
            output.push_str(&format!(
                "- ... and {} more impacted claims\n",
                impacted_claims.len() - max_claims
            ));
        }
    }

    output.push_str("\n## Full Change List\n");
    for change in &report.changes {
        output.push_str(&format!(
            "- {} `{}`",
            change.kind.to_ascii_uppercase(),
            change.entry_path
        ));
        if let Some(summary) = &change.summary {
            let a_count = summary
                .a_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            let b_count = summary
                .b_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            output.push_str(&format!(
                " ({}, a={}, b={})",
                summary.metric, a_count, b_count
            ));
        }
        if !change.affected_claims.is_empty() {
            output.push_str(&format!(
                " [affected_claims: {}]",
                change
                    .affected_claims
                    .iter()
                    .map(|claim_id| format!("`{claim_id}`"))
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        }
        output.push('\n');
    }

    output
}

fn collect_impacted_claim_summaries(
    a_zip: &Path,
    b_zip: &Path,
    changes: &[DriftChange],
) -> Vec<ImpactedClaimSummary> {
    let Ok(a_entries) = read_zip_entry_snapshots(a_zip) else {
        return Vec::new();
    };
    let Ok(b_entries) = read_zip_entry_snapshots(b_zip) else {
        return Vec::new();
    };
    let claims = collect_drift_claims_from_snapshots(&a_entries, &b_entries);
    if claims.is_empty() {
        return Vec::new();
    }

    let mut impact_by_claim_id = BTreeMap::new();
    for claim in &claims {
        impact_by_claim_id.insert(
            claim.claim_id.to_ascii_lowercase(),
            normalize_claim_impact(&claim.impact),
        );
    }

    let mut changed_paths_by_claim_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for change in changes {
        for claim_id in &change.affected_claims {
            changed_paths_by_claim_id
                .entry(claim_id.clone())
                .or_default()
                .push(change.entry_path.clone());
        }
    }

    let mut output = Vec::new();
    for (claim_id, changed_paths) in changed_paths_by_claim_id {
        let impact = impact_by_claim_id
            .get(&claim_id.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| "low".to_string());
        output.push(ImpactedClaimSummary {
            claim_id,
            impact,
            changed_paths: stable_unique_sorted_strings(changed_paths),
        });
    }

    output.sort_by(|left, right| {
        impact_rank(&right.impact)
            .cmp(&impact_rank(&left.impact))
            .then_with(|| {
                left.claim_id
                    .to_ascii_lowercase()
                    .cmp(&right.claim_id.to_ascii_lowercase())
            })
            .then_with(|| left.claim_id.cmp(&right.claim_id))
    });

    output
}

fn markdown_links_for_paths(paths: &[String]) -> String {
    paths
        .iter()
        .map(|path| format!("[{path}]({path})"))
        .collect::<Vec<String>>()
        .join(", ")
}

fn is_zip_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
}

fn build_replay_commands(context: &BundleContext) -> Vec<String> {
    let cupola = vec![
        path_to_string(&context.cupola_bin),
        "export-epi".to_string(),
        "--vault".to_string(),
        path_to_string(&context.vault),
        "--out".to_string(),
        path_to_string(&context.pack_dir),
        "--query".to_string(),
        context.query.clone(),
        "--limit".to_string(),
        context.limit.to_string(),
    ];

    let aegis = vec![
        path_to_string(&context.aegis_bin),
        "run".to_string(),
        "--vault".to_string(),
        path_to_string(&context.vault),
        "--cupola-repo".to_string(),
        path_to_string(&context.cupola_repo),
        "--intake".to_string(),
        path_to_string(&context.intake),
        "--out".to_string(),
        path_to_string(&context.pack_dir),
        "--data-dir".to_string(),
        path_to_string(&context.aegis_data_dir),
    ];

    let leo_pack = vec![
        "leo".to_string(),
        "pack".to_string(),
        "--vault".to_string(),
        path_to_string(&context.vault),
        "--intake".to_string(),
        path_to_string(&context.intake),
        "--out".to_string(),
        path_to_string(&context.out_dir),
        "--cupola-bin".to_string(),
        path_to_string(&context.cupola_bin),
        "--aegis-bin".to_string(),
        path_to_string(&context.aegis_bin),
        "--query".to_string(),
        context.query.clone(),
        "--limit".to_string(),
        context.limit.to_string(),
    ];

    vec![
        format_command_for_replay(&cupola),
        format_command_for_replay(&aegis),
        format_command_for_replay(&leo_pack),
    ]
}

fn run_command_capture(cwd: &Path, argv: &[String]) -> Result<std::process::Output> {
    let (program, args) = argv
        .split_first()
        .context("cannot execute empty command vector")?;

    Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| {
            format!(
                "failed to execute command in {}: {}",
                cwd.display(),
                format_command_for_replay(argv)
            )
        })
}

fn probe_version(program: &Path, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output();
    let output = match output {
        Ok(value) => value,
        Err(_) => return "unknown".to_string(),
    };
    if !output.status.success() {
        return "unknown".to_string();
    }

    extract_first_non_empty_line(&output.stdout).unwrap_or_else(|| "unknown".to_string())
}

fn detect_tool_version(program: &Path) -> String {
    let version = probe_version(program, &["--version"]);
    if version != "unknown" {
        return version;
    }
    probe_version(program, &["version"])
}

fn extract_git_commit_hash(version: &str) -> Option<String> {
    version
        .split(|ch: char| !ch.is_ascii_hexdigit())
        .find(|token| {
            let len = token.len();
            (7..=40).contains(&len) && token.chars().any(|ch| ch.is_ascii_alphabetic())
        })
        .map(|token| token.to_ascii_lowercase())
}

fn extract_first_non_empty_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn build_zip(pack_dir: &Path, zip_path: &Path, exclude_seal: bool) -> Result<()> {
    let mut rel_paths = list_relative_files(pack_dir)?;
    if exclude_seal {
        rel_paths.retain(|path| !normalize_rel_path(path).eq_ignore_ascii_case(SEAL_FILE));
    }
    sort_paths_deterministically(&mut rel_paths);

    let zip_file = fs::File::create(zip_path)
        .with_context(|| format!("failed to create zip: {}", zip_path.display()))?;
    let mut zip = ZipWriter::new(zip_file);
    let fixed_time = ZipDateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
        .context("failed to create deterministic zip timestamp")?;
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(fixed_time)
        .unix_permissions(0o644);

    for rel in &rel_paths {
        let rel_path = normalize_rel_path(rel);
        let full_path = pack_dir.join(rel);
        let mut source_file = fs::File::open(&full_path)
            .with_context(|| format!("failed to open file for zip: {}", full_path.display()))?;

        zip.start_file(rel_path.clone(), options)
            .with_context(|| format!("failed to add file to zip: {}", rel_path))?;
        io::copy(&mut source_file, &mut zip)
            .with_context(|| format!("failed to write file to zip: {}", rel_path))?;
    }

    zip.finish().context("failed to finalize zip archive")?;
    Ok(())
}

fn collect_pack_file_hashes(pack_dir: &Path, exclude_seal: bool) -> Result<Vec<PackFileHash>> {
    let mut rel_paths = list_relative_files(pack_dir)?;
    sort_paths_deterministically(&mut rel_paths);
    let mut files = Vec::new();

    for rel in rel_paths {
        let rel_path = normalize_rel_path(&rel);
        if exclude_seal && rel_path.eq_ignore_ascii_case(SEAL_FILE) {
            continue;
        }
        let sha256 = sha256_file(&pack_dir.join(&rel))?;
        files.push(PackFileHash { rel_path, sha256 });
    }

    Ok(files)
}

fn snapshot_hashes(base_dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut rel_paths = list_relative_files(base_dir)?;
    sort_paths_deterministically(&mut rel_paths);
    let mut hashes = BTreeMap::new();

    for rel in rel_paths {
        let rel_path = normalize_rel_path(&rel);
        let sha = sha256_file(&base_dir.join(&rel))?;
        hashes.insert(rel_path, sha);
    }

    Ok(hashes)
}

fn diff_outputs(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<StepOutput> {
    let mut outputs = Vec::new();
    for (path, sha256) in after {
        if before.get(path) != Some(sha256) {
            outputs.push(StepOutput {
                path: path.clone(),
                sha256: sha256.clone(),
            });
        }
    }
    outputs
}

fn list_relative_files(base_dir: &Path) -> Result<Vec<PathBuf>> {
    if !base_dir.exists() {
        return Ok(Vec::new());
    }

    let mut rel_paths = Vec::new();
    for entry in WalkDir::new(base_dir) {
        let entry = entry.with_context(|| format!("failed to walk {}", base_dir.display()))?;
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(base_dir)
                .with_context(|| {
                    format!(
                        "failed to build relative path from {} to {}",
                        base_dir.display(),
                        entry.path().display()
                    )
                })?
                .to_path_buf();
            rel_paths.push(rel);
        }
    }
    Ok(rel_paths)
}

fn sort_paths_deterministically(paths: &mut [PathBuf]) {
    paths.sort_by(|left, right| {
        let left_norm = normalize_rel_path(left);
        let right_norm = normalize_rel_path(right);
        let left_key = left_norm.to_ascii_lowercase();
        let right_key = right_norm.to_ascii_lowercase();
        left_key
            .cmp(&right_key)
            .then_with(|| left_norm.cmp(&right_norm))
    });
}

fn stable_unique_sorted_strings(values: Vec<String>) -> Vec<String> {
    let mut output: Vec<String> = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    sort_strings_deterministically(&mut output);
    output.dedup();
    output
}

fn sort_strings_deterministically(values: &mut [String]) {
    values.sort_by(|left, right| {
        left.to_ascii_lowercase()
            .cmp(&right.to_ascii_lowercase())
            .then_with(|| left.cmp(right))
    });
}

fn normalize_rel_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(segment.to_string_lossy().to_string()),
            Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect::<Vec<String>>()
        .join("/")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to open file: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read file: {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn sha256_of_hash_listing(listing: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    for (path, sha256) in listing {
        hasher.update(path.as_bytes());
        hasher.update([0_u8]);
        hasher.update(sha256.as_bytes());
        hasher.update([b'\n']);
    }
    format!("{:x}", hasher.finalize())
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("failed to serialize JSON")?;
    fs::write(path, format!("{json}\n"))
        .with_context(|| format!("failed to write JSON file: {}", path.display()))?;
    Ok(())
}

fn now_rfc3339_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn relative_or_absolute_slash_path(path: &Path, base: &Path) -> String {
    match path.strip_prefix(base) {
        Ok(rel) => normalize_rel_path(rel),
        Err(_) => path_to_string(path),
    }
}

fn format_command_for_replay(argv: &[String]) -> String {
    let mut command = String::new();
    for (index, arg) in argv.iter().enumerate() {
        if index > 0 {
            command.push(' ');
        }
        command.push_str(&quote_replay_arg(arg));
    }
    command
}

fn quote_replay_arg(arg: &str) -> String {
    let escaped = arg.replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(normalize_lexical(path));
    }
    let cwd = std::env::current_dir().context("failed to read current directory")?;
    Ok(normalize_lexical(&cwd.join(path)))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    normalized
}

fn ensure_outside_vault(vault: &Path, out_dir: &Path) -> Result<()> {
    let vault_canonical = fs::canonicalize(vault)
        .with_context(|| format!("failed to resolve vault path: {}", vault.display()))?;
    let out_absolute = absolutize(out_dir)?;

    let vault_key = path_compare_key(&vault_canonical);
    let out_key = path_compare_key(&out_absolute);

    if out_key == vault_key || out_key.starts_with(&(vault_key.clone() + "/")) {
        bail!(
            "--out must be outside --vault (vault={}, out={})",
            vault_canonical.display(),
            out_absolute.display()
        );
    }

    Ok(())
}

fn path_compare_key(path: &Path) -> String {
    normalize_lexical(path)
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_sort_is_deterministic() {
        let mut paths = vec![
            PathBuf::from("b\\z.txt"),
            PathBuf::from("A\\a.txt"),
            PathBuf::from("a\\B.txt"),
            PathBuf::from("a\\a.txt"),
        ];

        sort_paths_deterministically(&mut paths);
        let sorted: Vec<String> = paths.iter().map(|path| normalize_rel_path(path)).collect();

        assert_eq!(
            sorted,
            vec![
                "A/a.txt".to_string(),
                "a/a.txt".to_string(),
                "a/B.txt".to_string(),
                "b/z.txt".to_string(),
            ]
        );
    }

    #[test]
    fn infer_repo_data_dir_from_target_release_aegis_bin() {
        let aegis_bin = PathBuf::from("repo")
            .join("target")
            .join("release")
            .join("aegis.exe");
        let resolved = infer_repo_data_dir_from_aegis_bin(&aegis_bin)
            .expect("expected repo data dir for target/release layout");
        let expected = normalize_lexical(&PathBuf::from("repo").join("data"));
        assert_eq!(path_compare_key(&resolved), path_compare_key(&expected));
        let wrong = normalize_lexical(
            &PathBuf::from("repo")
                .join("target")
                .join("release")
                .join("data"),
        );
        assert_ne!(path_compare_key(&resolved), path_compare_key(&wrong));
    }

    #[test]
    fn infer_repo_data_dir_returns_none_for_packaged_layout() {
        let aegis_bin = PathBuf::from("dist")
            .join("tools")
            .join("aegis")
            .join("aegis.exe");
        assert!(infer_repo_data_dir_from_aegis_bin(&aegis_bin).is_none());
    }

    #[test]
    fn replay_command_always_includes_aegis_data_dir() {
        let context = BundleContext {
            out_dir: PathBuf::from("out"),
            pack_dir: PathBuf::from("out").join("pack"),
            vault: PathBuf::from("vault"),
            intake: PathBuf::from("intake.json"),
            cupola_bin: PathBuf::from("cupola-cli.exe"),
            cupola_repo: PathBuf::from("."),
            aegis_bin: PathBuf::from("aegis.exe"),
            aegis_data_dir: PathBuf::from("aegis-data"),
            query: "alpha".to_string(),
            limit: 20,
        };
        let replay = build_replay_commands(&context);
        assert_eq!(replay.len(), 3);
        assert!(replay[1].contains("\"--data-dir\""));
        assert!(replay[1].contains("\"aegis-data\""));
    }

    #[test]
    fn zip_file_count_matches_hash_listing_count() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!("leo-test-{}", Uuid::new_v4()));
        let pack_dir = temp_root.join("pack");
        fs::create_dir_all(pack_dir.join("nested"))?;
        fs::write(pack_dir.join("one.txt"), "one")?;
        fs::write(pack_dir.join("nested").join("two.txt"), "two")?;

        let zip_path = temp_root.join("pack.zip");
        build_zip(&pack_dir, &zip_path, false)?;

        let hashes = collect_pack_file_hashes(&pack_dir, false)?;
        let zip_count = zip_entry_count(&zip_path)?;
        assert_eq!(hashes.len(), zip_count);

        if temp_root.exists() {
            fs::remove_dir_all(&temp_root)?;
        }
        Ok(())
    }

    #[test]
    fn bundle_contains_latest_decision_pack_assets() -> Result<()> {
        let temp_root =
            std::env::temp_dir().join(format!("leo-test-bundle-assets-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir.join("acme").join("eng42").join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;

            let html_path = decision_pack_dir.join(DECISION_PACK_HTML_FILE);
            let pdf_path = decision_pack_dir.join(DECISION_PACK_PDF_FILE);
            let sha_path = decision_pack_dir.join(DECISION_PACK_PDF_SHA256_FILE);
            fs::write(&html_path, "<html><body>final branded html</body></html>")?;
            fs::write(&pdf_path, b"%PDF-1.7\nfinal rendered bytes\n")?;
            let pdf_sha = sha256_file(&pdf_path)?;
            fs::write(&sha_path, format!("{pdf_sha}  {}\n", pdf_path.display()))?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_MANIFEST_FILE),
                r#"{"schema_version":"aegis.manifest.v1.1"}"#,
            )?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_SEAL_FILE),
                r#"{"schema_version":"aegis.seal.v1"}"#,
            )?;
            write_json_pretty(
                &pack_dir.join(DECISION_PACK_FILE),
                &json!({
                    "schema_version": DECISION_PACK_SCHEMA,
                    "pack_meta": {
                        "pack_type": "trust_audit",
                        "library": "vendorsecurity/v1",
                        "client": "acme",
                        "engagement": "eng42"
                    }
                }),
            )?;
            write_json_pretty(
                &pack_dir.join(CLAIMS_FILE),
                &json!({
                    "schema_version": CLAIMS_SCHEMA,
                    "generated_at": "2026-02-20T00:00:00Z",
                    "claims": []
                }),
            )?;

            let zip_path = temp_root.join(PACK_FILE);
            bundle_pack_directory(&pack_dir, &zip_path)?;

            let html_zip =
                read_zip_entry_bytes(&zip_path, "acme/eng42/PACK-001/DecisionPack.html")?;
            let pdf_zip = read_zip_entry_bytes(&zip_path, "acme/eng42/PACK-001/DecisionPack.pdf")?;
            assert_eq!(sha256_file(&html_path)?, sha256_bytes(&html_zip));
            assert_eq!(sha256_file(&pdf_path)?, sha256_bytes(&pdf_zip));

            let _ = read_zip_entry_bytes(&zip_path, "acme/eng42/PACK-001/SHA256.txt")?;
            let _ =
                read_zip_entry_bytes(&zip_path, "acme/eng42/PACK-001/DecisionPack.manifest.json")?;
            let _ = read_zip_entry_bytes(&zip_path, "acme/eng42/PACK-001/DecisionPack.seal.json")?;
            let _ = read_zip_entry_bytes(&zip_path, DECISION_PACK_FILE)?;
            let _ = read_zip_entry_bytes(&zip_path, CLAIMS_FILE)?;
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn verify_step_reports_missing_html_when_bundling_skipped() -> Result<()> {
        let temp_root =
            std::env::temp_dir().join(format!("leo-test-run-missing-html-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let out_dir = temp_root.join("out");
            let logs_dir = out_dir.join("_logs");
            let pack_dir = out_dir.join("pack");
            let decision_pack_dir = pack_dir.join("acme").join("eng42").join("PACK-001");
            fs::create_dir_all(&logs_dir)?;
            fs::create_dir_all(&decision_pack_dir)?;

            fs::write(
                decision_pack_dir.join(DECISION_PACK_PDF_FILE),
                b"%PDF-1.7\n",
            )?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_PDF_SHA256_FILE),
                "placeholder-sha\n",
            )?;
            write_json_pretty(
                &pack_dir.join(DECISION_PACK_FILE),
                &json!({
                    "schema_version": DECISION_PACK_SCHEMA,
                    "pack_meta": {
                        "pack_type": "trust_audit",
                        "library": "vendorsecurity/v1",
                        "client": "acme",
                        "engagement": "eng42"
                    }
                }),
            )?;

            let package_error = bundle_skip_reason_for_failed_steps(&pack_dir);
            assert!(
                package_error.contains(DECISION_PACK_HTML_FILE),
                "expected package error to mention missing html, got: {package_error}"
            );

            let pack_zip = out_dir.join(PACK_FILE);
            let verify_step = execute_verify_pack_step(
                StepSpec {
                    step_id: "step-04-verify",
                    tool: "epi-cli",
                    cwd: out_dir.clone(),
                    argv: vec![
                        "epi-cli".to_string(),
                        "verify".to_string(),
                        path_to_string(&pack_zip),
                        "--json".to_string(),
                    ],
                },
                &out_dir,
                &logs_dir,
                &pack_dir,
                &pack_zip,
                Some(package_error.as_str()),
            )?;
            assert_eq!(verify_step.status, "error");

            let verify_path = out_dir.join(VERIFY_FILE);
            let verify_json: Value = serde_json::from_slice(&fs::read(&verify_path)?)?;
            assert_eq!(
                verify_json.pointer("/ok").and_then(Value::as_bool),
                Some(false)
            );
            assert_eq!(
                verify_json.pointer("/pack_type").and_then(Value::as_str),
                Some("trust_audit")
            );
            assert_eq!(
                verify_json.pointer("/library").and_then(Value::as_str),
                Some("vendorsecurity/v1")
            );
            assert_eq!(
                verify_json.pointer("/client").and_then(Value::as_str),
                Some("acme")
            );
            assert_eq!(
                verify_json.pointer("/engagement").and_then(Value::as_str),
                Some("eng42")
            );
            let verifier_error = verify_json
                .pointer("/verifier_error")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            assert!(
                verifier_error.contains(DECISION_PACK_HTML_FILE),
                "expected verifier_error to mention missing html, got: {verifier_error}"
            );
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn claims_extraction_is_deterministic_and_has_structured_evidence() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!("leo-test-claims-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir.join("acme").join("eng42").join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;
            fs::write(
                decision_pack_dir.join("notes.md"),
                "ownership is with platform team",
            )?;

            let manifest = json!({
                "schema_version": "aegis.manifest.v1.1",
                "control_results": {
                    "VS-001": {
                        "title": "Identity Platform Ownership",
                        "status": "met",
                        "evidence_refs": [
                            {
                                "chunk_id": "chunk-1",
                                "rel_path": "notes.md",
                                "start_line": 1,
                                "end_line": 2
                            }
                        ]
                    }
                }
            });
            write_json_pretty(
                &decision_pack_dir.join(DECISION_PACK_MANIFEST_FILE),
                &manifest,
            )?;

            let claims_run_a = build_claims_from_pack_dir(&pack_dir)?;
            let claims_run_b = build_claims_from_pack_dir(&pack_dir)?;
            assert_eq!(claims_run_a.schema_version, CLAIMS_SCHEMA);
            assert!(!claims_run_a.claims.is_empty());

            let claim_ids_a: Vec<String> = claims_run_a
                .claims
                .iter()
                .map(|claim| claim.claim_id.clone())
                .collect();
            let claim_ids_b: Vec<String> = claims_run_b
                .claims
                .iter()
                .map(|claim| claim.claim_id.clone())
                .collect();
            assert_eq!(claim_ids_a, claim_ids_b);

            let mut sorted_ids = claim_ids_a.clone();
            sort_strings_deterministically(&mut sorted_ids);
            assert_eq!(claim_ids_a, sorted_ids);

            let first_claim = &claims_run_a.claims[0];
            assert_eq!(first_claim.status, "supported");
            assert_eq!(first_claim.impact, "high");
            assert!(!first_claim.evidence.is_empty());
            assert!(!first_claim.evidence_refs.is_empty());
            assert_eq!(
                first_claim.evidence[0].rel_path,
                first_claim.evidence_refs[0]
            );
            assert!(!first_claim.evidence[0].sha256.is_empty());

            let claim_id_suffix = first_claim
                .claim_id
                .strip_prefix("CLAIM-")
                .unwrap_or_default();
            assert_eq!(claim_id_suffix.len(), 12);
            assert!(claim_id_suffix.chars().all(|ch| {
                ch.is_ascii_hexdigit() && (!ch.is_ascii_alphabetic() || ch.is_ascii_uppercase())
            }));

            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn decision_pack_meta_is_populated_and_non_empty() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!("leo-test-pack-meta-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir.join("acme").join("eng42").join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;

            let manifest = json!({
                "schema_version": "aegis.manifest.v1.1",
                "pack_meta": {
                    "pack_type": "trust_audit",
                    "library": "vendorsecurity/v1",
                    "client": "acme",
                    "engagement": "eng42",
                    "pack_id": "PACK-001"
                }
            });
            write_json_pretty(
                &decision_pack_dir.join(DECISION_PACK_MANIFEST_FILE),
                &manifest,
            )?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_HTML_FILE),
                "<html><body>DecisionPack</body></html>",
            )?;

            let intake = json!({
                "schema_version": "aegis.intake.v1",
                "client_id": "acme",
                "engagement_id": "eng42",
                "pack_type": "trust_audit",
                "library_pack": "vendorsecurity/v1"
            });
            let intake_path = temp_root.join("intake.json");
            write_json_pretty(&intake_path, &intake)?;

            let context = BundleContext {
                out_dir: temp_root.clone(),
                pack_dir,
                vault: PathBuf::from("vault"),
                intake: intake_path,
                cupola_bin: PathBuf::from("cupola-cli.exe"),
                cupola_repo: PathBuf::from("."),
                aegis_bin: PathBuf::from("aegis.exe"),
                aegis_data_dir: PathBuf::from("data"),
                query: "alpha".to_string(),
                limit: 20,
            };

            let decision_pack = build_decision_pack(&context)?;
            assert_eq!(decision_pack.pack_meta.pack_type, "trust_audit");
            assert_eq!(decision_pack.pack_meta.library, "vendorsecurity/v1");
            assert_eq!(decision_pack.pack_meta.client, "acme");
            assert_eq!(decision_pack.pack_meta.engagement, "eng42");
            assert_eq!(decision_pack.pack_meta.pack_id.as_deref(), Some("PACK-001"));
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn prerender_stub_is_written_when_decision_pack_json_is_missing() -> Result<()> {
        let temp_root =
            std::env::temp_dir().join(format!("leo-test-prerender-stub-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir
                .join("civitasanalytica")
                .join("self-audit")
                .join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_HTML_FILE),
                "<html><body>DecisionPack</body></html>",
            )?;

            let intake = json!({
                "schema_version": "aegis.intake.v1",
                "pack_type": "trust_audit",
                "library_pack": "vendor_security",
                "client_id": "civitasanalytica",
                "engagement_id": "self-audit"
            });
            let intake_path = temp_root.join("intake.json");
            write_json_pretty(&intake_path, &intake)?;

            let stub_path = pack_dir.join(DECISION_PACK_FILE);
            assert!(!stub_path.exists());
            write_prerender_decision_pack_stub(&pack_dir, &intake_path)?;
            assert!(stub_path.is_file());

            let stub: Value = serde_json::from_slice(&fs::read(&stub_path)?)?;
            assert_eq!(
                stub.pointer("/schema_version").and_then(Value::as_str),
                Some(DECISION_PACK_SCHEMA)
            );

            for (field, expected) in [
                ("pack_type", "trust_audit"),
                ("library", "vendor_security"),
                ("client", "civitasanalytica"),
                ("engagement", "self-audit"),
            ] {
                let pointer = format!("/pack_meta/{field}");
                let actual = stub
                    .pointer(&pointer)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                assert!(
                    !actual.is_empty(),
                    "expected /pack_meta/{field} to be non-empty in {}",
                    stub_path.display()
                );
                assert_eq!(actual, expected);
            }
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn decision_pack_meta_fails_when_required_fields_are_missing() -> Result<()> {
        let temp_root =
            std::env::temp_dir().join(format!("leo-test-pack-meta-missing-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir.join("acme").join("eng42").join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_HTML_FILE),
                "<html><body>DecisionPack</body></html>",
            )?;

            let intake = json!({
                "schema_version": "aegis.intake.v1",
                "client_id": "   ",
                "engagement_id": "   ",
                "pack_type": "   ",
                "library_pack": "   ",
                "pack_meta": {
                    "pack_type": "   ",
                    "library": "   ",
                    "client": "   ",
                    "engagement": "   "
                }
            });
            let intake_path = temp_root.join("intake-missing.json");
            write_json_pretty(&intake_path, &intake)?;

            let context = BundleContext {
                out_dir: temp_root.clone(),
                pack_dir,
                vault: PathBuf::from("vault"),
                intake: intake_path,
                cupola_bin: PathBuf::from("cupola-cli.exe"),
                cupola_repo: PathBuf::from("."),
                aegis_bin: PathBuf::from("aegis.exe"),
                aegis_data_dir: PathBuf::from("data"),
                query: "alpha".to_string(),
                limit: 20,
            };

            let err = match build_decision_pack(&context) {
                Ok(_) => panic!("decision pack generation should fail when metadata is incomplete"),
                Err(err) => err,
            };
            assert!(
                err.to_string()
                    .contains("missing required decision pack metadata field"),
                "unexpected error: {err:#}"
            );
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn emitted_decision_pack_json_has_non_empty_pack_meta_fields() -> Result<()> {
        let temp_root =
            std::env::temp_dir().join(format!("leo-test-pack-meta-json-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir
                .join("demo-vendorsecurity-v1")
                .join("starter")
                .join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;
            fs::write(
                decision_pack_dir.join(DECISION_PACK_HTML_FILE),
                "<html><body>DecisionPack</body></html>",
            )?;

            let intake = json!({
                "schema_version": "aegis.intake.v1",
                "client_id": "demo-vendorsecurity-v1",
                "engagement_id": "starter",
                "pack_type": "trust_audit",
                "library_pack": "vendorsecurity/v1",
                "pack_meta": {
                    "pack_type": "demo",
                    "library": "vendorsecurity-v1",
                    "client": "demo-vendorsecurity-v1",
                    "engagement": "starter",
                    "pack_id": "PACK-001"
                }
            });
            let intake_path = temp_root.join("intake.json");
            write_json_pretty(&intake_path, &intake)?;

            let context = BundleContext {
                out_dir: temp_root.clone(),
                pack_dir: pack_dir.clone(),
                vault: PathBuf::from("vault"),
                intake: intake_path,
                cupola_bin: PathBuf::from("cupola-cli.exe"),
                cupola_repo: PathBuf::from("."),
                aegis_bin: PathBuf::from("aegis.exe"),
                aegis_data_dir: PathBuf::from("data"),
                query: "alpha".to_string(),
                limit: 20,
            };

            let decision_pack = build_decision_pack(&context)?;
            let decision_pack_path = pack_dir.join(DECISION_PACK_FILE);
            write_json_pretty(&decision_pack_path, &decision_pack)?;
            let value: Value = serde_json::from_slice(&fs::read(&decision_pack_path)?)?;

            for field in ["pack_type", "library", "client", "engagement"] {
                let pointer = format!("/pack_meta/{field}");
                let text = value
                    .pointer(&pointer)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                assert!(
                    !text.is_empty(),
                    "expected /pack_meta/{field} to be non-empty in {}",
                    decision_pack_path.display()
                );
            }
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn verify_report_ok_when_verifier_succeeds_and_pack_meta_present() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!("leo-test-verify-ok-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            fs::create_dir_all(&pack_dir)?;
            write_json_pretty(
                &pack_dir.join(DECISION_PACK_FILE),
                &json!({
                    "schema_version": DECISION_PACK_SCHEMA,
                    "pack_meta": {
                        "pack_type": "trust_audit",
                        "library": "vendorsecurity/v1",
                        "client": "acme",
                        "engagement": "eng42"
                    }
                }),
            )?;

            let verifier_json = json!({
                "status": {"success": true},
                "missing_files": [],
                "invalid_json": [],
                "schema_version_mismatches": []
            });
            let report = build_verify_report(
                &temp_root.join(PACK_FILE),
                &pack_dir,
                &verifier_json,
                true,
                None,
            );
            assert!(report.ok, "expected verification to pass: {report:?}");
            assert_eq!(report.pack_type, "trust_audit");
            assert_eq!(report.library, "vendorsecurity/v1");
            assert_eq!(report.client, "acme");
            assert_eq!(report.engagement, "eng42");
            assert_eq!(report.pack_meta.pack_type, "trust_audit");
            assert_eq!(report.pack_meta.library, "vendorsecurity/v1");
            assert_eq!(report.pack_meta.client, "acme");
            assert_eq!(report.pack_meta.engagement, "eng42");
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn verify_report_fails_when_missing_files_present() -> Result<()> {
        let temp_root =
            std::env::temp_dir().join(format!("leo-test-verify-missing-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            fs::create_dir_all(&pack_dir)?;
            write_json_pretty(
                &pack_dir.join(DECISION_PACK_FILE),
                &json!({
                    "schema_version": DECISION_PACK_SCHEMA,
                    "pack_meta": {
                        "pack_type": "trust_audit",
                        "library": "vendorsecurity/v1",
                        "client": "acme",
                        "engagement": "eng42"
                    }
                }),
            )?;

            let verifier_json = json!({
                "status": {"success": true},
                "missing_files": ["epi.claims.v1.json"],
                "invalid_json": [],
                "schema_version_mismatches": []
            });
            let report = build_verify_report(
                &temp_root.join(PACK_FILE),
                &pack_dir,
                &verifier_json,
                true,
                None,
            );
            assert!(!report.ok, "expected verification to fail: {report:?}");
            assert_eq!(report.missing_files, vec!["epi.claims.v1.json".to_string()]);
            Ok(())
        })();

        if temp_root.exists() {
            let _ = fs::remove_dir_all(&temp_root);
        }
        result
    }

    #[test]
    fn drift_changes_are_sorted_and_classified() {
        let mut a_entries = BTreeMap::new();
        a_entries.insert(
            "gone.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "old-gone".to_string(),
                summary_bytes: None,
            },
        );
        a_entries.insert(
            "mod.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "old-mod".to_string(),
                summary_bytes: None,
            },
        );
        a_entries.insert(
            "same.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "same".to_string(),
                summary_bytes: None,
            },
        );

        let mut b_entries = BTreeMap::new();
        b_entries.insert(
            "added.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "new-added".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            "mod.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "new-mod".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            "same.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "same".to_string(),
                summary_bytes: None,
            },
        );

        let changes = compute_drift_changes(&a_entries, &b_entries);
        let actual: Vec<(String, String)> = changes
            .iter()
            .map(|change| (change.entry_path.clone(), change.kind.clone()))
            .collect();

        assert_eq!(
            actual,
            vec![
                ("added.txt".to_string(), "added".to_string()),
                ("gone.txt".to_string(), "removed".to_string()),
                ("mod.txt".to_string(), "modified".to_string()),
            ]
        );
    }

    #[test]
    fn drift_report_schema_version_is_correct() {
        let empty: BTreeMap<String, ZipEntrySnapshot> = BTreeMap::new();
        let report = build_drift_report_from_snapshots(
            "a-hash".to_string(),
            "b-hash".to_string(),
            &empty,
            &empty,
        );
        assert_eq!(report.schema_version, DRIFT_REPORT_SCHEMA);
        assert_eq!(report.drift_summary.counts.added, 0);
        assert_eq!(report.drift_summary.claims_affected_count, 0);
    }

    #[test]
    fn drift_affected_claims_include_parent_child_and_are_sorted() {
        let claims_json = json!({
            "schema_version": CLAIMS_SCHEMA,
            "generated_at": "2026-02-18T00:00:00Z",
            "claims": [
                {
                    "claim_id": "CLAIM-ZETA",
                    "title": "Policy is present",
                    "status": "supported",
                    "impact": "high",
                    "evidence": [
                        {"rel_path": "evidence/team/docs/policy.md", "sha256": "hash-zeta"}
                    ],
                    "evidence_refs": ["evidence/team/docs/policy.md"]
                },
                {
                    "claim_id": "CLAIM-BETA",
                    "title": "Data input is controlled",
                    "status": "supported",
                    "impact": "low",
                    "evidence": [
                        {"rel_path": "team/data/input.json", "sha256": "hash-beta"}
                    ],
                    "evidence_refs": ["team/data/input.json"]
                },
                {
                    "claim_id": "CLAIM-ALPHA",
                    "title": "Docs directory is stable",
                    "status": "partial",
                    "impact": "medium",
                    "evidence": [
                        {"rel_path": "evidence/team/docs", "sha256": "hash-alpha"}
                    ],
                    "evidence_refs": ["evidence/team/docs"]
                }
            ]
        });
        let claims_bytes = serde_json::to_vec(&claims_json).expect("claims json must serialize");

        let mut a_entries = BTreeMap::new();
        a_entries.insert(
            "evidence/team/docs/policy.md".to_string(),
            ZipEntrySnapshot {
                sha256: "old-policy".to_string(),
                summary_bytes: None,
            },
        );
        a_entries.insert(
            "team/data/input.json".to_string(),
            ZipEntrySnapshot {
                sha256: "stable-input".to_string(),
                summary_bytes: None,
            },
        );
        a_entries.insert(
            CLAIMS_FILE.to_string(),
            ZipEntrySnapshot {
                sha256: "claims-hash".to_string(),
                summary_bytes: Some(claims_bytes.clone()),
            },
        );

        let mut b_entries = BTreeMap::new();
        b_entries.insert(
            "evidence/team/docs/appendix.md".to_string(),
            ZipEntrySnapshot {
                sha256: "new-appendix".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            "evidence/team/docs/policy.md".to_string(),
            ZipEntrySnapshot {
                sha256: "new-policy".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            "team/data/input.json".to_string(),
            ZipEntrySnapshot {
                sha256: "stable-input".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            "team/data/input.json/segments/part-1.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "child-change".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            "unrelated/new.txt".to_string(),
            ZipEntrySnapshot {
                sha256: "other-change".to_string(),
                summary_bytes: None,
            },
        );
        b_entries.insert(
            CLAIMS_FILE.to_string(),
            ZipEntrySnapshot {
                sha256: "claims-hash".to_string(),
                summary_bytes: Some(claims_bytes),
            },
        );

        let report = build_drift_report_from_snapshots(
            "a-hash".to_string(),
            "b-hash".to_string(),
            &a_entries,
            &b_entries,
        );

        let mut affected_by_path = BTreeMap::new();
        for change in &report.changes {
            affected_by_path.insert(change.entry_path.clone(), change.affected_claims.clone());
        }

        assert_eq!(
            affected_by_path.get("evidence/team/docs/appendix.md"),
            Some(&vec!["CLAIM-ALPHA".to_string(), "CLAIM-ZETA".to_string()])
        );
        assert_eq!(
            affected_by_path.get("evidence/team/docs/policy.md"),
            Some(&vec!["CLAIM-ALPHA".to_string(), "CLAIM-ZETA".to_string()])
        );
        assert_eq!(
            affected_by_path.get("team/data/input.json/segments/part-1.txt"),
            Some(&vec!["CLAIM-BETA".to_string()])
        );
        assert_eq!(
            affected_by_path.get("unrelated/new.txt"),
            Some(&Vec::<String>::new())
        );

        assert_eq!(report.drift_summary.counts.added, 3);
        assert_eq!(report.drift_summary.counts.modified, 1);
        assert_eq!(report.drift_summary.counts.removed, 0);
        assert_eq!(report.drift_summary.claims_affected_count, 3);
        assert_eq!(report.drift_summary.by_impact.high, 1);
        assert_eq!(report.drift_summary.by_impact.medium, 1);
        assert_eq!(report.drift_summary.by_impact.low, 1);
    }

    fn read_zip_entry_bytes(zip_path: &Path, rel_path: &str) -> Result<Vec<u8>> {
        let file = fs::File::open(zip_path)?;
        let mut archive = zip::ZipArchive::new(file)?;
        let mut entry = archive.by_name(rel_path)?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn zip_entry_count(zip_path: &Path) -> Result<usize> {
        let file = fs::File::open(zip_path)?;
        let archive = zip::ZipArchive::new(file)?;
        Ok(archive.len())
    }
}

use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
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
const DECISION_PACK_HTML_FILE: &str = "DecisionPack.html";
const DECISION_PACK_ARTIFACT_BASENAMES: [&str; 8] = [
    DECISION_PACK_MANIFEST_FILE,
    "DecisionPack.seal.json",
    DECISION_PACK_HTML_FILE,
    "REPLAY.md",
    "Quote.json",
    "Quote.md",
    "DataShareChecklist.md",
    "cupola.manifest.json",
];
const PACK_FILE: &str = "pack.zip";

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
}

#[derive(Args, Debug, Clone)]
struct RunArgs {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    intake: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = r"E:\CupolaCore")]
    cupola_repo: PathBuf,
    #[arg(long, default_value = r"E:\Sanctuary\products\aegis")]
    aegis_repo: PathBuf,
    #[arg(long, default_value = "alpha")]
    query: String,
    #[arg(long, default_value_t = 20)]
    limit: u32,
}

#[derive(Args, Debug, Clone)]
struct PackArgs {
    #[arg(long)]
    vault: PathBuf,
    #[arg(long)]
    intake: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = r"E:\CupolaCore")]
    cupola_repo: PathBuf,
    #[arg(long, default_value = r"E:\Sanctuary\products\aegis")]
    aegis_repo: PathBuf,
    #[arg(long, default_value = "alpha")]
    query: String,
    #[arg(long, default_value_t = 20)]
    limit: u32,
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
    toolchain: DecisionPackToolchain,
    artifacts: Vec<DecisionPackArtifact>,
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
    evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Serialize)]
struct DriftReportV1 {
    schema_version: String,
    generated_at: String,
    a_sha256: String,
    b_sha256: String,
    changes: Vec<DriftChange>,
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
}

#[derive(Serialize)]
struct DriftJsonSummary {
    metric: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    a_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    b_count: Option<usize>,
}

#[derive(Clone)]
struct ZipEntrySnapshot {
    sha256: String,
    summary_bytes: Option<Vec<u8>>,
}

struct ClaimSeed {
    title: String,
    status: String,
    evidence_refs: Vec<String>,
    notes: Option<String>,
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
    cupola_repo: PathBuf,
    aegis_repo: PathBuf,
    query: String,
    limit: u32,
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
    }
}

fn run(args: RunArgs) -> Result<()> {
    let out_dir = absolutize(&args.out)?;
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
        cupola_cli: probe_version(
            &args.cupola_repo,
            &["cargo", "run", "-p", "cupola-cli", "--", "--version"],
        ),
        aegis: probe_version(&args.aegis_repo, &["cargo", "run", "--", "--version"]),
    };

    let cupola_argv = vec![
        "cargo".to_string(),
        "run".to_string(),
        "-p".to_string(),
        "cupola-cli".to_string(),
        "--".to_string(),
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
        "cargo".to_string(),
        "run".to_string(),
        "--".to_string(),
        "run".to_string(),
        "--vault".to_string(),
        path_to_string(&args.vault),
        "--intake".to_string(),
        path_to_string(&args.intake),
        "--out".to_string(),
        path_to_string(&pack_dir),
    ];

    let mut steps = Vec::new();
    let cupola_step = execute_step(
        StepSpec {
            step_id: "step-01-cupola-export-epi",
            tool: "cupola-cli",
            cwd: args.cupola_repo.clone(),
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
            cwd: args.aegis_repo.clone(),
            argv: aegis_argv.clone(),
        },
        &out_dir,
        &logs_dir,
        &pack_dir,
    )?;
    any_failed |= aegis_step.status != "ok";
    steps.push(aegis_step);

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
        cupola_repo: args.cupola_repo.clone(),
        aegis_repo: args.aegis_repo.clone(),
        query: args.query.clone(),
        limit: args.limit,
    };
    package_bundle(&bundle_context)?;

    if any_failed {
        bail!("one or more tool steps failed; stop_reason=tool_failed");
    }

    Ok(())
}

fn pack_only(args: PackArgs) -> Result<()> {
    let out_dir = absolutize(&args.out)?;
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
        cupola_repo: args.cupola_repo,
        aegis_repo: args.aegis_repo,
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

fn execute_step(
    spec: StepSpec,
    out_dir: &Path,
    logs_dir: &Path,
    pack_dir: &Path,
) -> Result<RunStep> {
    let before = snapshot_hashes(pack_dir)?;
    let started_at = now_rfc3339_utc();

    let stdout_path = logs_dir.join(format!("{}.stdout.log", spec.step_id));
    let stderr_path = logs_dir.join(format!("{}.stderr.log", spec.step_id));

    let command_result = run_command_capture(&spec.cwd, &spec.argv);
    let finished_at = now_rfc3339_utc();

    let (status, stdout_bytes, stderr_bytes) = match command_result {
        Ok(output) => {
            let status_text = if output.status.success() {
                "ok"
            } else {
                "error"
            };
            (status_text.to_string(), output.stdout, output.stderr)
        }
        Err(err) => (
            "error".to_string(),
            Vec::new(),
            format!("{err:#}\n").into_bytes(),
        ),
    };

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
    build_zip(&context.pack_dir, &pack_zip, false)?;
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
    let manifest_ref = manifest_rel.as_ref().map(|path| normalize_rel_path(path));
    let html_ref = html_rel.as_ref().map(|path| normalize_rel_path(path));

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

    if claim_seeds.is_empty() {
        let mut evidence_refs = Vec::new();
        if let Some(manifest_ref) = &manifest_ref {
            evidence_refs.push(manifest_ref.clone());
        } else if let Some(html_ref) = &html_ref {
            evidence_refs.push(html_ref.clone());
        }

        claim_seeds.push(ClaimSeed {
            title: "Claim 1".to_string(),
            status: "unknown".to_string(),
            evidence_refs,
            notes: Some("No structured claims were found in DecisionPack artifacts.".to_string()),
        });
    }

    let claims = claim_seeds
        .into_iter()
        .enumerate()
        .map(|(idx, seed)| ClaimV1 {
            claim_id: format!("CLAIM-{num:03}", num = idx + 1),
            title: seed.title,
            status: normalize_claim_status(&seed.status),
            evidence_refs: stable_unique_sorted_strings(seed.evidence_refs),
            notes: seed.notes,
        })
        .collect();

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
    for rel in rel_paths {
        let file_name = rel.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if !DECISION_PACK_ARTIFACT_BASENAMES.contains(&file_name) {
            continue;
        }

        let rel_path = normalize_rel_path(&rel);
        let sha256 = sha256_file(&context.pack_dir.join(&rel))?;
        artifacts.push(DecisionPackArtifact { rel_path, sha256 });
    }

    Ok(DecisionPackV1 {
        schema_version: DECISION_PACK_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
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

fn build_self_drift_report(pack_dir: &Path) -> Result<DriftReportV1> {
    let listing = snapshot_hashes(pack_dir)?;
    let snapshot_sha = sha256_of_hash_listing(&listing);
    Ok(DriftReportV1 {
        schema_version: DRIFT_REPORT_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
        a_sha256: snapshot_sha.clone(),
        b_sha256: snapshot_sha,
        changes: Vec::new(),
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
        let mut evidence_refs = extract_evidence_refs(control_result.get("evidence_refs"));
        if evidence_refs.is_empty() {
            evidence_refs.push(manifest_ref.to_string());
        }

        claims.push(ClaimSeed {
            title,
            status,
            evidence_refs,
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
        claims.push(ClaimSeed {
            title: claim_key.to_string(),
            status: status.to_string(),
            evidence_refs: vec![manifest_ref.to_string()],
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
        let mut evidence_refs = extract_evidence_refs(entry.get("evidence_refs"));
        if evidence_refs.is_empty() {
            evidence_refs.push(manifest_ref.to_string());
        }

        claims.push(ClaimSeed {
            title,
            status: "unknown".to_string(),
            evidence_refs,
            notes: query_id.map(|value| format!("query_id={value}")),
        });
    }

    claims
}

fn extract_claims_from_html(html: &str, html_ref: &str) -> Vec<ClaimSeed> {
    let mut claims = Vec::new();
    for token in extract_code_tokens(html) {
        claims.push(ClaimSeed {
            title: token,
            status: "unknown".to_string(),
            evidence_refs: vec![html_ref.to_string()],
            notes: Some("derived from DecisionPack.html".to_string()),
        });
    }
    claims
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

fn extract_evidence_refs(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut evidence_refs = Vec::new();
    for item in items {
        if let Some(evidence_ref) = evidence_ref_to_string(item) {
            evidence_refs.push(evidence_ref);
        }
    }

    stable_unique_sorted_strings(evidence_refs)
}

fn evidence_ref_to_string(value: &Value) -> Option<String> {
    if let Some(text) = value_non_empty_string(value) {
        return Some(text.to_string());
    }

    let object = value.as_object()?;
    if let Some(raw_blob_id) = object.get("raw_blob_id").and_then(value_non_empty_string) {
        return Some(format!("raw_blob_id:{raw_blob_id}"));
    }
    if let Some(chunk_blob_id) = object.get("chunk_blob_id").and_then(value_non_empty_string) {
        return Some(format!("chunk_blob_id:{chunk_blob_id}"));
    }
    if let Some(rel_path) = object.get("rel_path").and_then(value_non_empty_string) {
        let start_line = object.get("start_line").and_then(Value::as_u64);
        let end_line = object.get("end_line").and_then(Value::as_u64);
        return Some(match (start_line, end_line) {
            (Some(start), Some(end)) => format!("{rel_path}#L{start}-L{end}"),
            _ => rel_path.to_string(),
        });
    }
    if let Some(chunk_id) = object.get("chunk_id").and_then(value_non_empty_string) {
        return Some(format!("chunk_id:{chunk_id}"));
    }

    None
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
    DriftReportV1 {
        schema_version: DRIFT_REPORT_SCHEMA.to_string(),
        generated_at: now_rfc3339_utc(),
        a_sha256,
        b_sha256,
        changes: compute_drift_changes(a_entries, b_entries),
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
            }),
            (Some(a_entry), None) => changes.push(DriftChange {
                kind: "removed".to_string(),
                entry_path: entry_path.clone(),
                a_sha256: Some(a_entry.sha256.clone()),
                b_sha256: None,
                summary: summarize_json_change(&entry_path, a_entry.summary_bytes.as_deref(), None),
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
                });
            }
            _ => {}
        }
    }

    sort_drift_changes_deterministically(&mut changes);
    changes
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
    let mut added = 0usize;
    let mut removed = 0usize;
    let mut modified = 0usize;
    for change in &report.changes {
        match change.kind.as_str() {
            "added" => added += 1,
            "removed" => removed += 1,
            "modified" => modified += 1,
            _ => {}
        }
    }

    let mut output = String::new();
    output.push_str("# Drift Report\n\n");
    output.push_str(&format!("- generated_at: `{}`\n", report.generated_at));
    output.push_str(&format!("- a: `{}`\n", a_zip.display()));
    output.push_str(&format!("- b: `{}`\n", b_zip.display()));
    output.push_str(&format!("- a_sha256: `{}`\n", report.a_sha256));
    output.push_str(&format!("- b_sha256: `{}`\n", report.b_sha256));
    output.push_str(&format!(
        "- totals: added={}, removed={}, modified={}\n",
        added, removed, modified
    ));

    if report.changes.is_empty() {
        output.push_str("\nNo file-level changes detected.\n");
        return output;
    }

    output.push_str("\n## Changes\n");
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
        output.push('\n');
    }

    output
}

fn is_zip_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
}

fn build_replay_commands(context: &BundleContext) -> Vec<String> {
    let cupola = vec![
        "cargo".to_string(),
        "run".to_string(),
        "-p".to_string(),
        "cupola-cli".to_string(),
        "--".to_string(),
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
        "cargo".to_string(),
        "run".to_string(),
        "--".to_string(),
        "run".to_string(),
        "--vault".to_string(),
        path_to_string(&context.vault),
        "--intake".to_string(),
        path_to_string(&context.intake),
        "--out".to_string(),
        path_to_string(&context.pack_dir),
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
        "--cupola-repo".to_string(),
        path_to_string(&context.cupola_repo),
        "--aegis-repo".to_string(),
        path_to_string(&context.aegis_repo),
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

fn probe_version(cwd: &Path, argv: &[&str]) -> String {
    let (program, args) = match argv.split_first() {
        Some(value) => value,
        None => return "unknown".to_string(),
    };

    let output = Command::new(program).args(args).current_dir(cwd).output();
    let output = match output {
        Ok(value) => value,
        Err(_) => return "unknown".to_string(),
    };
    if !output.status.success() {
        return "unknown".to_string();
    }

    extract_first_non_empty_line(&output.stdout).unwrap_or_else(|| "unknown".to_string())
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
    fn claims_extraction_from_manifest_has_schema_and_claims() -> Result<()> {
        let temp_root = std::env::temp_dir().join(format!("leo-test-claims-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let pack_dir = temp_root.join("pack");
            let decision_pack_dir = pack_dir.join("acme").join("eng42").join("PACK-001");
            fs::create_dir_all(&decision_pack_dir)?;

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

            let claims = build_claims_from_pack_dir(&pack_dir)?;
            assert_eq!(claims.schema_version, CLAIMS_SCHEMA);
            assert!(!claims.claims.is_empty());
            assert_eq!(claims.claims[0].claim_id, "CLAIM-001");
            assert_eq!(claims.claims[0].status, "supported");
            assert!(!claims.claims[0].evidence_refs.is_empty());

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
    }

    fn zip_entry_count(zip_path: &Path) -> Result<usize> {
        let file = fs::File::open(zip_path)?;
        let archive = zip::ZipArchive::new(file)?;
        Ok(archive.len())
    }
}

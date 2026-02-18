use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::Command,
};
use uuid::Uuid;
use walkdir::WalkDir;
use zip::{CompressionMethod, DateTime as ZipDateTime, ZipWriter, write::SimpleFileOptions};

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
const DECISION_PACK_ARTIFACT_BASENAMES: [&str; 8] = [
    "DecisionPack.manifest.json",
    "DecisionPack.seal.json",
    "DecisionPack.html",
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
struct ClaimsV1Stub {
    schema_version: String,
    status: String,
    claims: Vec<String>,
}

#[derive(Serialize)]
struct DriftReportV1Stub {
    schema_version: String,
    status: String,
    drift: Vec<String>,
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

    let claims_stub = ClaimsV1Stub {
        schema_version: CLAIMS_SCHEMA.to_string(),
        status: "stub".to_string(),
        claims: Vec::new(),
    };
    write_json_pretty(&context.pack_dir.join(CLAIMS_FILE), &claims_stub)?;

    let drift_stub = DriftReportV1Stub {
        schema_version: DRIFT_REPORT_SCHEMA.to_string(),
        status: "stub".to_string(),
        drift: Vec::new(),
    };
    write_json_pretty(&context.pack_dir.join(DRIFT_REPORT_FILE), &drift_stub)?;

    Ok(())
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

    fn zip_entry_count(zip_path: &Path) -> Result<usize> {
        let file = fs::File::open(zip_path)?;
        let archive = zip::ZipArchive::new(file)?;
        Ok(archive.len())
    }
}

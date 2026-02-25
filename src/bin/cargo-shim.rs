use std::env;
use std::process::{Command, exit};

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let forwarded_args = match parse_forwarded_args(&raw_args) {
        Ok(value) => value,
        Err(message) => fail(&message),
    };

    let cupola_exe = match resolve_cupola_exe() {
        Some(path) => path,
        None => fail("CUPOLA_CLI/CUPOLA_BIN/CUPOLA_EXE is not set"),
    };

    let status = match Command::new(&cupola_exe).args(&forwarded_args).status() {
        Ok(value) => value,
        Err(err) => fail(&format!(
            "failed to execute cupola cli '{cupola_exe}': {err}"
        )),
    };

    match status.code() {
        Some(code) => exit(code),
        None => exit(1),
    }
}

fn parse_forwarded_args(args: &[String]) -> Result<Vec<String>, String> {
    if args.len() < 5 {
        return Err(
            "unsupported invocation (expected: cargo run -p cupola-cli -- <args>)".to_string(),
        );
    }
    if !args[0].eq_ignore_ascii_case("run")
        || args[1] != "-p"
        || !args[2].eq_ignore_ascii_case("cupola-cli")
        || args[3] != "--"
    {
        return Err(
            "unsupported invocation (expected: cargo run -p cupola-cli -- <args>)".to_string(),
        );
    }

    let forwarded = args[4..].to_vec();
    if forwarded.is_empty() {
        return Err("missing cupola arguments after '--'".to_string());
    }
    Ok(forwarded)
}

fn resolve_cupola_exe() -> Option<String> {
    for key in ["CUPOLA_CLI", "CUPOLA_BIN", "CUPOLA_EXE"] {
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn fail(message: &str) -> ! {
    eprintln!("cargo shim error: {message}");
    exit(1);
}

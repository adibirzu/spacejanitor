use sj_core::{SCHEMA_BLOCKERS_V1, SCHEMA_MEMORY_V1, SCHEMA_ORPHANS_V1, SCHEMA_PROPOSAL_V1, SCHEMA_STORAGE_V1};
use std::env;
use std::process::ExitCode;

fn print_doctor(json_mode: bool) {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    let version = env!("CARGO_PKG_VERSION");
    if json_mode {
        println!(
            "{{\"schema\":\"spacejanitor.doctor.v1\",\"engine\":\"rust\",\"version\":\"{version}\",\"os\":\"{os}\",\"arch\":\"{arch}\",\"schemas\":[\"{SCHEMA_STORAGE_V1}\",\"{SCHEMA_MEMORY_V1}\",\"{SCHEMA_BLOCKERS_V1}\",\"{SCHEMA_ORPHANS_V1}\",\"{SCHEMA_PROPOSAL_V1}\"],\"ready\":true}}"
        );
    } else {
        println!("sj (Rust core) v{version} — {os}/{arch}");
        println!("schemas: {SCHEMA_STORAGE_V1}, {SCHEMA_MEMORY_V1}, {SCHEMA_BLOCKERS_V1}, {SCHEMA_ORPHANS_V1}, {SCHEMA_PROPOSAL_V1}");
        println!("status: READY");
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let cmd = args.iter().find(|a| !a.starts_with('-')).map(String::as_str).unwrap_or("help");

    match cmd {
        "doctor" => {
            print_doctor(json_mode);
            ExitCode::SUCCESS
        }
        "help" | _ => {
            println!("sj — SpaceJanitor Rust Core CLI (v{})", env!("CARGO_PKG_VERSION"));
            println!("usage: sj <doctor|disk|memory|blockers|orphans|advise> [--json]");
            ExitCode::SUCCESS
        }
    }
}

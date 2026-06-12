use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config_path = Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .join(".build-config.toml");

    println!("cargo:rerun-if-changed=.build-config.toml");
    println!("cargo:rerun-if-changed=build.rs");

    let binary_name = if config_path.exists() {
        parse_binary_name(&config_path)
            .and_then(|raw| sanitize_binary_name(&raw))
            .unwrap_or_else(|| {
                println!(
                    "cargo:warning=Invalid or missing binary_name in .build-config.toml, using default 'aisudo'"
                );
                "aisudo".to_string()
            })
    } else {
        "aisudo".to_string()
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("bin_name.rs");

    // Emit via {:?} so the value is always a properly-escaped Rust string literal.
    // Combined with sanitize_binary_name's charset check, a crafted binary_name
    // cannot break out of the literal and inject code into the CLI (M6).
    fs::write(
        &dest_path,
        format!("pub const BINARY_NAME: &str = {binary_name:?};"),
    )
    .expect("Failed to write bin_name.rs");

    println!("cargo:rustc-env=BINARY_NAME={binary_name}");
}

/// A binary name is a single filename component. Restrict it to a safe charset
/// so it can never escape the generated Rust string literal or the cargo
/// directive. Returns None for anything outside `[A-Za-z0-9_-]` (the caller
/// falls back to the default).
fn sanitize_binary_name(value: &str) -> Option<String> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Some(value.to_string())
    } else {
        None
    }
}

fn parse_binary_name(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.ok()?;
        let line = line.trim();

        if line.starts_with("binary_name") {
            if let Some(eq_pos) = line.find('=') {
                let value = line[eq_pos + 1..].trim();
                let value = value.trim_matches('"').trim_matches('\'');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

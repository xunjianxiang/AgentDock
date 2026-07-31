use std::{collections::BTreeMap, fs, path::PathBuf};

fn main() {
    const OTLP_VARIABLES: [&str; 3] = [
        "AGENTDOCK_OTLP_ENDPOINT",
        "AGENTDOCK_OTLP_TOKEN",
        "AGENTDOCK_OTLP_SERVICE_NAME",
    ];
    for name in OTLP_VARIABLES {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let local = local_build_env();
    let configured = OTLP_VARIABLES.map(|name| {
        let value = std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| local.get(name).cloned());
        if let Some(value) = value.as_deref() {
            println!("cargo:rustc-env={name}={value}");
        }
        value.is_some()
    });
    if configured.iter().any(|present| *present) {
        for (name, present) in OTLP_VARIABLES.iter().zip(configured) {
            assert!(present, "Missing required packaged OTLP variable: {name}");
        }
    }
    tauri_build::build();
}

fn local_build_env() -> BTreeMap<String, String> {
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| "src-tauri".into()));
    let path = manifest_dir
        .parent()
        .unwrap_or(manifest_dir.as_path())
        .join(".env");
    println!("cargo:rerun-if-changed={}", path.display());
    let Ok(raw) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .or_else(|| {
                    value
                        .strip_prefix('\'')
                        .and_then(|value| value.strip_suffix('\''))
                })
                .unwrap_or(value)
                .trim();
            (!value.is_empty()).then(|| (key.to_string(), value.to_string()))
        })
        .collect()
}

//! End-to-end tests of the `soroban-linter` binary.

use std::process::Command;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_soroban-linter"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

#[test]
fn exit_codes() {
    assert_eq!(run(&[&fixture("safe_contract.rs")]).0, 0);
    assert_eq!(run(&[&fixture("vulnerable_contract.rs")]).0, 1);
    assert_eq!(
        run(&[&fixture("vulnerable_contract.rs"), "--fail-on", "never"]).0,
        0
    );
    assert_eq!(run(&["--disable", "NOPE"]).0, 2);
    assert_eq!(run(&["does/not/exist"]).0, 2);
}

#[test]
fn sarif_output() {
    let (_, out) = run(&[&fixture("vulnerable_contract.rs"), "--format", "sarif"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    assert_eq!(
        run["tool"]["driver"]["rules"].as_array().unwrap().len(),
        soroban_linter::all_rules().len()
    );
    let results = run["results"].as_array().unwrap();
    assert!(!results.is_empty());
    assert!(results
        .iter()
        .all(|r| r["locations"][0]["physicalLocation"]["region"]["startLine"].is_u64()));
}

#[test]
fn cargo_subcommand_form() {
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-soroban-linter"))
        .args(["soroban-linter", &fixture("safe_contract.rs")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn explain_rule() {
    let (code, out) = run(&["--explain", "SG008"]);
    assert_eq!(code, 0);
    assert!(out.contains("unchecked-auth-address"));
    assert!(out.contains("How to fix"));
    assert_eq!(run(&["--explain", "SG999"]).0, 2);
}

#[test]
fn config_file_is_applied() {
    let dir = std::env::temp_dir().join(format!("soroban-linter-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("soroban-guard.toml");

    // Disabling every error-level rule hit by the fixture makes the run pass.
    std::fs::write(
        &cfg,
        "disable = [\"SG001\", \"SG002\", \"SG003\", \"SG004\", \"SG008\"]\n",
    )
    .unwrap();
    let cfg_s = cfg.to_str().unwrap();
    let vuln = fixture("vulnerable_contract.rs");
    assert_eq!(run(&[&vuln, "--config", cfg_s]).0, 0);

    // fail-on and severity overrides from the file.
    std::fs::write(&cfg, "fail-on = \"never\"\n[severity]\nSG007 = \"error\"\n").unwrap();
    let (code, out) = run(&[&vuln, "--config", cfg_s, "--only", "SG007"]);
    assert_eq!(code, 0);
    assert!(out.contains("error[SG007]"));

    // Unknown keys and rules are rejected.
    std::fs::write(&cfg, "max-reads = 5\n").unwrap();
    assert_eq!(run(&[&vuln, "--config", cfg_s]).0, 2);
    std::fs::write(&cfg, "disable = [\"SG999\"]\n").unwrap();
    assert_eq!(run(&[&vuln, "--config", cfg_s]).0, 2);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn example_config_is_valid() {
    let path = format!(
        "{}/../../soroban-guard.example.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let (code, _) = run(&[&fixture("safe_contract.rs"), "--config", &path]);
    assert_eq!(code, 0);
}

#[test]
fn baseline_hides_known_findings_only() {
    let dir = std::env::temp_dir().join(format!("soroban-linter-bl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let base = dir.join("baseline.json");
    let base_s = base.to_str().unwrap();
    let vuln = fixture("vulnerable_contract.rs");

    // Accept everything that exists today.
    assert_eq!(run(&[&vuln, "--write-baseline", base_s]).0, 0);
    let (code, out) = run(&[&vuln, "--baseline", base_s]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("0 error(s), 0 warning(s), 0 note(s)"));

    // A new bug in a copy of the file is still reported, even though lines moved.
    let src = std::fs::read_to_string(&vuln).unwrap();
    let modified = src.replacen(
        "#[contract]\npub struct Vault;",
        "fn shifted() {}\n\n#[contract]\npub struct Vault;",
        1,
    );
    let modified = modified.replacen(
        "    /// Read-only: never flagged by SG001.",
        "    pub fn set_owner2(e: Env, o: Address) {\n        e.storage().instance().set(&DataKey::Owner, &o);\n    }\n\n    /// Read-only: never flagged by SG001.",
        1,
    );
    let copy = dir.join("vulnerable_contract.rs");
    std::fs::write(&copy, modified).unwrap();
    // Re-key the baseline to the copy's path.
    let bl = std::fs::read_to_string(&base)
        .unwrap()
        .replace(&vuln, copy.to_str().unwrap());
    std::fs::write(&base, bl).unwrap();
    let (code, out) = run(&[copy.to_str().unwrap(), "--baseline", base_s]);
    assert_eq!(code, 1);
    assert!(out.contains("set_owner2"), "{out}");
    assert!(out.contains("1 error(s), 1 warning(s), 0 note(s)"), "{out}");

    std::fs::remove_dir_all(&dir).unwrap();
}

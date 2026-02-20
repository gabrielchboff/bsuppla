use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("bsuppla_{name}_{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    path
}

#[test]
fn cli_runs_without_docker_when_skipped() {
    let dir = temp_dir("cli");
    let tar_path = fixture_path("demo_clean.tar");
    let output_dir = dir.join("out");

    let status = Command::new(env!("CARGO_BIN_EXE_bsuppla"))
        .arg("dummy-image")
        .arg(&tar_path)
        .env("BSUPPLA_SKIP_DOCKER", "1")
        .env("BSUPPLA_SKIP_SCAN", "1")
        .env("BSUPPLA_OUTPUT_DIR", &output_dir)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(output_dir.join("hello.txt").exists());
}

#[test]
fn cli_baseline_out_and_diff() {
    let dir = temp_dir("cli_baseline");
    let tar_path = fixture_path("demo_bad.tar");
    let output_dir = dir.join("out");
    let baseline_path = dir.join("baseline.txt");
    let allowlist_path = dir.join("allowlist.txt");
    fs::write(&allowlist_path, "").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_bsuppla"))
        .arg("dummy-image")
        .arg(&tar_path)
        .arg(&allowlist_path)
        .env("BSUPPLA_SKIP_DOCKER", "1")
        .env("BSUPPLA_SKIP_SCAN", "0")
        .env("BSUPPLA_OUTPUT_DIR", &output_dir)
        .arg("--baseline-out")
        .arg(&baseline_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(baseline_path.exists());

    let output2 = Command::new(env!("CARGO_BIN_EXE_bsuppla"))
        .arg("dummy-image")
        .arg(&tar_path)
        .arg(&allowlist_path)
        .arg(&baseline_path)
        .env("BSUPPLA_SKIP_DOCKER", "1")
        .env("BSUPPLA_SKIP_SCAN", "0")
        .env("BSUPPLA_OUTPUT_DIR", &output_dir)
        .output()
        .unwrap();
    assert!(output2.status.success());
    let stdout = String::from_utf8_lossy(&output2.stdout);
    assert!(stdout.contains("No new findings") || stdout.contains("Baseline matched"));
}

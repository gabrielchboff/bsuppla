use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::detector::{Detector, FileContext, Finding, Severity};

pub struct PackageManagerConfigDetector;

const NPMRC_PATHS: &[&str] = &["/etc/npmrc", "/.npmrc", "/root/.npmrc"];
const PIP_PATHS: &[&str] = &["/etc/pip.conf", "/etc/pip/pip.conf", "/root/.pip/pip.conf"];
const GEM_PATHS: &[&str] = &["/etc/gemrc", "/.gemrc", "/root/.gemrc"];

impl Detector for PackageManagerConfigDetector {
    fn name(&self) -> &'static str {
        "package_manager_config"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();

        let is_pm_config = NPMRC_PATHS.iter().any(|p| norm == *p)
            || PIP_PATHS.iter().any(|p| norm == *p)
            || GEM_PATHS.iter().any(|p| norm == *p);

        if !is_pm_config {
            return None;
        }

        if let Some(detail) = package_manager_suspicion(ctx.path) {
            Some(Finding::new(
                "package_manager_config_suspicious",
                ctx.relative_path.clone(),
                detail,
                self.severity(),
            ))
        } else {
            None
        }
    }
}

fn package_manager_suspicion(path: &Path) -> Option<String> {
    let data = read_small(path, 64 * 1024).ok()?;
    let content = String::from_utf8_lossy(&data);
    let norm = path.to_string_lossy();
    let mut findings = Vec::new();

    if norm.contains("npmrc") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.starts_with("registry=") && !line.contains("registry.npmjs.org") {
                findings.push(format!("npm registry override: {line}"));
            }
        }
    }

    if norm.contains("pip") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.starts_with("index-url") && !line.contains("pypi.org") {
                findings.push(format!("pip index override: {line}"));
            }
            if line.starts_with("extra-index-url") && !line.contains("pypi.org") {
                findings.push(format!("pip extra-index: {line}"));
            }
        }
    }

    if norm.contains("gemrc") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.contains("http") && !line.contains("rubygems.org") {
                findings.push(format!("gem source override: {line}"));
            }
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings.join("; "))
    }
}

pub struct LockfileDetector;

const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "poetry.lock",
    "Gemfile.lock",
    "requirements.txt",
];

impl Detector for LockfileDetector {
    fn name(&self) -> &'static str {
        "lockfile_suspicious"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let name = ctx.file_name_str()?;

        if !LOCKFILE_NAMES.iter().any(|&n| name == n) {
            return None;
        }

        if let Some(detail) = lockfile_suspicion(ctx.path) {
            Some(Finding::new(
                "lockfile_suspicious_source",
                ctx.relative_path.clone(),
                detail,
                self.severity(),
            ))
        } else {
            None
        }
    }
}

fn lockfile_suspicion(path: &Path) -> Option<String> {
    let data = read_small(path, 128 * 1024).ok()?;
    let content = String::from_utf8_lossy(&data);
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("git+") || line.contains("github.com") || line.contains("gitlab.com") {
            findings.push("git source in lockfile".to_string());
            break;
        }
        if line.contains("http://") {
            findings.push("http source in lockfile".to_string());
            break;
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings.join("; "))
    }
}

pub struct ApkRepositoryDetector;

impl Detector for ApkRepositoryDetector {
    fn name(&self) -> &'static str {
        "apk_repository"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();
        if norm != "/etc/apk/repositories" {
            return None;
        }

        if let Some(detail) = apk_repo_suspicion(ctx.path) {
            Some(Finding::new(
                "apk_repository_suspicious",
                ctx.relative_path.clone(),
                detail,
                self.severity(),
            ))
        } else {
            None
        }
    }
}

fn apk_repo_suspicion(path: &Path) -> Option<String> {
    let data = read_small(path, 64 * 1024).ok()?;
    let content = String::from_utf8_lossy(&data);
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains("file://") {
            findings.push("file:// repository".to_string());
        }
        if line.contains("http")
            && !line.contains("alpinelinux.org")
            && !line.contains("dl-cdn.alpinelinux.org")
        {
            findings.push(format!("non-alpine repo: {line}"));
        }
    }

    if findings.is_empty() {
        None
    } else {
        Some(findings.join("; "))
    }
}

pub struct ApkKeyDetector;

impl Detector for ApkKeyDetector {
    fn name(&self) -> &'static str {
        "apk_key"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();
        if !norm.starts_with("/etc/apk/keys/") {
            return None;
        }

        let name = ctx.file_name_str()?;
        if !name.ends_with(".rsa.pub") {
            return Some(Finding::new(
                "apk_key_unusual",
                ctx.relative_path.clone(),
                "non-standard key name".to_string(),
                self.severity(),
            ));
        }

        None
    }
}

fn read_small(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.by_ref().take(max as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("bsuppla_{name}_{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn detects_suspicious_npm_registry() {
        let dir = temp_dir("npmrc");
        let path = dir.join("npmrc");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"registry=http://evil.example\n").unwrap();
        let result = package_manager_suspicion(&path);
        assert!(result.is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_suspicious_pip_index() {
        let dir = temp_dir("pipconf");
        let path = dir.join("pip.conf");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"index-url=http://evil.example/simple\n")
            .unwrap();
        let result = package_manager_suspicion(&path);
        assert!(result.is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_lockfile_git_sources() {
        let dir = temp_dir("lockfile");
        let path = dir.join("lockfile");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"git+https://github.com/user/repo\n")
            .unwrap();
        let result = lockfile_suspicion(&path);
        assert!(result.is_some());
        fs::remove_dir_all(&dir).ok();
    }
}

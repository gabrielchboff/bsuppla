use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use goblin::elf::Elf;

use crate::error::Result;

#[derive(Debug, Clone)]
struct Finding {
    kind: &'static str,
    path: PathBuf,
    detail: String,
}

#[derive(Debug, Clone)]
struct AllowEntry {
    kind: Option<String>,
    pattern: String,
}

#[derive(Debug, Default)]
struct ScanConfig<'a> {
    allowlist_path: Option<&'a str>,
    baseline_path: Option<&'a str>,
    baseline_out_path: Option<&'a str>,
}

/// Entry point for filesystem scanning
pub fn scan_filesystem(
    root: &str,
    allowlist_path: Option<&str>,
    baseline_path: Option<&str>,
    baseline_out_path: Option<&str>,
) -> Result<()> {
    println!("\n[+] Scanning filesystem for potential supply-chain issues...\n");
    let mut findings = Vec::new();
    let root_path = Path::new(root);
    let cfg = ScanConfig {
        allowlist_path,
        baseline_path,
        baseline_out_path,
    };
    let allowlist = load_allowlist(cfg.allowlist_path);
    let baseline = load_baseline(cfg.baseline_path).unwrap_or_default();
    walk_dir(root_path, root_path, &mut findings)?;
    report_findings(&findings, &allowlist, &baseline, cfg.baseline_out_path)?;
    Ok(())
}

/// Recursively walk directories
fn walk_dir(root: &Path, path: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let ftype = meta.file_type();
    if ftype.is_symlink() {
        return Ok(());
    }

    if meta.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return Ok(()), // skip unreadable dirs
        };

        for entry in entries.flatten() {
            walk_dir(root, &entry.path(), findings)?;
        }
        return Ok(());
    }

    if !meta.is_file() {
        return Ok(());
    }

    let rel_path = path.strip_prefix(root).unwrap_or(path);

    let mode = meta.permissions().mode();
    let is_exec = is_executable(mode);
    let is_world_writable = (mode & 0o002) != 0;
    let is_world_readable = (mode & 0o004) != 0;
    let is_suid = (mode & 0o4000) != 0;
    let is_sgid = (mode & 0o2000) != 0;

    if is_exec && (is_suid || is_sgid) {
        findings.push(Finding {
            kind: "suid_or_sgid_executable",
            path: rel_path.to_path_buf(),
            detail: format!("mode={mode:o}"),
        });
    }

    if is_exec && is_world_writable {
        findings.push(Finding {
            kind: "world_writable_executable",
            path: rel_path.to_path_buf(),
            detail: format!("mode={mode:o}"),
        });
    }

    if is_exec && is_in_writable_dir(rel_path) {
        findings.push(Finding {
            kind: "executable_in_writable_dir",
            path: rel_path.to_path_buf(),
            detail: "writable dir".to_string(),
        });
    }

    if is_exec && is_hidden_name(rel_path) {
        findings.push(Finding {
            kind: "hidden_executable",
            path: rel_path.to_path_buf(),
            detail: "starts with '.'".to_string(),
        });
    }

    if is_exec && is_elf(path) && is_unusual_exec_location(rel_path) {
        findings.push(Finding {
            kind: "elf_in_unusual_location",
            path: rel_path.to_path_buf(),
            detail: "outside standard bin/lib paths".to_string(),
        });
    }

    if is_exec
        && is_elf(path)
        && let Some(detail) = elf_suspicious_detail(path)
    {
        findings.push(Finding {
            kind: "elf_suspicious",
            path: rel_path.to_path_buf(),
            detail,
        });
    }

    if is_sensitive_shadow(rel_path) && (is_world_readable || is_world_writable) {
        findings.push(Finding {
            kind: "insecure_shadow_permissions",
            path: rel_path.to_path_buf(),
            detail: format!("mode={mode:o}"),
        });
    }

    if is_authorized_keys(rel_path) {
        findings.push(Finding {
            kind: "authorized_keys_present",
            path: rel_path.to_path_buf(),
            detail: "ssh keys can allow access".to_string(),
        });
    }

    if is_private_key_candidate(rel_path) {
        findings.push(Finding {
            kind: "private_key_candidate",
            path: rel_path.to_path_buf(),
            detail: "key material present".to_string(),
        });
    }

    if is_credential_file(rel_path) {
        findings.push(Finding {
            kind: "credential_file",
            path: rel_path.to_path_buf(),
            detail: "potential secrets".to_string(),
        });
    }

    if is_risky_tool(rel_path) {
        findings.push(Finding {
            kind: "risky_tool_present",
            path: rel_path.to_path_buf(),
            detail: "known dual-use tool".to_string(),
        });
    }

    if is_crypto_miner(rel_path) {
        findings.push(Finding {
            kind: "crypto_miner_candidate",
            path: rel_path.to_path_buf(),
            detail: "known miner name".to_string(),
        });
    }

    if is_startup_script(rel_path) {
        findings.push(Finding {
            kind: "startup_script_present",
            path: rel_path.to_path_buf(),
            detail: "init/rc/cron".to_string(),
        });
    }

    if is_package_manager_config(rel_path)
        && let Some(detail) = package_manager_suspicion(path)
    {
        findings.push(Finding {
            kind: "package_manager_config_suspicious",
            path: rel_path.to_path_buf(),
            detail,
        });
    }

    if is_lockfile(rel_path)
        && let Some(detail) = lockfile_suspicion(path)
    {
        findings.push(Finding {
            kind: "lockfile_suspicious_source",
            path: rel_path.to_path_buf(),
            detail,
        });
    }

    if is_apk_repositories_file(rel_path)
        && let Some(detail) = apk_repo_suspicion(path)
    {
        findings.push(Finding {
            kind: "apk_repository_suspicious",
            path: rel_path.to_path_buf(),
            detail,
        });
    }

    if is_apk_key_path(rel_path) && !is_expected_apk_key(rel_path) {
        findings.push(Finding {
            kind: "apk_key_unusual",
            path: rel_path.to_path_buf(),
            detail: "non-standard key name".to_string(),
        });
    }

    Ok(())
}

fn is_elf(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }

    magic == [0x7f, b'E', b'L', b'F']
}

fn report_findings(
    findings: &[Finding],
    allowlist: &[AllowEntry],
    baseline: &HashSet<String>,
    baseline_out_path: Option<&str>,
) -> Result<()> {
    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| !is_allowlisted_with_kind(f, allowlist))
        .collect();

    let baseline_filtered = filter_baseline(baseline, allowlist);
    let (new_findings, known_findings) = diff_with_baseline(&filtered, &baseline_filtered);
    let missing_baseline = missing_from_scan(&filtered, &baseline_filtered);

    if let Some(path) = baseline_out_path {
        write_baseline(path, &filtered)?;
        println!("[+] Baseline written: {path}");
    }

    if new_findings.is_empty() && baseline_filtered.is_empty() {
        println!("[+] No high-signal findings detected.");
        println!("[+] Suspicion level: low");
        return Ok(());
    }

    if !new_findings.is_empty() {
        println!("[+] Findings:");
        for f in &new_findings {
            println!(" - {}: {} ({})", f.kind, f.path.display(), f.detail);
        }
    } else if !baseline_filtered.is_empty() {
        println!("[+] No new findings (all matched baseline).");
    }

    if !baseline_filtered.is_empty() {
        println!("[+] Baseline matched: {}", known_findings.len());
        if !missing_baseline.is_empty() {
            println!("[+] Baseline missing:");
            for key in &missing_baseline {
                println!(" - {key}");
            }
        }
    }

    let level = suspicion_level(&new_findings);
    println!("[+] Suspicion level: {level}");
    Ok(())
}

fn is_executable(mode: u32) -> bool {
    (mode & 0o111) != 0
}

fn is_in_writable_dir(path: &Path) -> bool {
    const DIRS: [&str; 5] = ["/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run"];
    let norm = normalized(path);
    DIRS.iter().any(|d| norm.starts_with(d))
}

fn is_hidden_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with('.'))
        .unwrap_or(false)
}

fn is_unusual_exec_location(path: &Path) -> bool {
    const OK_PREFIXES: [&str; 8] = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/lib",
        "/usr/lib",
    ];
    let norm = normalized(path);
    !OK_PREFIXES.iter().any(|p| norm.starts_with(p))
}

fn is_sensitive_shadow(path: &Path) -> bool {
    normalized(path).ends_with("/etc/shadow")
}

fn is_authorized_keys(path: &Path) -> bool {
    normalized(path).ends_with("/.ssh/authorized_keys")
}

fn is_private_key_candidate(path: &Path) -> bool {
    let s = normalized(path);
    if !s.contains("/.ssh/") {
        return false;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(name, "id_rsa" | "id_ed25519" | "id_dsa" | "id_ecdsa") || name.ends_with(".pem")
}

fn is_credential_file(path: &Path) -> bool {
    let norm = normalized(path);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with(".env") {
        return true;
    }
    if matches!(
        name,
        ".npmrc"
            | ".pypirc"
            | ".netrc"
            | ".git-credentials"
            | "config.json"
            | "credentials"
            | "config"
    ) {
        return norm.ends_with("/.docker/config.json")
            || norm.ends_with("/.aws/credentials")
            || norm.ends_with("/.aws/config")
            || norm.ends_with("/.kube/config")
            || norm.ends_with("/.npmrc")
            || norm.ends_with("/.pypirc")
            || norm.ends_with("/.netrc")
            || norm.ends_with("/.git-credentials");
    }
    false
}

fn is_risky_tool(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(
        name,
        "curl"
            | "wget"
            | "nc"
            | "ncat"
            | "netcat"
            | "socat"
            | "ssh"
            | "scp"
            | "sftp"
            | "strace"
            | "tcpdump"
    )
}

fn is_crypto_miner(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(
        name,
        "xmrig" | "xmr-stak" | "minerd" | "cgminer" | "bfgminer" | "kawpowminer" | "cryptonight"
    )
}

fn is_startup_script(path: &Path) -> bool {
    let norm = normalized(path);
    norm.starts_with("/etc/init.d/")
        || norm.starts_with("/etc/rc")
        || norm.starts_with("/etc/cron.")
        || norm.starts_with("/etc/cron/")
        || norm.starts_with("/var/spool/cron")
        || norm == "/etc/crontab"
}

fn is_package_manager_config(path: &Path) -> bool {
    let norm = normalized(path);
    matches!(
        norm.as_str(),
        "/etc/npmrc"
            | "/.npmrc"
            | "/root/.npmrc"
            | "/etc/pip.conf"
            | "/etc/pip/pip.conf"
            | "/root/.pip/pip.conf"
            | "/etc/gemrc"
            | "/.gemrc"
            | "/root/.gemrc"
    )
}

fn package_manager_suspicion(path: &Path) -> Option<String> {
    let data = read_small(path, 64 * 1024).ok()?;
    let content = String::from_utf8_lossy(&data);
    let norm = normalized(path);
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

fn is_lockfile(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Pipfile.lock"
            | "poetry.lock"
            | "Gemfile.lock"
            | "requirements.txt"
    )
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

fn is_apk_repositories_file(path: &Path) -> bool {
    normalized(path) == "/etc/apk/repositories"
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

fn is_apk_key_path(path: &Path) -> bool {
    normalized(path).starts_with("/etc/apk/keys/")
}

fn is_expected_apk_key(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".rsa.pub")
}

fn elf_suspicious_detail(path: &Path) -> Option<String> {
    let data = read_small(path, 5 * 1024 * 1024).ok()?;
    let elf = Elf::parse(&data).ok()?;

    let has_symtab = elf
        .section_headers
        .iter()
        .any(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".symtab"));
    let has_strtab = elf
        .section_headers
        .iter()
        .any(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".strtab"));
    let stripped = !(has_symtab || has_strtab);

    let has_interp = elf
        .program_headers
        .iter()
        .any(|p| p.p_type == goblin::elf::program_header::PT_INTERP);
    let has_dynamic = elf
        .program_headers
        .iter()
        .any(|p| p.p_type == goblin::elf::program_header::PT_DYNAMIC);
    let is_static = !has_interp && !has_dynamic;

    let mut unusual = false;
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
            && (name.contains("upx") || name.contains("packer") || name.contains("packed"))
        {
            unusual = true;
            break;
        }
    }

    if stripped || is_static || unusual {
        let mut parts = Vec::new();
        if stripped {
            parts.push("stripped");
        }
        if is_static {
            parts.push("static");
        }
        if unusual {
            parts.push("suspicious_sections");
        }
        return Some(parts.join(","));
    }
    None
}

fn read_small(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.by_ref().take(max as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_baseline(path: &str, findings: &[&Finding]) -> Result<()> {
    let mut lines: Vec<String> = findings.iter().map(|f| finding_key(f)).collect();
    lines.sort();
    let content = lines.join("\n");
    fs::write(path, content)?;
    Ok(())
}

fn load_baseline(path: Option<&str>) -> Option<HashSet<String>> {
    let path = path?;
    let content = fs::read_to_string(path).ok()?;
    let mut set = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        set.insert(line.to_string());
    }
    Some(set)
}

fn load_allowlist(path: Option<&str>) -> Vec<AllowEntry> {
    let mut entries = default_allowlist();
    let Some(path) = path else {
        return entries;
    };
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return entries,
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((kind, pat)) = parse_allowlist_line(line) {
            entries.push(AllowEntry {
                kind: Some(kind),
                pattern: normalize_allowlist_line(&pat),
            });
        } else {
            entries.push(AllowEntry {
                kind: None,
                pattern: normalize_allowlist_line(line),
            });
        }
    }
    entries
}

fn normalize_allowlist_line(line: &str) -> String {
    if line.starts_with('/') {
        line.to_string()
    } else {
        format!("/{line}")
    }
}

fn parse_allowlist_line(line: &str) -> Option<(String, String)> {
    let (kind, rest) = line.split_once(": ")?;
    if kind.is_empty() || rest.is_empty() {
        return None;
    }
    Some((kind.to_string(), rest.to_string()))
}

fn default_allowlist() -> Vec<AllowEntry> {
    vec![
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/bin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/sbin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/usr/bin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/usr/sbin/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/lib/*".to_string(),
        },
        AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/usr/lib/*".to_string(),
        },
    ]
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut i = 0usize;
    let mut j = 0usize;
    let mut star_i: Option<usize> = None;
    let mut star_j: Option<usize> = None;

    while j < t.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star_i = Some(i);
            star_j = Some(j);
            i += 1;
        } else if let (Some(si), Some(sj)) = (star_i, star_j) {
            i = si + 1;
            j = sj + 1;
            star_j = Some(j);
        } else {
            return false;
        }
    }

    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}

fn is_allowlisted_with_kind(finding: &Finding, allowlist: &[AllowEntry]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let norm = normalized(&finding.path);
    allowlist.iter().any(|a| {
        if let Some(k) = &a.kind
            && k != finding.kind
        {
            return false;
        }
        wildcard_match(&a.pattern, &norm)
    })
}

fn filter_baseline(baseline: &HashSet<String>, allowlist: &[AllowEntry]) -> HashSet<String> {
    if allowlist.is_empty() {
        return baseline.clone();
    }
    baseline
        .iter()
        .filter(|k| !baseline_path_allowlisted(k, allowlist))
        .cloned()
        .collect()
}

fn baseline_path_allowlisted(entry: &str, allowlist: &[AllowEntry]) -> bool {
    let mut parts = entry.splitn(2, ": ");
    let kind = parts.next().unwrap_or("");
    let path = match parts.next() {
        Some(p) => p,
        None => return false,
    };
    let norm = normalize_allowlist_line(path);
    allowlist.iter().any(|a| {
        if let Some(k) = &a.kind
            && k != kind
        {
            return false;
        }
        wildcard_match(&a.pattern, &norm)
    })
}

fn finding_key(f: &Finding) -> String {
    format!("{}: {}", f.kind, f.path.display())
}

fn diff_with_baseline<'a>(
    findings: &'a [&Finding],
    baseline: &HashSet<String>,
) -> (Vec<&'a Finding>, Vec<&'a Finding>) {
    if baseline.is_empty() {
        return (findings.to_vec(), Vec::new());
    }
    let mut new_findings = Vec::new();
    let mut known = Vec::new();
    for f in findings {
        if baseline.contains(&finding_key(f)) {
            known.push(*f);
        } else {
            new_findings.push(*f);
        }
    }
    (new_findings, known)
}

fn missing_from_scan(findings: &[&Finding], baseline: &HashSet<String>) -> Vec<String> {
    if baseline.is_empty() {
        return Vec::new();
    }
    let present: HashSet<String> = findings.iter().map(|f| finding_key(f)).collect();
    baseline
        .iter()
        .filter(|k| !present.contains(*k))
        .cloned()
        .collect()
}

fn suspicion_level(findings: &[&Finding]) -> &'static str {
    let mut score = 0u32;
    for f in findings {
        score += match f.kind {
            "crypto_miner_candidate" => 5,
            "private_key_candidate" => 4,
            "credential_file" => 4,
            "suid_or_sgid_executable" => 3,
            "world_writable_executable" => 3,
            "apk_repository_suspicious" => 3,
            "apk_key_unusual" => 3,
            "package_manager_config_suspicious" => 3,
            "lockfile_suspicious_source" => 2,
            "elf_suspicious" => 2,
            "elf_in_unusual_location" => 2,
            "executable_in_writable_dir" => 2,
            "authorized_keys_present" => 2,
            "startup_script_present" => 1,
            "risky_tool_present" => 1,
            "hidden_executable" => 1,
            "insecure_shadow_permissions" => 3,
            _ => 1,
        };
    }
    if score >= 10 {
        "high"
    } else if score >= 4 {
        "medium"
    } else {
        "low"
    }
}

fn normalized(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.starts_with('/') {
        s.to_string()
    } else {
        format!("/{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AllowEntry, baseline_path_allowlisted, is_elf, lockfile_suspicion,
        package_manager_suspicion, wildcard_match,
    };
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("bsuppla_{name}_{nanos}"));
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let path = temp_path(name);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn detects_elf_magic() {
        let path = temp_path("elf");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[0x7f, b'E', b'L', b'F', 0x00]).unwrap();
        assert!(is_elf(&path));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_non_elf_magic() {
        let path = temp_path("noelf");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"NOPE").unwrap();
        assert!(!is_elf(&path));
        fs::remove_file(&path).ok();
    }

    #[test]
    fn baseline_allowlist_match() {
        let allowlist = vec![AllowEntry {
            kind: Some("elf_suspicious".to_string()),
            pattern: "/bin/*".to_string(),
        }];
        let entry = "elf_suspicious: /bin/busybox";
        assert!(baseline_path_allowlisted(entry, &allowlist));
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("/usr/lib/*", "/usr/lib/libssl.so.3"));
        assert!(wildcard_match("*/bin/*", "/usr/bin/curl"));
        assert!(!wildcard_match("/usr/lib/*", "/usr/bin/curl"));
    }

    #[test]
    fn detects_suspicious_npm_registry() {
        let dir = temp_dir("npmrc");
        let path = dir.join("npmrc");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"registry=http://evil.example\n").unwrap();
        let detail = package_manager_suspicion(&path);
        assert!(detail.is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_suspicious_pip_index() {
        let dir = temp_dir("pipconf");
        let path = dir.join("pip.conf");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"index-url=http://evil.example/simple\n")
            .unwrap();
        let detail = package_manager_suspicion(&path);
        assert!(detail.is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detects_lockfile_git_sources() {
        let dir = temp_dir("lockfile");
        let path = dir.join("lockfile");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"git+https://github.com/user/repo\n")
            .unwrap();
        let detail = lockfile_suspicion(&path);
        assert!(detail.is_some());
        fs::remove_dir_all(&dir).ok();
    }
}

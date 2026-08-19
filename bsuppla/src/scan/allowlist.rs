//! Allowlist handling: default entries, file parsing, and matching.
//!
//! An allowlist suppresses findings by kind + path pattern. Entries may
//! optionally be prefixed with a finding kind: `<kind>: <path-or-pattern>`.
//! Patterns support `*` and `?`.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::core::Finding;

#[derive(Debug, Clone)]
pub struct AllowEntry {
    pub kind: Option<String>,
    pub pattern: String,
}

impl AllowEntry {
    pub fn new(kind: Option<String>, pattern: String) -> Self {
        Self {
            kind,
            pattern: normalize_allowlist_line(&pattern),
        }
    }
}

/// Load the user allowlist file on top of the built-in default allowlist.
/// A unreadable file silently falls back to the defaults.
pub fn load_allowlist(path: Option<&str>) -> Vec<AllowEntry> {
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
            entries.push(AllowEntry::new(Some(kind), pat));
        } else {
            entries.push(AllowEntry::new(None, line.to_string()));
        }
    }
    entries
}

fn parse_allowlist_line(line: &str) -> Option<(String, String)> {
    let (kind, rest) = line.split_once(": ")?;
    if kind.is_empty() || rest.is_empty() {
        return None;
    }
    Some((kind.to_string(), rest.to_string()))
}

fn normalize_allowlist_line(line: &str) -> String {
    if line.starts_with('/') {
        line.to_string()
    } else {
        format!("/{line}")
    }
}

/// Built-in suppressors: standard library/bin locations for ELF signals.
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

/// True if the finding's kind + path match any allowlist entry.
pub fn is_allowlisted(finding: &Finding, allowlist: &[AllowEntry]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let norm = normalized(&finding.path);
    allowlist.iter().any(|a| {
        if let Some(k) = &a.kind
            && k != &finding.kind
        {
            return false;
        }
        wildcard_match(&a.pattern, &norm)
    })
}

/// Drop baseline entries that the allowlist would suppress anyway.
pub fn filter_baseline(baseline: &HashSet<String>, allowlist: &[AllowEntry]) -> HashSet<String> {
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
    use super::{AllowEntry, baseline_path_allowlisted, wildcard_match};

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("/usr/lib/*", "/usr/lib/libssl.so.3"));
        assert!(wildcard_match("*/bin/*", "/usr/bin/curl"));
        assert!(!wildcard_match("/usr/lib/*", "/usr/bin/curl"));
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
}

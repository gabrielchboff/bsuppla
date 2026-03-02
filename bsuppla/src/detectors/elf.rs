use std::fs::File;
use std::io::Read;
use std::path::Path;

use goblin::elf::Elf;

use crate::detector::{Detector, FileContext, Finding, Severity};

pub struct ElfAnalyzerDetector;

const STANDARD_BIN_PREFIXES: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/lib",
    "/usr/lib",
];

impl Detector for ElfAnalyzerDetector {
    fn name(&self) -> &'static str {
        "elf_analyzer"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        if !ctx.is_executable {
            return None;
        }

        let path = ctx.path;
        if !is_elf(path) {
            return None;
        }

        let mut findings = Vec::new();
        let norm = ctx.normalized_path();

        if !STANDARD_BIN_PREFIXES.iter().any(|p| norm.starts_with(p)) {
            findings.push("outside standard bin/lib paths".to_string());
        }

        if let Some(detail) = elf_suspicious_detail(path) {
            findings.push(detail);
        }

        if findings.is_empty() {
            None
        } else {
            let kind = if findings.iter().any(|f| f.contains("stripped") || f.contains("static") || f.contains("suspicious")) {
                "elf_suspicious"
            } else {
                "elf_in_unusual_location"
            };
            let detail = findings.join("; ");

            Some(Finding::new(
                kind,
                ctx.relative_path.clone(),
                detail,
                if kind == "elf_suspicious" { Severity::Medium } else { Severity::Low },
            ))
        }
    }
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

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("bsuppla_{name}_{nanos}"));
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
    fn rejects_non_elf() {
        let path = temp_path("noelf");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"NOPE").unwrap();
        assert!(!is_elf(&path));
        fs::remove_file(&path).ok();
    }
}

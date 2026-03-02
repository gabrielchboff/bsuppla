use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn score(self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: String,
    pub path: PathBuf,
    pub detail: String,
    pub severity: Severity,
}

impl Finding {
    pub fn new(kind: &'static str, path: PathBuf, detail: String, severity: Severity) -> Self {
        Self {
            kind: kind.to_string(),
            path,
            detail,
            severity,
        }
    }

    pub fn key(&self) -> String {
        format!("{}: {}", self.kind, self.path.display())
    }
}

#[derive(Debug, Clone)]
pub struct FileContext<'a> {
    pub path: &'a PathBuf,
    pub relative_path: &'a PathBuf,
    pub mode: u32,
    pub is_executable: bool,
    pub is_world_writable: bool,
    pub is_world_readable: bool,
    pub is_suid: bool,
    pub is_sgid: bool,
}

impl<'a> FileContext<'a> {
    pub fn normalized_path(&self) -> String {
        let s = self.relative_path.to_string_lossy();
        if s.starts_with('/') {
            s.to_string()
        } else {
            format!("/{s}")
        }
    }

    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.relative_path.file_name()
    }

    pub fn file_name_str(&self) -> Option<String> {
        self.file_name().and_then(|n| n.to_str().map(String::from))
    }
}

pub trait Detector: Send + Sync {
    #[allow(dead_code)]
    fn name(&self) -> &'static str;
    fn detect(&self, ctx: &FileContext) -> Option<Finding>;
    fn severity(&self) -> Severity {
        Severity::Medium
    }
}

pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn detect(&self, ctx: &FileContext) -> Vec<Finding> {
        self.detectors
            .iter()
            .filter_map(|d| d.detect(ctx))
            .collect()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

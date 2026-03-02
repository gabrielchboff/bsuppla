use crate::detector::{Detector, FileContext, Finding, Severity};

pub struct SuidSgidDetector;

impl Detector for SuidSgidDetector {
    fn name(&self) -> &'static str {
        "suid_or_sgid_executable"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        if ctx.is_executable && (ctx.is_suid || ctx.is_sgid) {
            Some(Finding::new(
                "suid_or_sgid_executable",
                ctx.relative_path.clone(),
                format!("mode={:o}", ctx.mode),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

pub struct WorldWritableExecutableDetector;

impl Detector for WorldWritableExecutableDetector {
    fn name(&self) -> &'static str {
        "world_writable_executable"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        if ctx.is_executable && ctx.is_world_writable {
            Some(Finding::new(
                "world_writable_executable",
                ctx.relative_path.clone(),
                format!("mode={:o}", ctx.mode),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

pub struct ExecutableInWritableDirDetector;

const WRITABLE_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run"];

impl Detector for ExecutableInWritableDirDetector {
    fn name(&self) -> &'static str {
        "executable_in_writable_dir"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        if ctx.is_executable {
            let norm = ctx.normalized_path();
            if WRITABLE_DIRS.iter().any(|d| norm.starts_with(d)) {
                return Some(Finding::new(
                    "executable_in_writable_dir",
                    ctx.relative_path.clone(),
                    "writable dir".to_string(),
                    self.severity(),
                ));
            }
        }
        None
    }
}

pub struct HiddenExecutableDetector;

impl Detector for HiddenExecutableDetector {
    fn name(&self) -> &'static str {
        "hidden_executable"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        if ctx.is_executable {
            if let Some(name) = ctx.file_name_str() {
                if name.starts_with('.') {
                    return Some(Finding::new(
                        "hidden_executable",
                        ctx.relative_path.clone(),
                        "starts with '.'".to_string(),
                        self.severity(),
                    ));
                }
            }
        }
        None
    }
}

pub struct InsecureShadowPermissionsDetector;

impl Detector for InsecureShadowPermissionsDetector {
    fn name(&self) -> &'static str {
        "insecure_shadow_permissions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();
        if norm.ends_with("/etc/shadow") && (ctx.is_world_readable || ctx.is_world_writable) {
            Some(Finding::new(
                "insecure_shadow_permissions",
                ctx.relative_path.clone(),
                format!("mode={:o}", ctx.mode),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn suid_detector_finds_suid() {
        let detector = SuidSgidDetector;
        let path_buf = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o4755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: true,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "suid_or_sgid_executable");
    }

    #[test]
    fn suid_detector_finds_sgid() {
        let detector = SuidSgidDetector;
        let path_buf = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o2755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: true,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn suid_detector_ignores_non_suid() {
        let detector = SuidSgidDetector;
        let path_buf = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn world_writable_detector_finds_world_writable() {
        let detector = WorldWritableExecutableDetector;
        let path_buf = PathBuf::from("/tmp/script");
        let rel_path = PathBuf::from("/tmp/script");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o777,
            is_executable: true,
            is_world_writable: true,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "world_writable_executable");
    }

    #[test]
    fn world_writable_detector_ignores_non_world_writable() {
        let detector = WorldWritableExecutableDetector;
        let path_buf = PathBuf::from("/bin/script");
        let rel_path = PathBuf::from("/bin/script");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn writable_dir_detector_finds_in_tmp() {
        let detector = ExecutableInWritableDirDetector;
        let path_buf = PathBuf::from("/tmp/myscript");
        let rel_path = PathBuf::from("/tmp/myscript");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn writable_dir_detector_ignores_standard_paths() {
        let detector = ExecutableInWritableDirDetector;
        let path_buf = PathBuf::from("/bin/ls");
        let rel_path = PathBuf::from("/bin/ls");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn hidden_executable_detector_finds_dotfile() {
        let detector = HiddenExecutableDetector;
        let path_buf = PathBuf::from("/home/user/.hidden");
        let rel_path = PathBuf::from("/home/user/.hidden");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn hidden_executable_detector_ignores_normal_files() {
        let detector = HiddenExecutableDetector;
        let path_buf = PathBuf::from("/bin/ls");
        let rel_path = PathBuf::from("/bin/ls");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn shadow_detector_finds_insecure_shadow() {
        let detector = InsecureShadowPermissionsDetector;
        let path_buf = PathBuf::from("/etc/shadow");
        let rel_path = PathBuf::from("/etc/shadow");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: true,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "insecure_shadow_permissions");
    }

    #[test]
    fn shadow_detector_ignores_secure_shadow() {
        let detector = InsecureShadowPermissionsDetector;
        let path_buf = PathBuf::from("/etc/shadow");
        let rel_path = PathBuf::from("/etc/shadow");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o640,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn detector_severity_values() {
        assert_eq!(SuidSgidDetector.severity(), Severity::High);
        assert_eq!(WorldWritableExecutableDetector.severity(), Severity::High);
        assert_eq!(ExecutableInWritableDirDetector.severity(), Severity::Medium);
        assert_eq!(HiddenExecutableDetector.severity(), Severity::Low);
        assert_eq!(InsecureShadowPermissionsDetector.severity(), Severity::High);
    }
}

use crate::detector::{Detector, FileContext, Finding, Severity};

pub struct AuthorizedKeysDetector;

impl Detector for AuthorizedKeysDetector {
    fn name(&self) -> &'static str {
        "authorized_keys_present"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();
        if norm.ends_with("/.ssh/authorized_keys") {
            Some(Finding::new(
                "authorized_keys_present",
                ctx.relative_path.clone(),
                "ssh keys can allow access".to_string(),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

pub struct PrivateKeyDetector;

impl Detector for PrivateKeyDetector {
    fn name(&self) -> &'static str {
        "private_key_candidate"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();
        if !norm.contains("/.ssh/") {
            return None;
        }

        let name = ctx.file_name_str()?;
        let name_ref: &str = &name;
        if matches!(name_ref, "id_rsa" | "id_ed25519" | "id_dsa" | "id_ecdsa")
            || name.ends_with(".pem")
        {
            Some(Finding::new(
                "private_key_candidate",
                ctx.relative_path.clone(),
                "key material present".to_string(),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

pub struct CredentialFileDetector;

const CREDENTIAL_FILENAMES: &[&str] = &[
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "credentials",
    "config",
];

const CREDENTIAL_PATHS: &[&str] = &[
    ".docker/config.json",
    ".aws/credentials",
    ".aws/config",
    ".kube/config",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
];

impl Detector for CredentialFileDetector {
    fn name(&self) -> &'static str {
        "credential_file"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();
        let name = ctx.file_name_str()?;

        if name.starts_with(".env") {
            return Some(Finding::new(
                "credential_file",
                ctx.relative_path.clone(),
                "potential secrets".to_string(),
                self.severity(),
            ));
        }

        if CREDENTIAL_FILENAMES
            .iter()
            .any(|&n| name == n || name.starts_with(n))
        {
            if CREDENTIAL_PATHS.iter().any(|p| norm.contains(p)) {
                return Some(Finding::new(
                    "credential_file",
                    ctx.relative_path.clone(),
                    "potential secrets".to_string(),
                    self.severity(),
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn authorized_keys_detector_finds_authorized_keys() {
        let detector = AuthorizedKeysDetector;
        let path_buf = PathBuf::from("/root/.ssh/authorized_keys");
        let rel_path = PathBuf::from("/root/.ssh/authorized_keys");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "authorized_keys_present");
    }

    #[test]
    fn authorized_keys_detector_ignores_other_files() {
        let detector = AuthorizedKeysDetector;
        let path_buf = PathBuf::from("/root/.ssh/known_hosts");
        let rel_path = PathBuf::from("/root/.ssh/known_hosts");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
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
    fn private_key_detector_finds_id_rsa() {
        let detector = PrivateKeyDetector;
        let path_buf = PathBuf::from("/root/.ssh/id_rsa");
        let rel_path = PathBuf::from("/root/.ssh/id_rsa");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "private_key_candidate");
    }

    #[test]
    fn private_key_detector_finds_id_ed25519() {
        let detector = PrivateKeyDetector;
        let path_buf = PathBuf::from("/home/user/.ssh/id_ed25519");
        let rel_path = PathBuf::from("/home/user/.ssh/id_ed25519");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn private_key_detector_finds_pem_files() {
        let detector = PrivateKeyDetector;
        let path_buf = PathBuf::from("/home/user/.ssh/key.pem");
        let rel_path = PathBuf::from("/home/user/.ssh/key.pem");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn private_key_detector_ignores_non_ssh_paths() {
        let detector = PrivateKeyDetector;
        let path_buf = PathBuf::from("/etc/ssl/private/server.key");
        let rel_path = PathBuf::from("/etc/ssl/private/server.key");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
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
    fn credential_file_detector_finds_env() {
        let detector = CredentialFileDetector;
        let path_buf = PathBuf::from("/app/.env");
        let rel_path = PathBuf::from("/app/.env");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn credential_file_detector_finds_aws_credentials() {
        let detector = CredentialFileDetector;
        let path_buf = PathBuf::from("/root/.aws/credentials");
        let rel_path = PathBuf::from("/root/.aws/credentials");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn credential_file_detector_finds_docker_config() {
        let detector = CredentialFileDetector;
        let path_buf = PathBuf::from("/root/.docker/config.json");
        let rel_path = PathBuf::from("/root/.docker/config.json");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
            is_executable: false,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn credential_file_detector_ignores_unrelated_files() {
        let detector = CredentialFileDetector;
        let path_buf = PathBuf::from("/etc/passwd");
        let rel_path = PathBuf::from("/etc/passwd");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o644,
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
    fn credential_severity_is_critical() {
        assert_eq!(PrivateKeyDetector.severity(), Severity::Critical);
        assert_eq!(CredentialFileDetector.severity(), Severity::Critical);
        assert_eq!(AuthorizedKeysDetector.severity(), Severity::Medium);
    }
}

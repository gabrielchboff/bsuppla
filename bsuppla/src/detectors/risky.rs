use crate::detector::{Detector, FileContext, Finding, Severity};

pub struct RiskyToolDetector;

const RISKY_TOOLS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "strace", "tcpdump",
];

impl Detector for RiskyToolDetector {
    fn name(&self) -> &'static str {
        "risky_tool_present"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let name = ctx.file_name_str()?;

        if RISKY_TOOLS.iter().any(|&t| name == t) {
            Some(Finding::new(
                "risky_tool_present",
                ctx.relative_path.clone(),
                "known dual-use tool".to_string(),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

pub struct CryptoMinerDetector;

const MINER_NAMES: &[&str] = &[
    "xmrig",
    "xmr-stak",
    "minerd",
    "cgminer",
    "bfgminer",
    "kawpowminer",
    "cryptonight",
];

impl Detector for CryptoMinerDetector {
    fn name(&self) -> &'static str {
        "crypto_miner_candidate"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let name = ctx.file_name_str()?;

        if MINER_NAMES.iter().any(|&m| name == m) {
            Some(Finding::new(
                "crypto_miner_candidate",
                ctx.relative_path.clone(),
                "known miner name".to_string(),
                self.severity(),
            ))
        } else {
            None
        }
    }
}

pub struct StartupScriptDetector;

impl Detector for StartupScriptDetector {
    fn name(&self) -> &'static str {
        "startup_script_present"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn detect(&self, ctx: &FileContext) -> Option<Finding> {
        let norm = ctx.normalized_path();

        if norm.starts_with("/etc/init.d/")
            || norm.starts_with("/etc/rc")
            || norm.starts_with("/etc/cron.")
            || norm.starts_with("/etc/cron/")
            || norm.starts_with("/var/spool/cron")
            || norm == "/etc/crontab"
        {
            Some(Finding::new(
                "startup_script_present",
                ctx.relative_path.clone(),
                "init/rc/cron".to_string(),
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
    fn risky_tool_detector_finds_nc() {
        let detector = RiskyToolDetector;
        let path_buf = PathBuf::from("/usr/bin/nc");
        let rel_path = PathBuf::from("/usr/bin/nc");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "risky_tool_present");
    }

    #[test]
    fn risky_tool_detector_finds_tcpdump() {
        let detector = RiskyToolDetector;
        let path_buf = PathBuf::from("/usr/sbin/tcpdump");
        let rel_path = PathBuf::from("/usr/sbin/tcpdump");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn risky_tool_detector_ignores_normal_binaries() {
        let detector = RiskyToolDetector;
        let path_buf = PathBuf::from("/bin/ls");
        let rel_path = PathBuf::from("/bin/ls");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn crypto_miner_detector_finds_xmrig() {
        let detector = CryptoMinerDetector;
        let path_buf = PathBuf::from("/usr/bin/xmrig");
        let rel_path = PathBuf::from("/usr/bin/xmrig");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "crypto_miner_candidate");
    }

    #[test]
    fn crypto_miner_detector_finds_minerd() {
        let detector = CryptoMinerDetector;
        let path_buf = PathBuf::from("/usr/local/bin/minerd");
        let rel_path = PathBuf::from("/usr/local/bin/minerd");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn crypto_miner_detector_ignores_normal_binaries() {
        let detector = CryptoMinerDetector;
        let path_buf = PathBuf::from("/bin/bash");
        let rel_path = PathBuf::from("/bin/bash");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn startup_script_detector_finds_initd() {
        let detector = StartupScriptDetector;
        let path_buf = PathBuf::from("/etc/init.d/docker");
        let rel_path = PathBuf::from("/etc/init.d/docker");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, "startup_script_present");
    }

    #[test]
    fn startup_script_detector_finds_cron() {
        let detector = StartupScriptDetector;
        let path_buf = PathBuf::from("/var/spool/cron/root");
        let rel_path = PathBuf::from("/var/spool/cron/root");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn startup_script_detector_finds_crontab() {
        let detector = StartupScriptDetector;
        let path_buf = PathBuf::from("/etc/crontab");
        let rel_path = PathBuf::from("/etc/crontab");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn startup_script_detector_ignores_normal_files() {
        let detector = StartupScriptDetector;
        let path_buf = PathBuf::from("/etc/passwd");
        let rel_path = PathBuf::from("/etc/passwd");
        let ctx = FileContext {
            path: &path_buf,
            relative_path: &rel_path,
            mode: 0o755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: true,
            is_suid: false,
            is_sgid: false,
        };
        let result = detector.detect(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn risky_severity_values() {
        assert_eq!(CryptoMinerDetector.severity(), Severity::Critical);
        assert_eq!(RiskyToolDetector.severity(), Severity::Low);
        assert_eq!(StartupScriptDetector.severity(), Severity::Low);
    }
}

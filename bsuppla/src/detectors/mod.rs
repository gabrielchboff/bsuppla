pub mod credentials;
pub mod elf;
pub mod package_managers;
pub mod permissions;
pub mod risky;

use crate::detector::DetectorRegistry;

pub fn default_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    registry.register(Box::new(permissions::SuidSgidDetector));
    registry.register(Box::new(permissions::WorldWritableExecutableDetector));
    registry.register(Box::new(permissions::ExecutableInWritableDirDetector));
    registry.register(Box::new(permissions::HiddenExecutableDetector));
    registry.register(Box::new(permissions::InsecureShadowPermissionsDetector));

    registry.register(Box::new(elf::ElfAnalyzerDetector));

    registry.register(Box::new(credentials::AuthorizedKeysDetector));
    registry.register(Box::new(credentials::PrivateKeyDetector));
    registry.register(Box::new(credentials::CredentialFileDetector));

    registry.register(Box::new(package_managers::PackageManagerConfigDetector));
    registry.register(Box::new(package_managers::LockfileDetector));
    registry.register(Box::new(package_managers::ApkRepositoryDetector));
    registry.register(Box::new(package_managers::ApkKeyDetector));

    registry.register(Box::new(risky::RiskyToolDetector));
    registry.register(Box::new(risky::CryptoMinerDetector));
    registry.register(Box::new(risky::StartupScriptDetector));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Detector, FileContext};
    use std::path::PathBuf;

    #[test]
    fn default_registry_contains_all_detectors() {
        let registry = default_registry();
        let path_buf = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
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
        let findings = registry.detect(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn registry_detects_suid_file() {
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(permissions::SuidSgidDetector));
        
        let path = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
        let ctx = FileContext {
            path: &path,
            relative_path: &rel_path,
            mode: 0o4755,
            is_executable: true,
            is_world_writable: false,
            is_world_readable: false,
            is_suid: true,
            is_sgid: false,
        };
        
        let findings = registry.detect(&ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn registry_empty_returns_no_findings() {
        let registry = DetectorRegistry::new();
        let path_buf = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
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
        let findings = registry.detect(&ctx);
        assert!(findings.is_empty());
    }

    #[test]
    fn registry_multiple_detectors_collect_all() {
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(permissions::SuidSgidDetector));
        registry.register(Box::new(permissions::WorldWritableExecutableDetector));
        
        let path = PathBuf::from("/tmp/script");
        let rel_path = PathBuf::from("/tmp/script");
        let ctx = FileContext {
            path: &path,
            relative_path: &rel_path,
            mode: 0o4777,
            is_executable: true,
            is_world_writable: true,
            is_world_readable: true,
            is_suid: true,
            is_sgid: false,
        };
        
        let findings = registry.detect(&ctx);
        assert!(findings.len() >= 2);
    }

    #[test]
    fn detector_trait_object_safety() {
        let detector: Box<dyn Detector> = Box::new(permissions::SuidSgidDetector);
        let path_buf = PathBuf::from("/bin/test");
        let rel_path = PathBuf::from("/bin/test");
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
        let _result = detector.detect(&ctx);
    }
}

use std::fs::File;
use std::io::{Read, Result};
use std::path::Path;
use std::fs;

/// Entry point for filesystem scanning
pub fn scan_filesystem(root: &str) {
    println!("\n[+] Scanning filesystem for ELF binaries...\n");
    walk_dir(Path::new(root));
}

/// Recursively walk directories
fn walk_dir(path: &Path) {
    if path.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return, // skip unreadable dirs
        };

        for entry in entries {
            if let Ok(entry) = entry {
                walk_dir(&entry.path());
            }
        }
    } else if path.is_file() {
        if is_elf(path) {
            println!("[ELF] {}", path.display());
        } else {
            println!("[NO ELF] {}", path.display());
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

    return magic == [0x7f, b'E', b'L', b'F'];
}



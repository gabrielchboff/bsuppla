//! Docker daemon interaction: `docker pull` and `docker save`.

use std::process::Command;

use crate::error::{Error, Result};

/// Pull an image from a registry.
pub fn pull(image: &str) -> Result<()> {
    println!("[+] Image: {image}");
    println!("Make sure you have docker installed and running");

    let output = Command::new("docker")
        .args(["pull", image])
        .output()
        .map_err(|e| Error::Docker(format!("Failed to run docker pull: {e}")))?;

    if output.status.success() {
        println!("[+] Image pulled");
        Ok(())
    } else {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Docker(format!(
            "Docker pull failed (code {code}): {stderr}"
        )))
    }
}

/// Save an image to a tar file for offline analysis.
pub fn save(image: &str, tar: &str) -> Result<()> {
    println!("[+] Saving tar file");
    let output = Command::new("docker")
        .args(["save", image, "-o", tar])
        .output()
        .map_err(|e| Error::Docker(format!("Failed to run docker save: {e}")))?;

    if output.status.success() {
        println!("[+] Tar file saved");
        Ok(())
    } else {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::Docker(format!(
            "Docker save failed (code {code}): {stderr}"
        )))
    }
}

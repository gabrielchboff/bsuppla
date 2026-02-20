use std::process::Command;

use crate::error::{Result, err};

pub struct UI {
    image_name: String,
    tar_name: String,
}

impl UI {
    pub fn new(image: String, tar: String) -> UI {
        Self {
            image_name: image,
            tar_name: tar,
        }
    }

    pub fn get_image(&self) -> Result<()> {
        println!("[+] Image: {}", self.image_name);
        println!("Make sure you have docker installed and running");

        let pull_image = Command::new("docker")
            .args(["pull", &self.image_name])
            .output()
            .map_err(|e| err(format!("Failed to run docker pull: {e}")))?;

        if pull_image.status.success() {
            println!("[+] Image pulled");
            Ok(())
        } else {
            let code = pull_image.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&pull_image.stderr);
            Err(err(format!("Docker pull failed (code {code}): {stderr}")))
        }
    }

    pub fn save_tar(&self) -> Result<()> {
        println!("[+] Saving tar file");
        let save_tar = Command::new("docker")
            .args(["save", &self.image_name, "-o", &self.tar_name])
            .output()
            .map_err(|e| err(format!("Failed to run docker save: {e}")))?;
        if save_tar.status.success() {
            println!("[+] Tar file saved");
            Ok(())
        } else {
            let code = save_tar.status.code().unwrap_or(-1);
            let stderr = String::from_utf8_lossy(&save_tar.stderr);
            Err(err(format!("Docker save failed (code {code}): {stderr}")))
        }
    }
}

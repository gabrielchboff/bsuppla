use std::fs::File;
use std::io::Read;
use tar::Archive;

use crate::error::{Error, Result};

/// Extract manifest.json from a Docker image tar
pub fn read_manifest_from_image(image_path: &str) -> Result<String> {
    let file = File::open(image_path)?;

    let mut archive = Archive::new(file);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.as_ref() == std::path::Path::new("manifest.json") {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            return Ok(contents);
        }
    }

    Err(Error::Image("manifest.json not found in image".to_string()))
}

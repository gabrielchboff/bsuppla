use flate2::read::GzDecoder;
use std::fs::{self, File};
use tar::Archive;

use crate::error::{Result, err};

/// Apply Docker layers in order to reconstruct the filesystem
pub fn build_filesystem(image_path: &str, layers: &[String], output_dir: &str) -> Result<()> {
    if let Err(e) = fs::remove_dir_all(output_dir)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(e.into());
    }
    fs::create_dir_all(output_dir)?;

    for layer_path in layers {
        apply_layer(image_path, layer_path, output_dir)?;
    }
    Ok(())
}

fn apply_layer(image_path: &str, layer_path: &str, output_dir: &str) -> Result<()> {
    let file = File::open(image_path)?;

    let mut archive = Archive::new(file);

    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;

        if path.as_ref() == std::path::Path::new(layer_path) {
            let decoder = GzDecoder::new(entry);
            let mut layer_archive = Archive::new(decoder);

            layer_archive.unpack(output_dir)?;

            return Ok(());
        }
    }

    Err(err(format!(
        "Layer not found while extracting: {layer_path}"
    )))
}

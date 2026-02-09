use std::fs::{self, File};
use tar::Archive;
use flate2::read::GzDecoder;

/// Apply Docker layers in order to reconstruct the filesystem
pub fn build_filesystem(image_path: &str, layers: &[String], output_dir: &str) {
    let _ = fs::remove_dir_all(output_dir);
    fs::create_dir_all(output_dir)
        .expect("Failed to create filesystem directory");

    for layer_path in layers {
        apply_layer(image_path, layer_path, output_dir);
    }
}

fn apply_layer(image_path: &str, layer_path: &str, output_dir: &str) {
    let file = File::open(image_path)
        .expect("Failed to open image tar");

    let mut archive = Archive::new(file);

    for entry in archive.entries().expect("Failed to read tar entries") {
        let entry = entry.expect("Invalid tar entry");
        let path = entry.path().expect("Invalid entry path");

        if path.as_ref() == std::path::Path::new(layer_path) {
            let decoder = GzDecoder::new(entry);
            let mut layer_archive = Archive::new(decoder);

            layer_archive
                .unpack(output_dir)
                .expect("Failed to unpack gzip-compressed layer");

            return;
        }
    }

    panic!("Layer not found while extracting: {}", layer_path);
}


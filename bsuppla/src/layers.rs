use std::fs::File;
use tar::Archive;

/// Verify that all layers listed in the manifest exist in image.tar
pub fn locate_layers(image_path: &str, layer_paths: &[String]) -> Vec<String> {
    let file = File::open(image_path)
        .expect("Failed to open image tar");

    let mut archive = Archive::new(file);

    let mut found = Vec::new();

    for layer in layer_paths {
        let mut exists = false;

        for entry in archive.entries().expect("Failed to read tar entries") {
            let entry = entry.expect("Invalid tar entry");
            let path = entry.path().expect("Invalid entry path");

            if path.as_ref() == std::path::Path::new(layer) {
                exists = true;
                break;
            }
        }

        if !exists {
            panic!("Layer not found in image: {}", layer);
        }

        found.push(layer.clone());
    }

    return found;
}


use std::fs::File;
use std::io::Read;
use tar::Archive;

/// Extract manifest.json from a Docker image tar
pub fn read_manifest_from_image(image_path: &str) -> String {
    let file = File::open(image_path)
        .expect("Failed to open image tar");

    let mut archive = Archive::new(file);

    for entry in archive.entries().expect("Failed to read tar entries") {
        let mut entry = entry.expect("Invalid tar entry");
        let path = entry.path().expect("Invalid path");

        if path.as_ref() == std::path::Path::new("manifest.json") {
            let mut contents = String::new();
            entry
                .read_to_string(&mut contents)
                .expect("Failed to read manifest.json");
            return contents;
        }
    }

    panic!("manifest.json not found in image");
}




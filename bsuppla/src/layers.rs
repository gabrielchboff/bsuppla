use std::collections::HashSet;
use std::fs::File;
use tar::Archive;

use crate::error::{Result, err};

/// Verify that all layers listed in the manifest exist in image.tar
pub fn locate_layers(image_path: &str, layer_paths: &[String]) -> Result<Vec<String>> {
    let file = File::open(image_path)?;

    let mut archive = Archive::new(file);

    let mut available = HashSet::new();
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        if let Some(path_str) = path.to_str() {
            available.insert(path_str.to_string());
        }
    }

    for layer in layer_paths {
        if !available.contains(layer) {
            return Err(err(format!("Layer not found in image: {layer}")));
        }
    }

    Ok(layer_paths.to_vec())
}

#[cfg(test)]
mod tests {
    use super::locate_layers;
    use std::fs::{self, File};
    use std::io;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tar::Builder;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("bsuppla_{name}_{nanos}.tar"));
        path
    }

    fn write_tar(path: &PathBuf, files: &[&str]) {
        let file = File::create(path).unwrap();
        let mut builder = Builder::new(file);
        for name in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, io::empty())
                .unwrap();
        }
        builder.finish().unwrap();
    }

    #[test]
    fn finds_all_layers_in_tar() {
        let path = temp_path("layers_ok");
        write_tar(&path, &["layer1.tar", "layer2.tar"]);
        let layers = vec!["layer1.tar".to_string(), "layer2.tar".to_string()];
        let found = locate_layers(path.to_str().unwrap(), &layers).unwrap();
        assert_eq!(found, layers);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn errors_on_missing_layer() {
        let path = temp_path("layers_missing");
        write_tar(&path, &["layer1.tar"]);
        let layers = vec!["layer1.tar".to_string(), "layer2.tar".to_string()];
        let result = locate_layers(path.to_str().unwrap(), &layers);
        assert!(result.is_err());
        fs::remove_file(&path).ok();
    }
}

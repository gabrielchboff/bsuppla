use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ManifestEntry {
    pub Config: String,
    pub RepoTags: Option<Vec<String>>,
    pub Layers: Vec<String>,
}

pub fn parse_manifest(data: &str) -> Vec<ManifestEntry> {
    return serde_json::from_str(data).expect("Invalid manifest.json")
}





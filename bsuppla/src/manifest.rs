use serde::Deserialize;

use crate::error::Result;

#[derive(Debug, Deserialize)]
pub struct ManifestEntry {
    #[allow(dead_code)]
    #[serde(rename = "Config")]
    pub config: String,
    #[allow(dead_code)]
    #[serde(rename = "RepoTags")]
    pub repo_tags: Option<Vec<String>>,
    #[serde(rename = "Layers")]
    pub layers: Vec<String>,
}

pub fn parse_manifest(data: &str) -> Result<Vec<ManifestEntry>> {
    Ok(serde_json::from_str(data)?)
}

#[cfg(test)]
mod tests {
    use super::parse_manifest;

    #[test]
    fn parse_manifest_maps_fields() {
        let json = r#"[{"Config":"cfg.json","RepoTags":["repo:tag"],"Layers":["a","b"]}]"#;
        let entries = parse_manifest(json).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.config, "cfg.json");
        assert_eq!(
            entry.repo_tags.as_deref(),
            Some(&["repo:tag".to_string()][..])
        );
        assert_eq!(entry.layers, vec!["a".to_string(), "b".to_string()]);
    }
}

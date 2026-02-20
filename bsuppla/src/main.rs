mod error;
mod fs;
mod image;
mod layers;
mod manifest;
mod scanner;
mod ui;

use clap::Parser;
use error::Result;
use fs::build_filesystem;
use image::read_manifest_from_image;
use layers::locate_layers;
use manifest::parse_manifest;

#[derive(Parser, Debug)]
#[command(
    name = "bsuppla",
    version,
    about = "Static scanner for Docker images",
    arg_required_else_help = true
)]
struct Args {
    /// Docker image name (e.g., alpine:latest)
    image: String,
    /// Output tar path for docker save
    tar: String,
    /// Optional allowlist file (one path per line)
    allowlist: Option<String>,
    /// Optional baseline findings file (lines from previous scan)
    baseline: Option<String>,
    /// Write current findings to this baseline file
    #[arg(long)]
    baseline_out: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let image_name = args.image;
    let tar_path = args.tar;

    let ui = ui::UI::new(image_name, tar_path.clone());

    if !env_flag("BSUPPLA_SKIP_DOCKER") {
        ui.get_image()?;
        println!("[+] Image ready for scanning");

        ui.save_tar()?;
        println!("[+] Tar ready for scanning");
    }

    let manifest_json = read_manifest_from_image(&tar_path)?;
    let entries = parse_manifest(&manifest_json)?;
    let output_dir = std::env::var("BSUPPLA_OUTPUT_DIR").unwrap_or_else(|_| "container_fs".into());
    let output_display = if std::path::Path::new(&output_dir).is_absolute() {
        output_dir.clone()
    } else {
        format!("./{output_dir}")
    };

    for entry in entries {
        println!("Building filesystem...");

        let layers = locate_layers(&tar_path, &entry.layers)?;
        build_filesystem(&tar_path, &layers, &output_dir)?;

        println!("Filesystem ready at {output_display}");
        if !env_flag("BSUPPLA_SKIP_SCAN") {
            scanner::scan_filesystem(
                &output_dir,
                args.allowlist.as_deref(),
                args.baseline.as_deref(),
                args.baseline_out.as_deref(),
            )?;
        }
    }
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

mod manifest;
mod image;
mod layers;
mod fs;
mod scanner;
mod ui;

use manifest::parse_manifest;
use image::read_manifest_from_image;
use layers::locate_layers;
use fs::build_filesystem;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    

    if args.len() < 3 {
        eprintln!("Uso: {} <imagem> <arquivo.tar>", args[0]);
        return;
    }

    let bin_path = args.get(0).cloned().unwrap_or_default();
    let image_name = args.get(1).cloned().unwrap_or_default();

    let ui = ui::UI::new(image_name, bin_path);

    if ui.get_image() {
        println!("[+] Image ready for scanning");
    } else {
        println!("[+] Image failed to pull");
    }

    if ui.save_tar() {
        println!("[+] Tar ready for scanning");
    } else {
        println!("[+] Tar failed to save");
    }

    let manifest_json = read_manifest_from_image(&args[1]);
    let entries = parse_manifest(&manifest_json);

    for entry in entries {
        println!("Building filesystem...");

        let layers = locate_layers(&args[1], &entry.Layers);
        build_filesystem(&args[1], &layers, "container_fs");

        println!("Filesystem ready at ./container_fs");
        scanner::scan_filesystem("./container_fs");
    }
}

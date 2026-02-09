use std::process::Command;

pub struct UI {
    image_name: String,
    tar_name: String,
}

impl UI {
    pub fn new(image: String, tar: String) -> UI {
        Self {
            image_name: image,
            tar_name: tar
        }
    }

    pub fn get_image(&self) -> bool {

        let mut r = false;

        println!("[+] Image: {}", self.image_name);
        println!("Make sure you have docker installed and running");

        let pull_image = Command::new("docker")
            .args(["pull", &self.image_name])
            .output()
            .expect("Failed to pull image");
        
        if pull_image.status.success() {
            println!("[+] Image pulled");
            r = true;
        }
        return r;
    }

    pub fn save_tar(&self) -> bool {
        let mut r = false;
        println!("[+] Saving tar file");
        let save_tar = Command::new("docker")
            .args(["save", &self.image_name, "-o", &self.tar_name])
            .output()
            .expect("Failed to save tar");
        if save_tar.status.success() {
            println!("[+] Tar file saved");
            r = true;
        }

        return r;
    }

}

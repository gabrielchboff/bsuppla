use bsuppla::config::Config;
use bsuppla::error::Result;
use bsuppla::pipeline;

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = Config::from_args()?;
    pipeline::run(&config)
}

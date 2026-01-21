use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let args = lrzip_rust::cli::Args::parse();
    lrzip_rust::run(args)
}

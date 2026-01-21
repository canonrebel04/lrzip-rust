pub mod cli;
pub mod format;
pub mod pipeline;
pub mod rzip;

use anyhow::Result;

pub fn run(args: cli::Args) -> Result<()> {
    pipeline::execute(&args)
}

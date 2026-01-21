pub mod cli;
pub mod format;
pub mod pipeline;

use anyhow::Result;

pub fn run(args: cli::Args) -> Result<()> {
    pipeline::execute(&args)
}

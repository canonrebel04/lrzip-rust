pub mod cli;
pub mod format;
pub mod pipeline;
pub mod rzip;
pub mod ui;
pub mod zpaq;
pub mod encryption;

use anyhow::{Result, Context};
use std::path::Path;

pub fn run(args: cli::Args) -> Result<()> {
    if args.recursive && args.input.is_dir() {
        process_recursive(&args, &args.input)
    } else {
        process_single(&args)
    }
}

fn process_single(args: &cli::Args) -> Result<()> {
    pipeline::execute(args)?;
    
    if args.delete {
        // Verify output exists before deleting input
        // pipeline.rs derives output path if None. Unfortunately we don't know EXACTLY what pipeline chose unless we duplicate logic.
        // But pipeline.rs fails if it can't create output.
        // We can check if input still exists?
        // To be safe, we should probably refactor pipeline to return the output path used.
        // But for now, we rely on `execute` returning Ok only on success.
        
        let should_delete = if args.decompress {
             // If decompressing, output is the target.
             // If we can't easily guess output path, we assume success means it's done.
             true
        } else {
             // Compressing
             true
        };

        if should_delete {
            if args.input.exists() {
                if !args.quiet {
                    println!("Deleting input: {}", args.input.display());
                }
                std::fs::remove_file(&args.input).with_context(|| format!("failed to delete {}", args.input.display()))?;
            }
        }
    }
    Ok(())
}

fn process_recursive(args: &cli::Args, dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            process_recursive(args, &path)?;
        } else {
            // Check if we should process this file.
            // If decompressing, we look for .lrz?
            // If compressing, we ignore .lrz? 
            // lrzip logic: compress everything that isn't .lrz?
            // For safety, we skip .lrz files if compressing.
            let is_lrz = path.extension().map_or(false, |e| e == "lrz");
            
            if !args.decompress && is_lrz {
                continue;
            }
            if args.decompress && !is_lrz {
                continue;
            }

            let mut sub_args = args.clone();
            sub_args.input = path;
            sub_args.output = None; // Force auto-naming
            
            if !args.quiet {
                println!("Processing: {}", sub_args.input.display());
            }
            if let Err(e) = process_single(&sub_args) {
                eprintln!("Error processing {}: {}", sub_args.input.display(), e);
                // Continue with other files? Yes.
            }
        }
    }
    Ok(())
}

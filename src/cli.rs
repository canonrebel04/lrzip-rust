use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "lrzip-rust", version, about = "Rust rewrite of lrzip-next")]
pub struct Args {
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    #[arg(value_name = "OUTPUT", short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    #[arg(short = 'd', long = "decompress", default_value_t = false)]
    pub decompress: bool,

    #[arg(long = "backend", value_enum, default_value_t = Backend::Lzma)]
    pub backend: Backend,

    #[arg(short = 't', long = "threads")]
    pub threads: Option<usize>,

    #[arg(long = "no-mmap", default_value_t = false)]
    pub disable_mmap: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum Backend {
    Lzma,
    Gzip,
    Zstd,
}

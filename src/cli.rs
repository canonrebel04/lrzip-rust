use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[command(name = "lrzip-rust", version, about = "Rust rewrite of lrzip-next")]
pub struct Args {
    /// Input file to process
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output file path (defaults to <input>.lrz or <input>.out)
    #[arg(value_name = "OUTPUT", short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Decompress the input file
    #[arg(short = 'd', long = "decompress", default_value_t = false)]
    pub decompress: bool,

    /// Compression backend to use
    #[arg(long = "backend", value_enum, default_value_t = Backend::Lzma)]
    pub backend: Backend,

    /// Set Lzma compression (default)
    #[arg(long = "lzma", default_value_t = false, conflicts_with_all = ["gzip_flag", "zstd_flag", "zpaq_flag"])]
    pub lzma_flag: bool,
    
    /// Set Gzip compression
    #[arg(short = 'g', long = "gzip", default_value_t = false, conflicts_with_all = ["lzma_flag", "zstd_flag", "zpaq_flag"])]
    pub gzip_flag: bool,

    /// Set Zstd compression
    #[arg(short = 'Z', long = "zstd", default_value_t = false, conflicts_with_all = ["lzma_flag", "gzip_flag", "zpaq_flag"])]
    pub zstd_flag: bool,

    /// Set ZPAQ compression
    #[arg(short = 'z', long = "zpaq", default_value_t = false, conflicts_with_all = ["lzma_flag", "gzip_flag", "zstd_flag"])]
    pub zpaq_flag: bool,

    /// Set Bzip2 compression
    #[arg(short = 'b', long = "bzip2", default_value_t = false, conflicts_with_all = ["lzma_flag", "gzip_flag", "zstd_flag", "zpaq_flag", "lzo_flag"])]
    pub bzip2_flag: bool,

    /// Set LZO compression
    #[arg(short = 'l', long = "lzo", default_value_t = false, conflicts_with_all = ["lzma_flag", "gzip_flag", "zstd_flag", "zpaq_flag", "bzip2_flag"])]
    pub lzo_flag: bool,

    /// Number of threads to use (defaults to available logical cores)
    #[arg(short = 't', visible_short_alias = 'p', long = "threads")]
    pub threads: Option<usize>,

    /// Disable memory mapping (slower, but works on special files)
    #[arg(long = "no-mmap", default_value_t = false)]
    pub disable_mmap: bool,

    /// Show information about the compressed file
    #[arg(long = "info", short = 'i', default_value_t = false)]
    pub info: bool,

    /// Suppress all output except errors
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub quiet: bool,

    /// Set compression level (1-9)
    #[arg(short = 'L', long = "level", value_name = "LEVEL")]
    pub level: Option<u8>,

    /// Set window size in bytes (e.g. 100 or 100k or 100m)
    #[arg(short = 'w', long = "window", value_name = "WINDOW")]
    pub window: Option<String>,

    /// Force overwrite of any existing files
    #[arg(short = 'f', long = "force", default_value_t = false)]
    pub force: bool,
    
    /// Delete existing files after successful operation
    #[arg(short = 'D', long = "delete", default_value_t = false)]
    pub delete: bool,

    /// Recursively process directories
    #[arg(short = 'r', long = "recursive", default_value_t = false)]
    pub recursive: bool,

    /// Encrypt with password
    #[arg(short = 'e', long = "encrypt", value_name = "PASSWORD")]
    pub encrypt: Option<String>,

    /// Benchmark mode: perform compression but do not write to disk
    #[arg(long = "benchmark", default_value_t = false)]
    pub benchmark: bool,
}

impl Args {
    pub fn get_backend(&self) -> Backend {
        if self.lzma_flag {
            Backend::Lzma
        } else if self.gzip_flag {
            Backend::Gzip
        } else if self.zstd_flag {
            Backend::Zstd
        } else if self.zpaq_flag {
            Backend::Zpaq
        } else if self.bzip2_flag {
            Backend::Bzip2
        } else if self.lzo_flag {
            Backend::Lzo
        } else {
            self.backend
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Lzma,
    Gzip,
    Zstd,
    Zpaq,
    Bzip2,
    Bzip3,
    Lzo,
    None,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "lrzip-rust", version = "0.15.0", about = "High Performance Rust rewrite of lrzip-next v0.15.0")]
pub struct Args {
    /// Input file to process
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output file path (defaults to <input>.lrz or <input>.out)
    #[arg(value_name = "OUTPUT", short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Decompress the input file
    #[arg(short = 'd', long = "decompress", default_value_t = false)]
    pub decompress: bool,

    /// Compression backend to use
    #[arg(long = "backend", value_enum, default_value_t = Backend::Lzma)]
    pub backend: Backend,

    /// Set Lzma compression (default)
    #[arg(long = "lzma", default_value_t = false)]
    pub lzma_flag: bool,
    
    /// Set Gzip compression
    #[arg(short = 'g', long = "gzip", default_value_t = false)]
    pub gzip_flag: bool,

    /// Set Zstd compression
    #[arg(short = 'Z', long = "zstd", default_value_t = false)]
    pub zstd_flag: bool,

    /// Set ZPAQ compression
    #[arg(short = 'z', long = "zpaq", default_value_t = false)]
    pub zpaq_flag: bool,

    /// Set Bzip2 compression
    #[arg(short = 'b', long = "bzip2", default_value_t = false)]
    pub bzip2_flag: bool,

    /// Set Bzip3 compression
    #[arg(short = '3', long = "bzip3", default_value_t = false)]
    pub bzip3_flag: bool,

    /// Set LZO compression
    #[arg(short = 'l', long = "lzo", default_value_t = false)]
    pub lzo_flag: bool,

    /// No backend compression (rzip container only)
    #[arg(short = 'n', long = "no-compress", default_value_t = false)]
    pub no_compress_flag: bool,

    /// Enable DXT texture plane transposing preprocessing
    #[arg(long = "dxt", default_value_t = false)]
    pub dxt: bool,

    /// Enable Deflate stream recompression preprocessing
    #[arg(long = "deflate-pre", default_value_t = false)]
    pub deflate_pre: bool,

    /// Number of threads to use (defaults to available logical cores)
    #[arg(short = 't', visible_short_alias = 'p', long = "threads")]
    pub threads: Option<usize>,

    /// Disable memory mapping (slower, but works on special files)
    #[arg(long = "no-mmap", default_value_t = false)]
    pub disable_mmap: bool,

    /// Show information about the compressed file
    #[arg(long = "info", short = 'i', default_value_t = false)]
    pub info: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose", default_value_t = false)]
    pub verbose: bool,

    /// Suppress all output except errors
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    pub quiet: bool,

    /// Set compression level (1-9)
    #[arg(short = 'L', long = "level", value_name = "LEVEL")]
    pub level: Option<u8>,

    /// Set window size in bytes (e.g. 100 or 100k or 100m)
    #[arg(short = 'w', long = "window", value_name = "WINDOW")]
    pub window: Option<String>,

    /// Force overwrite of any existing files
    #[arg(short = 'f', long = "force", default_value_t = false)]
    pub force: bool,
    
    /// Delete existing files after successful operation
    #[arg(short = 'D', long = "delete", default_value_t = false)]
    pub delete: bool,

    /// Recursively process directories
    #[arg(short = 'r', long = "recursive", default_value_t = false)]
    pub recursive: bool,

    /// Encrypt with password
    #[arg(short = 'e', long = "encrypt", value_name = "PASSWORD")]
    pub encrypt: Option<String>,

    /// Passphrase file for encryption
    #[arg(short = 'P', long = "passfile", value_name = "PASSFILE")]
    pub passfile: Option<PathBuf>,

    /// Benchmark mode: perform compression but do not write to disk
    #[arg(long = "benchmark", default_value_t = false)]
    pub benchmark: bool,
}

impl Args {
    pub fn get_backend(&self) -> Backend {
        if self.lzma_flag {
            Backend::Lzma
        } else if self.gzip_flag {
            Backend::Gzip
        } else if self.zstd_flag {
            Backend::Zstd
        } else if self.zpaq_flag {
            Backend::Zpaq
        } else if self.bzip2_flag {
            Backend::Bzip2
        } else if self.bzip3_flag {
            Backend::Bzip3
        } else if self.lzo_flag {
            Backend::Lzo
        } else if self.no_compress_flag {
            Backend::None
        } else {
            self.backend
        }
    }
}


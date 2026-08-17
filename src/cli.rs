use std::path::PathBuf;
use clap::{Parser, ValueEnum};

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

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    None,
    /// x86 BCJ (E8/E9) branch converter — makes call/jmp targets
    /// position-independent so identical code sequences dedupe across the
    /// rzip long-range window. Best on PE/DLL/exe-heavy data.
    X86,
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

    /// Set compression level (1-9). Defaults to 7 (parity with C++ lrzip-next,
    /// whose default is level 7). With the zpaq backend, 1-5 map to the
    /// built-in libzpaq models and 6-9 expand to the level-5 model.
    #[arg(short = 'L', long = "level", value_name = "LEVEL")]
    pub level: Option<u8>,

    /// ZPAQ advanced method string passthrough (overrides -L for the zpaq backend).
    /// Level digits 1-5 are built-ins; 6-9 expand to the level-5 model.
    /// Example: --method "x6.2.12.0.7.27.1c0,0,511i2"
    #[arg(long = "method", value_name = "METHOD")]
    pub method: Option<String>,

    /// Per-chunk entropy-based level selection: literal streams at >= 7.6
    /// bits/byte drop to level 1, >= 7.0 to level 2 (near-incompressible
    /// data: L1 ≈ L3 ratio at ~6x the speed). The control stream always
    /// uses the requested level.
    #[arg(long = "auto-level")]
    pub auto_level: bool,

    /// ZPAQ block size in MiB (C++ lrzip's -zpaqbs, 2-2048): the literal
    /// stream is compressed as independent blocks of this size, so model
    /// sizes scale with it. Smaller = faster/less memory, larger = stronger.
    /// Default: one block per input chunk.
    #[arg(long = "zpaqbs", value_name = "MIB", default_value_t = 0)]
    pub zpaqbs: u32,

    /// Store a comment in the archive header (shown by --info).
    #[arg(short = 'C', long = "comment", value_name = "TEXT")]
    pub comment: Option<String>,

    /// Reversible pre-filter applied before the rzip stage.
    #[arg(long = "filter", value_enum, default_value_t = Filter::None)]
    pub filter: Filter,

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

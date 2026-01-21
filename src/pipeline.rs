use std::fs::File;

use anyhow::{bail, Context, Result};
use memmap2::Mmap;

use crate::cli::Args;
use crate::format::{
    parse_rcd_header, BackendProps, CompressionType, FilterSpec, HashKind, MagicHeader,
    MAGIC_LEN_V11,
};

enum InputData {
    Mmap(Mmap),
    Buffer(Vec<u8>),
}

impl InputData {
    fn as_slice(&self) -> &[u8] {
        match self {
            InputData::Mmap(map) => map,
            InputData::Buffer(buf) => buf,
        }
    }
}

pub fn execute(args: &Args) -> Result<()> {
    let data = if args.disable_mmap {
        let buf = std::fs::read(&args.input)
            .with_context(|| format!("read input file {}", args.input.display()))?;
        InputData::Buffer(buf)
    } else {
        let file = File::open(&args.input)
            .with_context(|| format!("open input file {}", args.input.display()))?;
        // SAFETY: File is not mutated while the mmap is alive; we only read from it.
        let map = unsafe { Mmap::map(&file).context("mmap input file")? };
        InputData::Mmap(map)
    };

    let bytes = data.as_slice();
    if bytes.len() < MAGIC_LEN_V11 {
        bail!("input too small for lrzip magic header");
    }

    let magic = MagicHeader::parse(&bytes[..MAGIC_LEN_V11])?;
    if magic.major != 0 || magic.minor < 11 {
        bail!("unsupported lrzip version {}.{}", magic.major, magic.minor);
    }

    let header_end = MAGIC_LEN_V11 + magic.comment_len as usize;
    if bytes.len() < header_end {
        bail!("input too small for magic header + comment");
    }

    let encrypted = magic.encryption.is_some();
    let (rcd, _consumed) = parse_rcd_header(bytes, header_end, encrypted, 2)?;

    if args.info {
        print_info(&magic, &rcd);
        return Ok(());
    }

    // TODO: Implement rzip preprocessing + backend compression pipeline.
    Ok(())
}

fn print_info(magic: &MagicHeader, rcd: &crate::format::RcdHeader) {
    println!("LRZIP-NEXT {}.{}", magic.major, magic.minor);
    match magic.expected_size {
        Some(size) => println!("Expected size: {}", size),
        None => println!("Expected size: encrypted"),
    }
    println!("Hash: {}", format_hash(magic.hash));
    println!("Filter: {}", format_filter(magic.filter));
    println!("Compression: {}", format_compression(magic.compression));
    println!("Backend props: {}", format_backend_props(magic.backend_props));
    println!(
        "Levels: rzip={} lrzip={}",
        magic.levels.rzip, magic.levels.lrzip
    );
    println!("Comment length: {}", magic.comment_len);
    println!(
        "Chunk bytes: {} (last chunk: {})",
        rcd.chunk_bytes, rcd.is_last_chunk
    );
    match rcd.chunk_size {
        Some(size) => println!("Chunk size: {}", size),
        None => println!("Chunk size: encrypted"),
    }
    println!("Streams: {}", rcd.streams.len());
    for (idx, stream) in rcd.streams.iter().enumerate() {
        println!("Stream {}:", idx);
        println!("  ctype: {}", stream.ctype);
        println!("  compressed_len: {}", stream.compressed_len);
        println!("  uncompressed_len: {}", stream.uncompressed_len);
        println!("  next_head: {}", stream.next_head);
        if stream.header_salt.is_some() {
            println!("  header_salt: present");
        }
    }
}

fn format_hash(hash: HashKind) -> &'static str {
    match hash {
        HashKind::Crc => "CRC",
        HashKind::Md5 => "MD5",
        HashKind::Ripemd => "RIPEMD",
        HashKind::Sha256 => "SHA256",
        HashKind::Sha384 => "SHA384",
        HashKind::Sha512 => "SHA512",
        HashKind::Sha3_256 => "SHA3-256",
        HashKind::Sha3_512 => "SHA3-512",
        HashKind::Shake128_16 => "SHAKE128-16",
        HashKind::Shake128_32 => "SHAKE128-32",
        HashKind::Shake128_64 => "SHAKE128-64",
        HashKind::Shake256_16 => "SHAKE256-16",
        HashKind::Shake256_32 => "SHAKE256-32",
        HashKind::Shake256_64 => "SHAKE256-64",
        HashKind::Unknown(_) => "Unknown",
    }
}

fn format_filter(filter: FilterSpec) -> String {
    match filter {
        FilterSpec::None => "none".to_string(),
        FilterSpec::Delta { offset } => format!("delta(offset={})", offset),
        FilterSpec::Bcj(kind) => format!("bcj({:?})", kind),
        FilterSpec::Unknown(value) => format!("unknown({})", value),
    }
}

fn format_compression(comp: CompressionType) -> String {
    match comp {
        CompressionType::None => "none".to_string(),
        CompressionType::Lzma => "lzma".to_string(),
        CompressionType::Zpaq => "zpaq".to_string(),
        CompressionType::Bzip3 => "bzip3".to_string(),
        CompressionType::Zstd { strategy } => format!("zstd(strategy={})", strategy),
        CompressionType::Unknown(value) => format!("unknown({})", value),
    }
}

fn format_backend_props(props: BackendProps) -> String {
    match props {
        BackendProps::None => "none".to_string(),
        BackendProps::Lzma { dict_prop } => format!("lzma(dict_prop={})", dict_prop),
        BackendProps::Zpaq { level, block_size } => {
            format!("zpaq(level={}, block={})", level, block_size)
        }
        BackendProps::Bzip3 { block_size_code } => {
            format!("bzip3(block={})", block_size_code)
        }
        BackendProps::Zstd { level } => format!("zstd(level={})", level),
    }
}

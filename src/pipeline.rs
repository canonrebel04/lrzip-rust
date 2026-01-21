use std::fs::File;

use anyhow::{bail, Context, Result};
use memmap2::Mmap;

use crate::cli::Args;
use crate::format::{parse_rcd_header, MagicHeader, MAGIC_LEN_V11};

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
    let _rcd = parse_rcd_header(bytes, header_end, encrypted, 2)?;

    // TODO: Implement rzip preprocessing + backend compression pipeline.
    Ok(())
}

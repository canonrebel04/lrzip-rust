use std::fs::File;
use std::io::Write;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use crc32fast::Hasher;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;

use crate::cli::{Args, Backend};
use crate::format::{
    parse_rcd_header, BackendProps, CompressionLevels, CompressionType, FilterSpec, HashKind,
    IntegrityLayout, MagicHeader, MAGIC_LEN_V11, EncryptionInfo, EncryptionCode,
};
use crate::encryption::EncryptionEngine;
use crate::ui;
use rand::{Rng, rng};

const PB_STYLE: &str = "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})";
const PB_CHARS: &str = "█▆▄ ";


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
    if !args.decompress && !args.info {
        return compress(args);
    }

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

    if args.decompress {
        return decompress(args);
    }

    Ok(())
}

pub fn decompress(args: &Args) -> Result<()> {
    let input_data = if args.disable_mmap {
        let buf = std::fs::read(&args.input)
            .with_context(|| format!("read input file {}", args.input.display()))?;
        InputData::Buffer(buf)
    } else {
        let file = File::open(&args.input)
            .with_context(|| format!("open input file {}", args.input.display()))?;
        let map = unsafe { Mmap::map(&file).context("mmap input file")? };
        InputData::Mmap(map)
    };

    let bytes = input_data.as_slice();
    if bytes.len() < MAGIC_LEN_V11 {
        bail!("input too small for lrzip magic header");
    }

    let magic = MagicHeader::parse(&bytes[..MAGIC_LEN_V11])?;
    let header_end = MAGIC_LEN_V11 + magic.comment_len as usize;

    let encrypted = magic.encryption.is_some();
    if encrypted && args.encrypt.is_none() {
        bail!("file is encrypted, password required (use --encrypt)");
    }

    let output_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        if p.extension().map_or(false, |ext| ext == "lrz") {
            p.set_extension("");
        } else {
            p.set_extension("out");
        }
        p
    });

    let start_time = Instant::now();
    let mut out_file = File::create(&output_path)
        .with_context(|| format!("create output file {}", output_path.display()))?;

    let mut md5_ctx = if magic.hash == HashKind::Md5 {
        Some(md5::Context::new())
    } else {
        None
    };

    let mut cursor = header_end;
    let pb = if let Some(size) = magic.expected_size {
        if !args.quiet {
            let pb = ProgressBar::new(size);
            pb.set_style(ProgressStyle::default_bar()
                .template(PB_STYLE)
                .unwrap()
                .progress_chars(PB_CHARS));
            Some(pb)
        } else {
            None
        }
    } else {
        None
    };

    while cursor < bytes.len() {
        let (rcd, consumed) = parse_rcd_header(bytes, cursor, encrypted, 2)?;
        let rzip_chunk_data = decompress_chunk(&rcd, bytes, cursor, encrypted, args.encrypt.as_deref())?;
        out_file.write_all(&rzip_chunk_data)?;
        
        if let Some(ctx) = &mut md5_ctx {
            ctx.consume(&rzip_chunk_data);
        }

        if let Some(ref pb) = pb {
            pb.inc(rzip_chunk_data.len() as u64);
        }
        
        // Advance cursor to next RCD.
        let stream_header_start_rel = 2 + rcd.chunk_bytes as usize;
        let mut max_chunk_offset = consumed;
        for i in 0..rcd.streams.len() {
            let blocks = crate::format::walk_stream_blocks(bytes, cursor, i, rcd.streams.len(), encrypted, 1000)?;
            for (rel, block) in blocks {
                let header_len = crate::format::stream_header_len(rcd.chunk_bytes, encrypted)?;
                // rel is relative to stream_header_start.
                // max_chunk_offset is relative to cursor.
                let end = stream_header_start_rel + (rel as usize) + header_len + block.compressed_len as usize;
                if end > max_chunk_offset {
                    max_chunk_offset = end;
                }
            }
        }
        
        cursor += max_chunk_offset;

        if rcd.is_last_chunk {
            break;
        }
    }
    
    if let Some(pb) = pb {
        pb.finish_with_message("Decompression complete");
    }

    let integrity = IntegrityLayout::from_hash(magic.hash);
    if let Some(len) = integrity.file_hash_len {
        if cursor + len > bytes.len() {
             eprintln!("Warning: incomplete file for {} hash verification", format_hash(magic.hash));
        } else {
            let stored_hash = &bytes[cursor..cursor+len];
            
            if let Some(ctx) = md5_ctx {
                let digest = ctx.finalize();
                if digest.0 != stored_hash {
                     bail!("MD5 mismatch: expected {:02x?}, calculated {:02x?}", stored_hash, digest.0);
                }
            } else if magic.hash != HashKind::Crc && magic.hash != HashKind::Unknown(0) {
                 eprintln!("Warning: Verification for hash {} not supported yet", format_hash(magic.hash));
            }
        }
    }

    if !args.quiet {
        let final_size = out_file.metadata().map(|m| m.len()).unwrap_or(0);
        
        ui::print_summary(
            final_size, // Output size is the "Original" equivalent (decompressed)
            bytes.len() as u64, // Input size is "Compressed"
            start_time.elapsed(),
            "Decompression"
        );
    }

    Ok(())
}

fn decompress_chunk(
    rcd: &crate::format::RcdHeader,
    bytes: &[u8],
    rcd_offset: usize,
    encrypted: bool,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let mut streams_data = Vec::new();
    let stream_header_start = rcd_offset + 2 + if encrypted { 0 } else { rcd.chunk_bytes as usize };
    
    for i in 0..rcd.streams.len() {
        let blocks = crate::format::walk_stream_blocks(bytes, rcd_offset, i, rcd.streams.len(), encrypted, 1000)?;
        let mut stream_buf = Vec::new();
        for (rel_offset, block) in blocks {
            let chunk_bytes = rcd.chunk_bytes;
            // initial_pos in walk_stream_blocks was relative to stream_header_start
            // so absolute pos = stream_header_start + rel_offset + header_len
            let header_len = crate::format::stream_header_len(chunk_bytes, encrypted)?;
            
            let data_start = stream_header_start + rel_offset as usize + header_len;
            let data_end = data_start + block.compressed_len as usize;
            let compressed_raw = &bytes[data_start..data_end];
            
            let decrypted_buf;
            let compressed_data = if encrypted {
                if block.compressed_len == 0 {
                    decrypted_buf = Vec::new();
                    &decrypted_buf
                } else {
                    // Header salt for block is in block.header_salt
                    let salt = block.header_salt.as_ref().context("encrypted block missing salt")?;
                    let engine = EncryptionEngine::new(password.context("password required")?, salt);
                    decrypted_buf = engine.decrypt(compressed_raw)?;
                    &decrypted_buf
                }
            } else {
                compressed_raw
            };
            
            if block.compressed_len > 0 {
                let decompressed = match block.ctype {
                    crate::format::CTYPE_NONE => compressed_data.to_vec(),
                    crate::format::CTYPE_ZSTD => {
                        zstd::decode_all(compressed_data)?
                    }
                    crate::format::CTYPE_LZMA => {
                        use xz2::stream::{Stream, Action, Status};
                        
                        // Construct legacy .lzma header to make xz2's new_lzma_decoder happy.
                        // Header = [Properties (1 byte)] + [Dict Size (4 bytes)] + [Uncompressed Size (8 bytes)]
                        // Properties: lc=3, lp=0, pb=2 => 0x5d.
                        // Dict Size: 32MB => 0x02000000 (LE) => 00 00 00 02.
                        // Uncompressed Size: Unknown => -1 (LE) => FF...FF.
                        
                        let mut input_with_header = Vec::with_capacity(13 + compressed_data.len());
                        input_with_header.push(0x5d);
                        input_with_header.extend_from_slice(&33_554_432u32.to_le_bytes()); 
                        input_with_header.extend_from_slice(&u64::MAX.to_le_bytes());
                        input_with_header.extend_from_slice(compressed_data);

                        let mut stream = Stream::new_lzma_decoder(u64::MAX).map_err(|e| anyhow::anyhow!(e))?;
                        
                        let mut out = Vec::new();
                        let mut output_buf = [0u8; 32 * 1024];
                        let mut total_read = 0;
                        
                        loop {
                            let input_chunk = &input_with_header[total_read..];
                            let previous_out = stream.total_out();
                            let status = stream.process(input_chunk, &mut output_buf, Action::Run)
                                .map_err(|e| anyhow::anyhow!(e))?;
                            
                            let consumed = (stream.total_in() as usize) - total_read;
                            total_read += consumed;
                            
                            let produced = (stream.total_out() - previous_out) as usize;
                            out.extend_from_slice(&output_buf[..produced]);
                            
                            if status == Status::StreamEnd {
                                break;
                            }
                            if consumed == 0 && produced == 0 {
                                // If input exhausted but not finished
                                if total_read == input_with_header.len() {
                                     break; 
                                }
                                bail!("LZMA decoder stalled");
                            }
                        }
                        out
                    }
                    crate::format::CTYPE_GZIP => {
                        let mut decoder = flate2::read::GzDecoder::new(compressed_data);
                        let mut out = Vec::new();
                        std::io::Read::read_to_end(&mut decoder, &mut out)?;
                        out
                    }
                    crate::format::CTYPE_ZPAQ => {
                        crate::zpaq::decompress(compressed_data, block.uncompressed_len as usize, None, std::ptr::null_mut())
                    }
                    crate::format::CTYPE_BZIP2 => {
                        let mut decoder = bzip2::read::BzDecoder::new(compressed_data);
                        let mut out = Vec::new();
                        std::io::Read::read_to_end(&mut decoder, &mut out)?;
                        out
                    }
                    crate::format::CTYPE_LZO => {
                        let mut lzo = minilzo_rs::LZO::init().map_err(|e| anyhow::anyhow!("lzo init error: {:?}", e))?;
                        lzo.decompress(compressed_data, block.uncompressed_len as usize)
                            .map_err(|e| anyhow::anyhow!("lzo error: {:?}", e))?
                    }
                    other => bail!("unsupported block ctype {}", other),
                };
                stream_buf.extend_from_slice(&decompressed);
            }
        }
        streams_data.push(stream_buf);
    }

    if streams_data.len() < 2 {
        bail!("expected at least 2 streams in rzip chunk");
    }

    let control_stream = &streams_data[0];
    let literal_stream = &streams_data[1];

    let mut out = Vec::new();
    let mut hasher = Hasher::new();
    let mut ctrl_cursor = 0;
    let mut lit_cursor = 0;

    while ctrl_cursor < control_stream.len() {
        let t = control_stream[ctrl_cursor];
        ctrl_cursor += 1;
        
        let len = u16::from_le_bytes([control_stream[ctrl_cursor], control_stream[ctrl_cursor + 1]]) as usize;
        ctrl_cursor += 2;
        
        if t == 0 {
            // Literal
            if len == 0 {
                // End of chunk, verify CRC
                if ctrl_cursor + 4 > control_stream.len() {
                    bail!("incomplete control stream for CRC32");
                }
                let expected_crc = u32::from_be_bytes([
                    control_stream[ctrl_cursor],
                    control_stream[ctrl_cursor+1],
                    control_stream[ctrl_cursor+2],
                    control_stream[ctrl_cursor+3]
                ]);
                let _ = ctrl_cursor; // Suppress unused assignment before break
                
                if hasher.clone().finalize() != expected_crc {
                    bail!("CRC32 mismatch: expected 0x{:08x}, calculated 0x{:08x}", expected_crc, hasher.finalize());
                }
                break;
            }

            let end = lit_cursor + len;
            if end > literal_stream.len() {
                bail!("literal stream underflow: need {} bytes, have {}", len, literal_stream.len() - lit_cursor);
            }
            let slice = &literal_stream[lit_cursor..end];
            out.extend_from_slice(slice);
            hasher.update(slice);
            lit_cursor = end;
        } else if t == 1 {
            // Match
            let chunk_bytes = rcd.chunk_bytes as usize;
            let mut offset_bytes = [0u8; 8];
            offset_bytes[..chunk_bytes].copy_from_slice(&control_stream[ctrl_cursor..ctrl_cursor + chunk_bytes]);
            ctrl_cursor += chunk_bytes;
            let offset = u64::from_le_bytes(offset_bytes) as usize;
            
            let current_pos = out.len();
            if offset > current_pos {
                bail!("match offset {} beyond current position {}", offset, current_pos);
            }
            
            let start = current_pos - offset;
            for i in 0..len {
                let val = out[start + i];
                out.push(val);
                hasher.update(&[val]);
            }
        } else {
            bail!("unknown rzip control type {}", t);
        }
    }

    Ok(out)
}



pub fn compress(args: &Args) -> Result<()> {
    let start_time = Instant::now();
    let input_data = if args.disable_mmap {
        let buf = std::fs::read(&args.input)
            .with_context(|| format!("read input file {}", args.input.display()))?;
        InputData::Buffer(buf)
    } else {
        let file = File::open(&args.input)
            .with_context(|| format!("open input file {}", args.input.display()))?;
        let map = unsafe { Mmap::map(&file).context("mmap input file")? };
        InputData::Mmap(map)
    };

    let bytes = input_data.as_slice();
    let total_size = bytes.len() as u64;

    let output_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        p.set_extension("lrz");
        p
    });

    let mut out_file = File::create(&output_path)
        .with_context(|| format!("create output file {}", output_path.display()))?;

    // Parse window size
    let window_size = if let Some(w_str) = &args.window {
        crate::ui::parse_size(w_str).ok_or_else(|| anyhow::anyhow!("invalid window size"))?
    } else {
        100 * 1024 * 1024 // Default 100MB
    };

    // Prepare Magic Header
    let magic = MagicHeader {
        major: 0,
        minor: 14,
        expected_size: Some(total_size),
        encryption: if let Some(_password) = &args.encrypt {
             let mut salt = [0u8; 8];
             rng().fill(&mut salt);
             Some(EncryptionInfo {
                 code: EncryptionCode::Aes128,
                 salt,
             })
        } else {
            None
        },
        hash: HashKind::Md5,
        filter: FilterSpec::None,
        compression: match args.get_backend() {
            Backend::Lzma => CompressionType::Lzma,
            Backend::Gzip => CompressionType::Unknown(7), // Map Gzip
            Backend::Zstd => CompressionType::Zstd { strategy: 0 },
            Backend::Zpaq => CompressionType::Zpaq,
            Backend::Bzip2 => CompressionType::Bzip2,
            Backend::Lzo => CompressionType::Lzo,
        },
        backend_props: match args.get_backend() {
            Backend::Lzma => BackendProps::Lzma { dict_prop: 0x2d },
            Backend::Gzip => BackendProps::Zstd { level: 3 },
            Backend::Zstd => BackendProps::Zstd { level: 3 },
            Backend::Zpaq => BackendProps::Zpaq { level: args.level.unwrap_or(3), block_size: 0 },
            Backend::Bzip2 => BackendProps::Bzip2 { block_size_code: 9 }, // Default block 9
            Backend::Lzo => BackendProps::None, // No specific props for LZO usually stored? Or None.
        },
        levels: CompressionLevels { rzip: 7, lrzip: 7 },
        comment_len: 0,
    };

    if !args.benchmark {
        out_file.write_all(&magic.write())?;
    }

    // rzip configuration
    let rzip_config = crate::rzip::RzipConfig {
        max_chunk: window_size as u64,
        max_mmap: window_size as u64,
        window: window_size as u64,
        page_size: 4096,
        level: 7,
    };

    let chunk_map = crate::rzip::build_chunk_map(total_size, rzip_config);
    
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));
    
    use rayon::prelude::*;

    let chunk_results: Result<Vec<Vec<u8>>> = chunk_map.chunks.par_iter().map(|chunk| {
        let mut chunk_out = Vec::new();
        let hasher = crate::rzip::RollingHash::new();
        let mut table = crate::rzip::HashTable::new(rzip_config.level);
        compress_chunk_to_buffer(bytes, chunk, &rzip_config, &mut chunk_out, args, &hasher, &mut table)?;
        pb.inc(chunk.size);
        Ok(chunk_out)
    }).collect();

    pb.finish_with_message("Compression complete");

    if !args.benchmark {
        for chunk_data in chunk_results? {
            out_file.write_all(&chunk_data)?;
        }

        // Compute and write MD5 hash
        let digest = md5::compute(bytes);
        out_file.write_all(&digest.0)?;
    } else {
        // Just consume results to ensure errors are propagated
        for _ in chunk_results? {}
    }

    if !args.quiet {
        let final_size = out_file.metadata().map(|m| m.len()).unwrap_or(0);
        
        ui::print_summary(
            bytes.len() as u64,
            final_size,
            start_time.elapsed(),
            "Compression"
        );
    }

    Ok(())
}

fn compress_chunk_to_buffer(
    full_data: &[u8],
    chunk_spec: &crate::rzip::ChunkSpec,
    config: &crate::rzip::RzipConfig,
    out: &mut Vec<u8>,
    args: &Args,
    hasher: &crate::rzip::RollingHash,
    table: &mut crate::rzip::HashTable,
) -> Result<()> {
    use crate::rzip::{compress_chunk, RzipControl};
    use crate::format::write_var_le;

    let start = chunk_spec.offset as usize;
    let end = (chunk_spec.offset + chunk_spec.size) as usize;
    let chunk_data = &full_data[start..end];
    
    let mut crc_hasher = Hasher::new();
    crc_hasher.update(chunk_data);
    let chunk_crc = crc_hasher.finalize();

    let mut control_stream = Vec::new();
    let mut literal_stream = Vec::new();

    // Re-calculating chunk_bytes properly
    let mut bits = 8u64;
    while chunk_spec.size >> bits > 0 {
        bits += 8;
    }
    let chunk_bytes = (bits / 8) as u8 + if bits % 8 != 0 { 1 } else { 0 };

    let mut current_lit_pos = 0;
    let _stats = compress_chunk(chunk_data, config.level, hasher, table, |ctrl| {
        match ctrl {
            RzipControl::Literal { mut len } => {
                while len > 0 {
                    let cur_len = len.min(0xFFFF);
                    // println!("LIT len={}", cur_len);
                    control_stream.push(0u8);
                    control_stream.extend_from_slice(&(cur_len as u16).to_le_bytes());
                    literal_stream.extend_from_slice(&chunk_data[current_lit_pos..current_lit_pos + cur_len as usize]);
                    current_lit_pos += cur_len as usize;
                    len -= cur_len;
                }
            }
            RzipControl::Match { mut len, mut offset } => {
                while len > 0 {
                    let cur_len = len.min(0xFFFF);
                    // println!("MATCH len={} offset={}", cur_len, offset);
                    control_stream.push(1u8);
                    control_stream.extend_from_slice(&(cur_len as u16).to_le_bytes());
                    let rel_offset = (current_lit_pos as u64) - offset;
                    control_stream.extend_from_slice(&write_var_le(rel_offset, chunk_bytes as usize));
                    current_lit_pos += cur_len as usize;
                    len -= cur_len;
                    offset += cur_len as u64;
                }
            }
        }

    });

    // Write End-Of-Chunk (Literal Length 0) and CRC32
    control_stream.push(0u8);
    control_stream.extend_from_slice(&0u16.to_le_bytes());
    control_stream.extend_from_slice(&chunk_crc.to_be_bytes());

    let s0_ctype = match args.get_backend() {
        Backend::Zstd => crate::format::CTYPE_ZSTD,
        Backend::Lzma => crate::format::CTYPE_LZMA,
        Backend::Gzip => crate::format::CTYPE_GZIP,
        Backend::Zpaq => crate::format::CTYPE_ZPAQ,
        Backend::Bzip2 => crate::format::CTYPE_BZIP2,
        Backend::Lzo => crate::format::CTYPE_LZO,
    };
    let s1_ctype = match args.get_backend() {
        Backend::Zstd => crate::format::CTYPE_ZSTD,
        Backend::Lzma => crate::format::CTYPE_LZMA,
        Backend::Gzip => crate::format::CTYPE_GZIP,
        Backend::Zpaq => crate::format::CTYPE_ZPAQ,
        Backend::Bzip2 => crate::format::CTYPE_BZIP2,
        Backend::Lzo => crate::format::CTYPE_LZO,
    };

    let control_compressed = match args.get_backend() {
        Backend::Zstd => zstd::encode_all(&control_stream[..], 3)?,
        Backend::Lzma => {
            use xz2::stream::{LzmaOptions, Stream};
            use xz2::write::XzEncoder;

            let mut opts = LzmaOptions::new_preset(7).unwrap();
            opts.dict_size(32 * 1024 * 1024);
            
            let stream = Stream::new_lzma_encoder(&opts)?;
            let mut out = Vec::new();
            {
                let mut encoder = XzEncoder::new_stream(&mut out, stream);
                encoder.write_all(&control_stream)?;
                encoder.finish()?;
            }
            
            // Strip 13 byte header
            if out.len() < 13 {
                 bail!("lzma compression produced invalid size");
            }
            out[13..].to_vec()
        }
        Backend::Gzip => {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&control_stream)?;
            encoder.finish()?
        }
        Backend::Zpaq => {
            crate::zpaq::compress(&control_stream, args.level.unwrap_or(3), None, std::ptr::null_mut())
        }
        Backend::Bzip2 => {
            let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
            encoder.write_all(&control_stream)?;
            encoder.finish()?
        }
        Backend::Lzo => {
            let mut lzo = minilzo_rs::LZO::init().map_err(|e| anyhow::anyhow!("lzo init error: {:?}", e))?;
            lzo.compress(&control_stream).map_err(|e| anyhow::anyhow!("lzo error: {:?}", e))?
        }
    };
    let literal_compressed = match args.get_backend() {
        Backend::Zstd => zstd::encode_all(&literal_stream[..], 3)?,
        Backend::Lzma => {
            use xz2::stream::{LzmaOptions, Stream};
            use xz2::write::XzEncoder;

            let mut opts = LzmaOptions::new_preset(7).unwrap();
            opts.dict_size(32 * 1024 * 1024);
            
            let stream = Stream::new_lzma_encoder(&opts)?;
            let mut out = Vec::new();
            {
                let mut encoder = XzEncoder::new_stream(&mut out, stream);
                encoder.write_all(&literal_stream)?;
                encoder.finish()?;
            }
            
            // Strip 13 byte header
            if out.len() < 13 {
                 bail!("lzma compression produced invalid size");
            }
            out[13..].to_vec()
        }
        Backend::Gzip => {
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&literal_stream)?;
            encoder.finish()?
        }
        Backend::Zpaq => {
            crate::zpaq::compress(&literal_stream, args.level.unwrap_or(3), None, std::ptr::null_mut())
        }
        Backend::Bzip2 => {
            let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
            encoder.write_all(&literal_stream)?;
            encoder.finish()?
        }
        Backend::Lzo => {
            let mut lzo = minilzo_rs::LZO::init().map_err(|e| anyhow::anyhow!("lzo init error: {:?}", e))?;
            lzo.compress(&literal_stream).map_err(|e| anyhow::anyhow!("lzo error: {:?}", e))?
        }
    };

    let mut control_compressed = control_compressed;
    let mut literal_compressed = literal_compressed;
    // s0_ctype/s1_ctype do not need modification for encryption wrapper

    // Encrypt if requested
    let mut control_salt = [0u8; 8];
    let mut literal_salt = [0u8; 8];
    let encrypted = args.encrypt.is_some();

    if let Some(password) = &args.encrypt {
        rng().fill(&mut control_salt);
        let engine = EncryptionEngine::new(password, &control_salt);
        control_compressed = engine.encrypt(&control_compressed)?;

        rng().fill(&mut literal_salt);
        let engine = EncryptionEngine::new(password, &literal_salt);
        literal_compressed = engine.encrypt(&literal_compressed)?;
        
        // Note: ctype in BlockHeader describes the COMPRESSION. Encryption is a wrapper.
        // The block header struct has `has_block_salt`.
        // We do NOT change ctype.
    }

    // Write RCD Header
    out.write_all(&[chunk_bytes])?;
    let is_last = (chunk_spec.offset + chunk_spec.size) >= full_data.len() as u64;
    out.write_all(&[if is_last { 1 } else { 0 }])?;
    
    // Chunk size (if encrypted, not written here in standard RCD?)
    // format.rs: let chunk_size = if encrypted { None } else { ... read var ... }
    // So if encrypted, we skip writing chunk size?
    if !encrypted {
         out.write_all(&write_var_le(chunk_spec.size, chunk_bytes as usize))?;
    } else {
         // Format says `if encrypted { None }`. Meaning 0 bytes read.
         // Effectively we skip writing it?
         // Check format.rs: `let chunk_size = if encrypted { None } else { ... }`.
         // Correct.
    }

    // Stream Headers (Stream 0: Control, Stream 1: Literal)
    let val_len = if encrypted { 8 } else { chunk_bytes as usize };
    // Header len = (Salt if enc) + 1 + 3 * val_len
    let header_len = (if encrypted { 8 } else { 0 }) + 1 + 3 * val_len;
    
    // Position calculations need to account for header size
    let first_block_0_pos = (2 * header_len) as u64;
    let first_block_1_pos = first_block_0_pos + header_len as u64 + control_compressed.len() as u64;

    // Helper to write fields
    let write_fields = |out: &mut Vec<u8>, salt: Option<&[u8]>, ctype: u8, c_len: u64, u_len: u64, next: u64| -> Result<()> {
         if let Some(s) = salt {
             out.write_all(s)?;
         }
         out.write_all(&[ctype])?;
         out.write_all(&write_var_le(c_len, val_len))?;
         out.write_all(&write_var_le(u_len, val_len))?;
         out.write_all(&write_var_le(next, val_len))?;
         Ok(())
    };

    // Stream 0 Initial Header (Salt needed if encrypted? Yes, StreamHeader has salt)
    let mut sh0_salt = [0u8; 8];
    let mut sh1_salt = [0u8; 8];
    if encrypted {
        rng().fill(&mut sh0_salt);
        rng().fill(&mut sh1_salt);
    }
    
    write_fields(&mut *out, if encrypted { Some(&sh0_salt) } else { None }, crate::format::CTYPE_NONE, 0, 0, first_block_0_pos)?;
    
    // Stream 1 Initial Header
    write_fields(&mut *out, if encrypted { Some(&sh1_salt) } else { None }, crate::format::CTYPE_NONE, 0, 0, first_block_1_pos)?;

    // Write Stream 0 Data Block
    write_fields(&mut *out, if encrypted { Some(&control_salt) } else { None }, s0_ctype, control_compressed.len() as u64, control_stream.len() as u64, 0)?;
    out.write_all(&control_compressed)?;

    // Write Stream 1 Data Block
    write_fields(&mut *out, if encrypted { Some(&literal_salt) } else { None }, s1_ctype, literal_compressed.len() as u64, literal_stream.len() as u64, 0)?;
    out.write_all(&literal_compressed)?;

    Ok(())
}

fn print_info(magic: &MagicHeader, rcd: &crate::format::RcdHeader) {
    println!("LRZIP-NEXT {}.{}", magic.major, magic.minor);
    match magic.expected_size {
        Some(size) => println!("Expected size: {}", size),
        None => println!("Expected size: encrypted"),
    }
    println!("Hash: {}", format_hash(magic.hash));
    let integrity = IntegrityLayout::from_hash(magic.hash);
    println!("CRC32 per block: {} bytes", integrity.crc32_len);
    if let Some(len) = integrity.file_hash_len {
        println!("File hash length: {} bytes", len);
    }
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
        CompressionType::Bzip2 => "bzip2".to_string(),
        CompressionType::Lzo => "lzo".to_string(),
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
        BackendProps::Bzip2 { block_size_code } => format!("bzip2(block={})", block_size_code),
    }
}
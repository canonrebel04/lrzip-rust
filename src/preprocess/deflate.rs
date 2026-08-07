use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::{Read, Write};

pub const ZREC_MAGIC: &[u8; 4] = b"ZREC";
pub const ZREC_HDR_SIZE: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZrecMeta {
    pub orig_offset: u64,
    pub compressed_len: u64,
    pub raw_len: u64,
    pub zlib_cmf: u8,
    pub zlib_flg: u8,
    pub _pad: [u8; 6],
}

pub fn scan_and_decompress(in_buf: &[u8]) -> Option<Vec<u8>> {
    if in_buf.len() < 512 {
        return None;
    }

    let mut found_count = 0;
    let mut metas = Vec::new();
    let mut raw_streams = Vec::new();
    let mut raw_total_allocated = 0;

    let mut i = 0;
    while i + 32 < in_buf.len() && found_count < 16 {
        if in_buf[i] == 0x78 && matches!(in_buf[i + 1], 0x9c | 0x01 | 0xda | 0x5e) {
            let candidate = &in_buf[i..];
            let mut decoder = DeflateDecoder::new(&candidate[2..]); // Skip 2-byte zlib header for raw deflate
            let mut decompressed = Vec::new();

            if decoder.read_to_end(&mut decompressed).is_ok() && decompressed.len() > 1024 {
                let consumed_compressed = decoder.total_in() as usize + 2; // +2 for CMF/FLG
                let level = match in_buf[i + 1] {
                    0xda => Compression::best(),
                    0x01 => Compression::fast(),
                    _ => Compression::default(),
                };

                let mut encoder = DeflateEncoder::new(Vec::new(), level);
                if encoder.write_all(&decompressed).is_ok() {
                    if let Ok(recompressed) = encoder.finish() {
                        if recompressed.len() + 2 == consumed_compressed {
                            let meta = ZrecMeta {
                                orig_offset: i as u64,
                                compressed_len: consumed_compressed as u64,
                                raw_len: decompressed.len() as u64,
                                zlib_cmf: in_buf[i],
                                zlib_flg: in_buf[i + 1],
                                _pad: [0; 6],
                            };
                            raw_total_allocated += decompressed.len();
                            metas.push(meta);
                            raw_streams.push(decompressed);
                            found_count += 1;
                            i += consumed_compressed;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }

    if found_count == 0 {
        return None;
    }

    let meta_bytes_len = found_count * std::mem::size_of::<ZrecMeta>();
    let metadata_size = ZREC_HDR_SIZE + meta_bytes_len;
    let total_out_size = metadata_size + in_buf.len() + raw_total_allocated;
    let mut out = Vec::with_capacity(total_out_size);

    out.extend_from_slice(ZREC_MAGIC);
    out.extend_from_slice(&(found_count as u32).to_le_bytes());
    out.extend_from_slice(&(in_buf.len() as u64).to_le_bytes());

    for meta in &metas {
        let bytes: &[u8; std::mem::size_of::<ZrecMeta>()] = unsafe { std::mem::transmute(meta) };
        out.extend_from_slice(bytes);
    }

    let mut curr_in = 0;
    for (k, meta) in metas.iter().enumerate() {
        let copy_len = meta.orig_offset as usize - curr_in;
        if copy_len > 0 {
            out.extend_from_slice(&in_buf[curr_in..curr_in + copy_len]);
        }
        out.extend_from_slice(&raw_streams[k]);
        curr_in = meta.orig_offset as usize + meta.compressed_len as usize;
    }
    if in_buf.len() > curr_in {
        out.extend_from_slice(&in_buf[curr_in..]);
    }

    Some(out)
}

pub fn reconstruct(in_buf: &[u8]) -> Option<Vec<u8>> {
    if in_buf.len() < ZREC_HDR_SIZE || &in_buf[..4] != ZREC_MAGIC {
        return None;
    }

    let count = u32::from_le_bytes(in_buf[4..8].try_into().ok()?) as usize;
    let orig_in_len = u64::from_le_bytes(in_buf[8..16].try_into().ok()?) as usize;

    if count == 0 || count > 100 {
        return None;
    }

    let meta_size = std::mem::size_of::<ZrecMeta>();
    let metadata_size = ZREC_HDR_SIZE + count * meta_size;
    if in_buf.len() < metadata_size {
        return None;
    }

    let mut metas = Vec::with_capacity(count);
    for k in 0..count {
        let start = ZREC_HDR_SIZE + k * meta_size;
        let slice = &in_buf[start..start + meta_size];
        let meta: ZrecMeta = unsafe { std::ptr::read(slice.as_ptr() as *const ZrecMeta) };
        metas.push(meta);
    }

    let mut out = Vec::with_capacity(orig_in_len);
    let mut src_idx = metadata_size;

    for meta in metas {
        let copy_len = meta.orig_offset as usize - out.len();
        if copy_len > 0 && src_idx + copy_len <= in_buf.len() {
            out.extend_from_slice(&in_buf[src_idx..src_idx + copy_len]);
            src_idx += copy_len;
        }

        let raw_len = meta.raw_len as usize;
        if src_idx + raw_len <= in_buf.len() {
            let raw_data = &in_buf[src_idx..src_idx + raw_len];
            let level = match meta.zlib_flg {
                0xda => Compression::best(),
                0x01 => Compression::fast(),
                _ => Compression::default(),
            };

            let mut encoder = DeflateEncoder::new(Vec::new(), level);
            if encoder.write_all(raw_data).is_ok() {
                if let Ok(recompressed) = encoder.finish() {
                    out.push(meta.zlib_cmf);
                    out.push(meta.zlib_flg);
                    out.extend_from_slice(&recompressed);
                }
            }
            src_idx += raw_len;
        }
    }

    if src_idx < in_buf.len() {
        out.extend_from_slice(&in_buf[src_idx..]);
    }

    Some(out)
}

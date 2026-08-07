pub const DXT_MAGIC: &[u8; 4] = b"DXT\x01";
pub const DXT_HDR_SIZE: usize = 24;

pub fn transpose(in_buf: &[u8]) -> Option<Vec<u8>> {
    if in_buf.len() < 1024 {
        return None;
    }

    let mut dxt_type = 0;
    let mut block_size = 0;

    let scan_len = in_buf.len().min(4096);
    let scan_slice = &in_buf[..scan_len];

    if memmem(scan_slice, b"DXT1") {
        dxt_type = 1;
        block_size = 8;
    } else if memmem(scan_slice, b"DXT5") {
        dxt_type = 5;
        block_size = 16;
    } else if in_buf.len() >= 128 && &in_buf[..4] == b"DDS " {
        let fourcc = u32::from_le_bytes([in_buf[84], in_buf[85], in_buf[86], in_buf[87]]);
        if fourcc == 0x31545844 {
            dxt_type = 1;
            block_size = 8;
        } else if fourcc == 0x33545844 || fourcc == 0x35545844 {
            dxt_type = 5;
            block_size = 16;
        } else {
            return None;
        }
    } else {
        return None;
    }

    let blocks = in_buf.len() / block_size;
    if blocks < 64 {
        return None;
    }

    let out_len = DXT_HDR_SIZE + in_buf.len();
    let mut out = Vec::with_capacity(out_len);

    out.extend_from_slice(DXT_MAGIC);
    out.extend_from_slice(&(dxt_type as u32).to_le_bytes());
    out.extend_from_slice(&(blocks as u64).to_le_bytes());
    out.extend_from_slice(&(in_buf.len() as u64).to_le_bytes());

    if dxt_type == 1 {
        for b in 0..8 {
            for i in 0..blocks {
                out.push(in_buf[i * 8 + b]);
            }
        }
        if in_buf.len() > blocks * 8 {
            out.extend_from_slice(&in_buf[blocks * 8..]);
        }
    } else {
        for b in 0..16 {
            for i in 0..blocks {
                out.push(in_buf[i * 16 + b]);
            }
        }
        if in_buf.len() > blocks * 16 {
            out.extend_from_slice(&in_buf[blocks * 16..]);
        }
    }

    Some(out)
}

pub fn untranspose(in_buf: &[u8]) -> Option<Vec<u8>> {
    if in_buf.len() < DXT_HDR_SIZE {
        return None;
    }

    if &in_buf[..4] != DXT_MAGIC {
        return None;
    }

    let dxt_type = u32::from_le_bytes(in_buf[4..8].try_into().ok()?);
    let blocks = u64::from_le_bytes(in_buf[8..16].try_into().ok()?) as usize;
    let orig_len = u64::from_le_bytes(in_buf[16..24].try_into().ok()?) as usize;

    let mut out = vec![0u8; orig_len];
    let src = &in_buf[DXT_HDR_SIZE..];
    let mut src_idx = 0;

    if dxt_type == 1 {
        for b in 0..8 {
            for i in 0..blocks {
                if src_idx < src.len() && i * 8 + b < orig_len {
                    out[i * 8 + b] = src[src_idx];
                    src_idx += 1;
                }
            }
        }
        if orig_len > blocks * 8 && src_idx < src.len() {
            let tail_len = (orig_len - blocks * 8).min(src.len() - src_idx);
            out[blocks * 8..blocks * 8 + tail_len].copy_from_slice(&src[src_idx..src_idx + tail_len]);
        }
    } else {
        for b in 0..16 {
            for i in 0..blocks {
                if src_idx < src.len() && i * 16 + b < orig_len {
                    out[i * 16 + b] = src[src_idx];
                    src_idx += 1;
                }
            }
        }
        if orig_len > blocks * 16 && src_idx < src.len() {
            let tail_len = (orig_len - blocks * 16).min(src.len() - src_idx);
            out[blocks * 16..blocks * 16 + tail_len].copy_from_slice(&src[src_idx..src_idx + tail_len]);
        }
    }

    Some(out)
}

fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

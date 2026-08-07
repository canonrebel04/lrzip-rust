//! Bit-exact DEFLATE recompression via Microsoft's preflate-rs.
//!
//! Replaces the old flate2-recompression approach (which required the
//! recompressed stream to be exactly the same size and was therefore dead
//! code in practice). preflate-rs analyzes an existing DEFLATE bitstream,
//! extracts the plaintext plus a compact corrections blob (<1% typically),
//! and reconstructs the ORIGINAL bytes bit-for-bit.
//!
//! Container (ZREC): keeps the original magic/header layout, but each stream
//! payload is now [plaintext][corrections] instead of a recompressed stream.
//! Reconstruction replays preflate's predictor to restore the exact original
//! zlib stream (2-byte CMF/FLG header + raw deflate body; the trailing
//! ADLER-32 checksum stays in the unmodified region).

use preflate_rs::{PreflateConfig, preflate_whole_deflate_stream, recreate_whole_deflate_stream};

pub const ZREC_MAGIC: &[u8; 4] = b"ZREC";
pub const ZREC_HDR_SIZE: usize = 16;
pub const ZREC_META_SIZE: usize = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZrecMeta {
    /// Offset of the zlib stream (CMF byte) in the original input.
    pub orig_offset: u64,
    /// Length of the raw deflate body (excludes the 2-byte zlib header).
    pub deflate_len: u64,
    /// Plaintext (decompressed) length.
    pub raw_len: u64,
    /// preflate corrections blob length.
    pub corrections_len: u32,
    pub zlib_cmf: u8,
    pub zlib_flg: u8,
    pub _pad: [u8; 2],
}

fn write_meta(out: &mut Vec<u8>, meta: &ZrecMeta) {
    out.extend_from_slice(&meta.orig_offset.to_le_bytes());
    out.extend_from_slice(&meta.deflate_len.to_le_bytes());
    out.extend_from_slice(&meta.raw_len.to_le_bytes());
    out.extend_from_slice(&meta.corrections_len.to_le_bytes());
    out.push(meta.zlib_cmf);
    out.push(meta.zlib_flg);
    out.extend_from_slice(&meta._pad);
}

pub fn read_meta(in_buf: &[u8], at: usize) -> Option<ZrecMeta> {
    if at + ZREC_META_SIZE > in_buf.len() {
        return None;
    }
    Some(ZrecMeta {
        orig_offset: u64::from_le_bytes(in_buf[at..at + 8].try_into().ok()?),
        deflate_len: u64::from_le_bytes(in_buf[at + 8..at + 16].try_into().ok()?),
        raw_len: u64::from_le_bytes(in_buf[at + 16..at + 24].try_into().ok()?),
        corrections_len: u32::from_le_bytes(in_buf[at + 24..at + 28].try_into().ok()?),
        zlib_cmf: in_buf[at + 28],
        zlib_flg: in_buf[at + 29],
        _pad: [0; 2],
    })
}

/// Parse a ZIP local file header (PK\x03\x04) at `at`. Returns
/// (data_offset, compressed_size, method). Method 8 = deflate.
fn parse_zip_local_header(in_buf: &[u8], at: usize) -> Option<(usize, usize, u16)> {
    if at + 30 > in_buf.len() {
        return None;
    }
    let method = u16::from_le_bytes([in_buf[at + 8], in_buf[at + 9]]);
    let comp_len = u32::from_le_bytes(in_buf[at + 18..at + 22].try_into().ok()?) as usize;
    let name_len = u16::from_le_bytes([in_buf[at + 26], in_buf[at + 27]]) as usize;
    let extra_len = u16::from_le_bytes([in_buf[at + 28], in_buf[at + 29]]) as usize;
    let data_off = at + 30 + name_len + extra_len;
    if data_off > in_buf.len() {
        return None;
    }
    Some((data_off, comp_len, method))
}

/// Parse a gzip header (1F 8B) at `at`. Returns (deflate_body_offset,
/// available_len) — the body extends to the end of the buffer; preflate's
/// compressed_size pins the actual stream length (CRC32 + ISIZE follow).
fn parse_gzip_header(in_buf: &[u8], at: usize) -> Option<(usize, usize)> {
    if at + 10 > in_buf.len() || in_buf[at + 2] != 8 {
        return None;
    }
    let flags = in_buf[at + 3];
    let mut p = at + 10;
    if flags & 0x04 != 0 {
        // FEXTRA
        if p + 2 > in_buf.len() {
            return None;
        }
        let xlen = u16::from_le_bytes([in_buf[p], in_buf[p + 1]]) as usize;
        p += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        // FNAME (NUL-terminated)
        while p < in_buf.len() && in_buf[p] != 0 {
            p += 1;
        }
        if p >= in_buf.len() {
            return None;
        }
        p += 1;
    }
    if flags & 0x10 != 0 {
        // FCOMMENT (NUL-terminated)
        while p < in_buf.len() && in_buf[p] != 0 {
            p += 1;
        }
        if p >= in_buf.len() {
            return None;
        }
        p += 1;
    }
    if flags & 0x02 != 0 {
        // FHCRC
        p += 2;
    }
    if p >= in_buf.len() {
        return None;
    }
    Some((p, in_buf.len() - p))
}

/// Heuristic: is the plaintext text-like? zpaq's context models beat zlib
/// mainly on text/structured data (2-3x); on binary (PNG-filtered image
/// data, random) both sit near the entropy limit, so recompression is a
/// net loss. Sample a few windows and require a high printable fraction.
fn is_text_like(raw: &[u8]) -> bool {
    if raw.is_empty() {
        return false;
    }
    // Sample up to 4 windows of 4KB each spread across the plaintext.
    let windows: Vec<&[u8]> = if raw.len() <= 16384 {
        vec![raw]
    } else {
        let step = raw.len() / 3;
        vec![&raw[..16384], &raw[step..step + 16384], &raw[raw.len() - 16384..]]
    };
    let mut total = 0usize;
    let mut printable = 0usize;
    for w in windows {
        for &b in w {
            total += 1;
            let p = b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b);
            if p {
                printable += 1;
            }
        }
    }
    total > 0 && printable * 100 >= total * 80
}

/// Try preflate on a candidate deflate body. Returns Some((compressed_size,
/// plaintext, corrections)) when the stream is parseable and worthwhile.
fn try_preflate(candidate: &[u8], config: &PreflateConfig) -> Option<(usize, Vec<u8>, Vec<u8>)> {
    if candidate.len() < 128 {
        return None;
    }
    match preflate_whole_deflate_stream(candidate, config) {
        Ok((result, plain_text)) => {
            let raw = plain_text.text().to_vec();
            let comp = result.compressed_size;
            // Only keep streams that are clearly real and worthwhile:
            // - large plaintext (garbage parses of random bytes are small)
            // - meaningful compressed size
            // - text-like plaintext (only then does zpaq beat the original
            //   zlib; on binary both sit near the entropy limit -> loss)
            // - the parse consumed the whole candidate region
            if raw.len() > 32 * 1024
                && comp > 128
                && is_text_like(&raw)
                && comp <= candidate.len()
            {
                Some((comp, raw, result.corrections))
            } else {
                None
            }
        }
        Err(_) => None, // false positive (random 0x78 0xXX bytes)
    }
}

/// Scan for zlib streams (0x78 CMF) and replace each with
/// [plaintext][preflate corrections]. Returns None when nothing usable found.
pub fn scan_and_decompress(in_buf: &[u8]) -> Option<Vec<u8>> {
    if in_buf.len() < 512 {
        return None;
    }

    // verify_compression makes preflate round-trip-check every stream
    // internally (extra pass, but guarantees we only keep streams we can
    // reconstruct bit-exactly).
    let config = PreflateConfig {
        verify_compression: true,
        ..Default::default()
    };

    let mut found_count = 0;
    let mut metas = Vec::new();
    let mut payloads: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (plaintext, corrections)
    let mut payload_total = 0usize;

    let mut i = 0;
    while i + 32 < in_buf.len() && found_count < 16 {
        let mut processed = 0usize; // bytes consumed if a stream was found at i

        if in_buf[i] == 0x78 && u16::from_be_bytes([in_buf[i], in_buf[i + 1]]) % 31 == 0 {
            // zlib-wrapped deflate (PNG IDAT, .zlib, etc.). Validate the
            // stream boundary with the trailing ADLER-32 (big-endian).
            if let Some((comp, raw, corrections)) = try_preflate(&in_buf[i + 2..], &config) {
                let adler_off = i + 2 + comp;
                let complete = adler_off + 4 <= in_buf.len()
                    && u32::from_be_bytes(in_buf[adler_off..adler_off + 4].try_into().ok()?)
                        == adler::adler32_slice(&raw);
                if complete {
                    let meta = ZrecMeta {
                        orig_offset: i as u64,
                        deflate_len: comp as u64,
                        raw_len: raw.len() as u64,
                        corrections_len: corrections.len() as u32,
                        zlib_cmf: in_buf[i],
                        zlib_flg: in_buf[i + 1],
                        _pad: [0; 2],
                    };
                    payload_total += raw.len() + corrections.len();
                    metas.push(meta);
                    payloads.push((raw, corrections));
                    found_count += 1;
                    processed = 2 + comp + 4; // include the ADLER in the skip
                }
            }
        } else if in_buf[i..].starts_with(b"PK\x03\x04") {
            // ZIP local file header: locate a raw-deflate member's data.
            if let Some((data_off, comp_len, method)) = parse_zip_local_header(in_buf, i) {
                if method == 8 && comp_len > 0 && data_off + comp_len <= in_buf.len() {
                    if let Some((comp, raw, corrections)) =
                        try_preflate(&in_buf[data_off..data_off + comp_len], &config)
                    {
                        // Member is complete iff the parse consumes exactly
                        // the declared compressed size AND the plaintext
                        // CRC32 matches the local header's stored CRC.
                        let stored_crc =
                            u32::from_le_bytes(in_buf[i + 14..i + 18].try_into().ok()?);
                        let complete = comp == comp_len
                            && crc32fast::hash(&raw) == stored_crc;
                        if complete {
                            let meta = ZrecMeta {
                                orig_offset: data_off as u64,
                                deflate_len: comp as u64,
                                raw_len: raw.len() as u64,
                                corrections_len: corrections.len() as u32,
                                zlib_cmf: 0, // not zlib-wrapped
                                zlib_flg: 0,
                                _pad: [0; 2],
                            };
                            payload_total += raw.len() + corrections.len();
                            metas.push(meta);
                            payloads.push((raw, corrections));
                            found_count += 1;
                            processed = data_off - i + comp;
                        }
                    }
                }
            }
        } else if in_buf[i..].starts_with(b"\x1f\x8b") {
            // gzip: locate the raw-deflate body (skip header, flags, extras).
            if let Some((body_off, body_len)) = parse_gzip_header(in_buf, i) {
                if body_len > 0 {
                    if let Some((comp, raw, corrections)) =
                        try_preflate(&in_buf[body_off..body_off + body_len], &config)
                    {
                        // Trailer: CRC32 (LE) + ISIZE (LE) = plaintext len.
                        let crc_off = body_off + comp;
                        let complete = crc_off + 8 <= in_buf.len()
                            && u32::from_le_bytes(in_buf[crc_off..crc_off + 4].try_into().ok()?)
                                == crc32fast::hash(&raw)
                            && u32::from_le_bytes(in_buf[crc_off + 4..crc_off + 8].try_into().ok()?)
                                == raw.len() as u32;
                        if complete {
                            let meta = ZrecMeta {
                                orig_offset: body_off as u64,
                                deflate_len: comp as u64,
                                raw_len: raw.len() as u64,
                                corrections_len: corrections.len() as u32,
                                zlib_cmf: 0,
                                zlib_flg: 0,
                                _pad: [0; 2],
                            };
                            payload_total += raw.len() + corrections.len();
                            metas.push(meta);
                            payloads.push((raw, corrections));
                            found_count += 1;
                            processed = body_off - i + comp + 8; // skip trailer
                        }
                    }
                }
            }
        }

        if processed > 0 {
            i += processed;
        } else {
            i += 1;
        }
    }

    if found_count == 0 {
        return None;
    }

    let metadata_size = ZREC_HDR_SIZE + found_count * ZREC_META_SIZE;
    let mut out = Vec::with_capacity(metadata_size + in_buf.len() + payload_total);

    out.extend_from_slice(ZREC_MAGIC);
    out.extend_from_slice(&(found_count as u32).to_le_bytes());
    out.extend_from_slice(&(in_buf.len() as u64).to_le_bytes());
    for meta in &metas {
        write_meta(&mut out, meta);
    }

    let mut curr_in = 0;
    for (k, meta) in metas.iter().enumerate() {
        let copy_len = meta.orig_offset as usize - curr_in;
        if copy_len > 0 {
            out.extend_from_slice(&in_buf[curr_in..curr_in + copy_len]);
        }
        let (raw, corrections) = &payloads[k];
        out.extend_from_slice(raw);
        out.extend_from_slice(corrections);
        // zlib streams have a 2-byte CMF/FLG header; ZIP/gzip members are
        // raw deflate. The trailer (ADLER/CRC+ISIZE) stays in the unmodified
        // region because it is not part of the deflate body.
        let hdr = if meta.zlib_cmf != 0 { 2 } else { 0 };
        curr_in = meta.orig_offset as usize + hdr + meta.deflate_len as usize;
    }
    if in_buf.len() > curr_in {
        out.extend_from_slice(&in_buf[curr_in..]);
    }

    Some(out)
}

/// Restore the original input from a ZREC container: replay preflate's
/// predictor per stream to rebuild each zlib stream bit-exactly.
pub fn reconstruct(in_buf: &[u8]) -> Option<Vec<u8>> {
    if in_buf.len() < ZREC_HDR_SIZE || &in_buf[..4] != ZREC_MAGIC {
        return None;
    }

    let count = u32::from_le_bytes(in_buf[4..8].try_into().ok()?) as usize;
    let orig_in_len = u64::from_le_bytes(in_buf[8..16].try_into().ok()?) as usize;
    if count == 0 || count > 100 {
        return None;
    }

    let metadata_size = ZREC_HDR_SIZE + count * ZREC_META_SIZE;
    if in_buf.len() < metadata_size {
        return None;
    }

    let mut metas = Vec::with_capacity(count);
    for k in 0..count {
        metas.push(read_meta(in_buf, ZREC_HDR_SIZE + k * ZREC_META_SIZE)?);
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
        let corr_len = meta.corrections_len as usize;
        if src_idx + raw_len + corr_len <= in_buf.len() {
            let plaintext = &in_buf[src_idx..src_idx + raw_len];
            let corrections = &in_buf[src_idx + raw_len..src_idx + raw_len + corr_len];
            if let Ok(deflate_body) = recreate_whole_deflate_stream(plaintext, corrections) {
                // zlib_cmf != 0 means the stream was zlib-wrapped (2-byte
                // header preserved); ZIP/gzip members are raw deflate.
                if meta.zlib_cmf != 0 {
                    out.push(meta.zlib_cmf);
                    out.push(meta.zlib_flg);
                }
                out.extend_from_slice(&deflate_body);
            }
            src_idx += raw_len + corr_len;
        }
    }

    if src_idx < in_buf.len() {
        out.extend_from_slice(&in_buf[src_idx..]);
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn make_zlib_embedded(payload: &[u8], gap_before: usize, gap_after: usize) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let zlib_stream = enc.finish().unwrap();

        let mut file = vec![0xAAu8; gap_before];
        file.extend_from_slice(&zlib_stream);
        file.resize(file.len() + gap_after, 0xBB);
        file
    }

    #[test]
    fn roundtrip_embedded_zlib() {
        // Text payload (the case where zpaq beats zlib and preflate pays off)
        let mut payload = String::new();
        for row in 0..2000 {
            payload.push_str(&format!(
                "<entry id=\"{}\" name=\"item_{}\" value=\"{}\">row data {} padding</entry>\n",
                row, row % 500, (row * 7919) % 65536, row
            ));
        }
        let file = make_zlib_embedded(payload.as_bytes(), 100, 50);

        let zrec = scan_and_decompress(&file).expect("should find the zlib stream");
        assert_ne!(zrec, file);
        let restored = reconstruct(&zrec).expect("reconstruct");
        assert_eq!(restored, file, "bit-exact round-trip");
    }

    #[test]
    fn multiple_streams() {
        // Two text streams (preflate rejects degenerate trees from
        // single-repeated-byte data — those streams are skipped, never
        // corrupted).
        let mut payload1 = String::new();
        for row in 0..2000 {
            payload1.push_str(&format!(
                "<item id=\"{}\" name=\"thing_{}\" data=\"{}\"/>\n",
                row, row % 300, (row * 2654435761u64 % 100000)
            ));
        }
        let mut payload2 = String::new();
        for i in 0..20000u32 {
            payload2.push_str(&format!("line {}: the quick brown fox jumps over the lazy dog\n", i));
        }
        let mut enc1 = ZlibEncoder::new(Vec::new(), Compression::default());
        enc1.write_all(payload1.as_bytes()).unwrap();
        let s1 = enc1.finish().unwrap();
        let mut enc2 = ZlibEncoder::new(Vec::new(), Compression::best());
        enc2.write_all(payload2.as_bytes()).unwrap();
        let s2 = enc2.finish().unwrap();

        let mut file = Vec::new();
        file.extend_from_slice(&[1u8; 32]);
        file.extend_from_slice(&s1);
        file.extend_from_slice(&[2u8; 64]);
        file.extend_from_slice(&s2);
        file.extend_from_slice(&[3u8; 128]);

        let zrec = scan_and_decompress(&file).expect("streams found");
        let restored = reconstruct(&zrec).expect("reconstruct");
        assert_eq!(restored, file);
    }

    #[test]
    fn binary_stream_is_skipped() {
        // PNG-filter-like binary plaintext: zpaq ≈ zlib there, so the
        // scanner must NOT replace it (net loss otherwise).
        let mut payload = Vec::new();
        for row in 0..2000 {
            payload.push(0u8); // PNG filter type 0
            for x in 0..64 {
                payload.push(((x * 7 + row * 13) & 0xFF) as u8);
            }
        }
        let file = make_zlib_embedded(&payload, 100, 50);
        assert!(scan_and_decompress(&file).is_none(), "binary streams must be skipped");
    }

    #[test]
    fn no_streams_returns_none() {
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i * 31) as u8;
        }
        assert!(scan_and_decompress(&data).is_none());
    }
}

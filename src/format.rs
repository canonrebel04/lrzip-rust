use thiserror::Error;

pub const MAGIC_LEN_V11: usize = 21;
pub const SALT_LEN: usize = 8;

#[derive(Debug, Error)]
pub enum MagicError {
    #[error("magic header too short: {0} bytes")]
    TooShort(usize),
    #[error("invalid magic signature")]
    InvalidSignature,
}

#[derive(Debug, Error)]
pub enum RcdError {
    #[error("rcd header too short: need {needed} bytes, have {available}")]
    TooShort { needed: usize, available: usize },
    #[error("invalid chunk byte width: {0}")]
    InvalidChunkBytes(u8),
}

#[derive(Debug, Error)]
pub enum BlockError {
    #[error("block header too short: need {needed} bytes, have {available}")]
    TooShort { needed: usize, available: usize },
    #[error("invalid chunk byte width: {0}")]
    InvalidChunkBytes(u8),
    #[error("invalid next_head value: {0}")]
    InvalidNextHead(u64),
    #[error("excessive block headers walked ({0})")]
    ExcessiveBlocks(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionLevels {
    pub rzip: u8,
    pub lrzip: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Crc,
    Md5,
    Ripemd,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
    Shake128_16,
    Shake128_32,
    Shake128_64,
    Shake256_16,
    Shake256_32,
    Shake256_64,
    Unknown(u8),
}

impl From<u8> for HashKind {
    fn from(value: u8) -> Self {
        match value {
            0 => HashKind::Crc,
            1 => HashKind::Md5,
            2 => HashKind::Ripemd,
            3 => HashKind::Sha256,
            4 => HashKind::Sha384,
            5 => HashKind::Sha512,
            6 => HashKind::Sha3_256,
            7 => HashKind::Sha3_512,
            8 => HashKind::Shake128_16,
            9 => HashKind::Shake128_32,
            10 => HashKind::Shake128_64,
            11 => HashKind::Shake256_16,
            12 => HashKind::Shake256_32,
            13 => HashKind::Shake256_64,
            other => HashKind::Unknown(other),
        }
    }
}

pub const CRC32_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityLayout {
    pub crc32_len: usize,
    pub file_hash_len: Option<usize>,
}

impl IntegrityLayout {
    pub fn from_hash(hash: HashKind) -> Self {
        let file_hash_len = hash_len(hash);
        IntegrityLayout {
            crc32_len: CRC32_LEN,
            file_hash_len,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionCode {
    Aes128,
    Aes256,
    Unknown(u8),
}

impl From<u8> for EncryptionCode {
    fn from(value: u8) -> Self {
        match value {
            1 => EncryptionCode::Aes128,
            2 => EncryptionCode::Aes256,
            other => EncryptionCode::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionInfo {
    pub code: EncryptionCode,
    pub salt: [u8; 8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcjFilter {
    X86,
    Arm,
    ArmThumb,
    Arm64,
    Ppc,
    Sparc,
    Ia64,
    RiscV,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterSpec {
    None,
    Delta { offset: u8 },
    Bcj(BcjFilter),
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None,
    Lzma,
    Zpaq,
    Bzip3,
    Zstd { strategy: u8 },
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendProps {
    None,
    Lzma { dict_prop: u8 },
    Zpaq { level: u8, block_size: u8 },
    Bzip3 { block_size_code: u8 },
    Zstd { level: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicHeader {
    pub major: u8,
    pub minor: u8,
    pub expected_size: Option<u64>,
    pub encryption: Option<EncryptionInfo>,
    pub hash: HashKind,
    pub filter: FilterSpec,
    pub compression: CompressionType,
    pub backend_props: BackendProps,
    pub levels: CompressionLevels,
    pub comment_len: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    pub header_salt: Option<[u8; 8]>,
    pub ctype: u8,
    pub compressed_len: u64,
    pub uncompressed_len: u64,
    pub next_head: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub header_salt: Option<[u8; SALT_LEN]>,
    pub ctype: u8,
    pub compressed_len: u64,
    pub uncompressed_len: u64,
    pub next_head: u64,
    pub has_block_salt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcdHeader {
    pub chunk_bytes: u8,
    pub is_last_chunk: bool,
    pub chunk_size: Option<u64>,
    pub streams: Vec<StreamHeader>,
}

impl MagicHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, MagicError> {
        if bytes.len() < MAGIC_LEN_V11 {
            return Err(MagicError::TooShort(bytes.len()));
        }
        if &bytes[0..4] != b"LRZI" {
            return Err(MagicError::InvalidSignature);
        }

        let major = bytes[4];
        let minor = bytes[5];

        let enc_code = bytes[15];
        let encryption = if enc_code != 0 {
            let mut salt = [0u8; 8];
            salt.copy_from_slice(&bytes[6..14]);
            Some(EncryptionInfo {
                code: EncryptionCode::from(enc_code),
                salt,
            })
        } else {
            None
        };

        let expected_size = if encryption.is_none() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[6..14]);
            Some(u64::from_le_bytes(buf))
        } else {
            None
        };

        let hash = HashKind::from(bytes[14]);
        let filter = parse_filter(bytes[16], minor);
        let (compression, backend_props) = parse_compression(bytes[17], bytes[18]);
        let levels = CompressionLevels {
            rzip: bytes[19] >> 4,
            lrzip: bytes[19] & 0x0f,
        };
        let comment_len = bytes[20];

        Ok(MagicHeader {
            major,
            minor,
            expected_size,
            encryption,
            hash,
            filter,
            compression,
            backend_props,
            levels,
            comment_len,
        })
    }
}

pub fn parse_rcd_header(
    bytes: &[u8],
    offset: usize,
    encrypted: bool,
    num_streams: usize,
) -> Result<(RcdHeader, usize), RcdError> {
    let needed = offset + 2;
    if bytes.len() < needed {
        return Err(RcdError::TooShort {
            needed,
            available: bytes.len(),
        });
    }

    let chunk_bytes = bytes[offset];
    if chunk_bytes == 0 || chunk_bytes > 8 {
        return Err(RcdError::InvalidChunkBytes(chunk_bytes));
    }
    let is_last_chunk = bytes[offset + 1] != 0;
    let mut cursor = offset + 2;

    let chunk_size = if encrypted {
        None
    } else {
        let val = read_var_le(bytes, cursor, chunk_bytes as usize)?;
        cursor += chunk_bytes as usize;
        Some(val)
    };

    let header_len = if encrypted { 8usize } else { chunk_bytes as usize };
    let mut streams = Vec::with_capacity(num_streams);
    for _ in 0..num_streams {
        let header_salt = if encrypted {
            let needed = cursor + 8;
            if bytes.len() < needed {
                return Err(RcdError::TooShort {
                    needed,
                    available: bytes.len(),
                });
            }
            let mut salt = [0u8; 8];
            salt.copy_from_slice(&bytes[cursor..cursor + 8]);
            cursor += 8;
            Some(salt)
        } else {
            None
        };

        let needed = cursor + 1 + (header_len * 3);
        if bytes.len() < needed {
            return Err(RcdError::TooShort {
                needed,
                available: bytes.len(),
            });
        }

        let ctype = bytes[cursor];
        cursor += 1;
        let compressed_len = read_var_le(bytes, cursor, header_len)?;
        cursor += header_len;
        let uncompressed_len = read_var_le(bytes, cursor, header_len)?;
        cursor += header_len;
        let next_head = read_var_le(bytes, cursor, header_len)?;
        cursor += header_len;

        streams.push(StreamHeader {
            header_salt,
            ctype,
            compressed_len,
            uncompressed_len,
            next_head,
        });
    }

    Ok((
        RcdHeader {
            chunk_bytes,
            is_last_chunk,
            chunk_size,
            streams,
        },
        cursor - offset,
    ))
}

pub fn stream_header_len(chunk_bytes: u8, encrypted: bool) -> Result<usize, RcdError> {
    if chunk_bytes == 0 || chunk_bytes > 8 {
        return Err(RcdError::InvalidChunkBytes(chunk_bytes));
    }
    let val_len = if encrypted { 8 } else { chunk_bytes as usize };
    let base = 1 + (val_len * 3);
    Ok(if encrypted { SALT_LEN + base } else { base })
}

pub fn initial_pos_from_rcd(offset: usize, chunk_bytes: u8, encrypted: bool) -> Result<usize, RcdError> {
    if chunk_bytes == 0 || chunk_bytes > 8 {
        return Err(RcdError::InvalidChunkBytes(chunk_bytes));
    }
    Ok(offset + 2 + if encrypted { 0 } else { chunk_bytes as usize })
}

pub fn parse_block_header_at(
    bytes: &[u8],
    abs_offset: usize,
    chunk_bytes: u8,
    encrypted: bool,
) -> Result<BlockHeader, BlockError> {
    let val_len = if encrypted { 8 } else { chunk_bytes as usize };
    let needed = abs_offset + (if encrypted { SALT_LEN } else { 0 }) + 1 + (val_len * 3);
    if bytes.len() < needed {
        return Err(BlockError::TooShort {
            needed,
            available: bytes.len(),
        });
    }

    let header_salt = if encrypted {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[abs_offset..abs_offset + SALT_LEN]);
        Some(salt)
    } else {
        None
    };

    let mut cursor = abs_offset + if encrypted { SALT_LEN } else { 0 };
    let ctype = bytes[cursor];
    cursor += 1;
    let compressed_len = read_var_le_block(bytes, cursor, val_len)?;
    cursor += val_len;
    let uncompressed_len = read_var_le_block(bytes, cursor, val_len)?;
    cursor += val_len;
    let next_head = read_var_le_block(bytes, cursor, val_len)?;

    Ok(BlockHeader {
        header_salt,
        ctype,
        compressed_len,
        uncompressed_len,
        next_head,
        has_block_salt: encrypted,
    })
}

pub fn walk_stream_blocks(
    bytes: &[u8],
    rcd_offset: usize,
    stream_index: usize,
    num_streams: usize,
    encrypted: bool,
    max_blocks: usize,
) -> Result<Vec<(u64, BlockHeader)>, BlockError> {
    let chunk_bytes = bytes.get(rcd_offset).copied().ok_or(BlockError::TooShort {
        needed: rcd_offset + 1,
        available: bytes.len(),
    })?;

    let initial_pos = initial_pos_from_rcd(rcd_offset, chunk_bytes, encrypted).map_err(|e| match e {
        RcdError::TooShort { needed, available } => BlockError::TooShort { needed, available },
        RcdError::InvalidChunkBytes(v) => BlockError::InvalidChunkBytes(v),
    })?;

    let header_len = stream_header_len(chunk_bytes, encrypted).map_err(|e| match e {
        RcdError::TooShort { needed, available } => BlockError::TooShort { needed, available },
        RcdError::InvalidChunkBytes(v) => BlockError::InvalidChunkBytes(v),
    })?;

    let stream_rel = (stream_index * header_len) as u64;
    if stream_index >= num_streams {
        return Err(BlockError::InvalidNextHead(stream_rel));
    }

    let mut out: Vec<(u64, BlockHeader)> = Vec::new();
    let mut cur_rel = stream_rel;
    let mut walked = 0usize;
    loop {
        if walked >= max_blocks {
            return Err(BlockError::ExcessiveBlocks(walked));
        }
        walked += 1;

        let abs = initial_pos
            .checked_add(cur_rel as usize)
            .ok_or(BlockError::InvalidNextHead(cur_rel))?;

        let header = parse_block_header_at(bytes, abs, chunk_bytes, encrypted)?;

        // Minimal sanity: data must exist (at least c_len bytes) after header (+ blocksalt if encrypted).
        let data_start = abs
            + header_len
            + if encrypted { SALT_LEN } else { 0 };
        let data_end = data_start
            .checked_add(header.compressed_len as usize)
            .ok_or(BlockError::InvalidNextHead(header.compressed_len))?;
        if bytes.len() < data_end {
            return Err(BlockError::TooShort {
                needed: data_end,
                available: bytes.len(),
            });
        }

        if let Some((prev_rel, prev)) = out.last() {
            let mut prev_min_next = *prev_rel;
            prev_min_next = prev_min_next
                .checked_add(header_len as u64)
                .ok_or(BlockError::InvalidNextHead(*prev_rel))?;
            if encrypted {
                prev_min_next = prev_min_next
                    .checked_add(SALT_LEN as u64)
                    .ok_or(BlockError::InvalidNextHead(*prev_rel))?;
            }
            prev_min_next = prev_min_next
                .checked_add(prev.compressed_len)
                .ok_or(BlockError::InvalidNextHead(*prev_rel))?;
            if cur_rel < prev_min_next {
                return Err(BlockError::InvalidNextHead(cur_rel));
            }
        }

        out.push((cur_rel, header));

        if out.last().unwrap().1.next_head == 0 {
            break;
        }
        if out.last().unwrap().1.next_head <= cur_rel {
            return Err(BlockError::InvalidNextHead(out.last().unwrap().1.next_head));
        }
        cur_rel = out.last().unwrap().1.next_head;
    }

    Ok(out)
}

fn parse_filter(byte: u8, minor: u8) -> FilterSpec {
    if byte == 0 {
        return FilterSpec::None;
    }

    if minor >= 13 {
        if byte >= 128 {
            let offset = byte - 128;
            return FilterSpec::Delta { offset };
        }
        return match byte {
            1 => FilterSpec::Bcj(BcjFilter::X86),
            2 => FilterSpec::Bcj(BcjFilter::Arm),
            3 => FilterSpec::Bcj(BcjFilter::ArmThumb),
            4 => FilterSpec::Bcj(BcjFilter::Arm64),
            5 => FilterSpec::Bcj(BcjFilter::Ppc),
            6 => FilterSpec::Bcj(BcjFilter::Sparc),
            7 => FilterSpec::Bcj(BcjFilter::Ia64),
            8 => FilterSpec::Bcj(BcjFilter::RiscV),
            other => FilterSpec::Unknown(other),
        };
    }

    match byte {
        1 => FilterSpec::Bcj(BcjFilter::X86),
        2 => FilterSpec::Bcj(BcjFilter::Arm),
        3 => FilterSpec::Bcj(BcjFilter::ArmThumb),
        4 => FilterSpec::Bcj(BcjFilter::Ppc),
        5 => FilterSpec::Bcj(BcjFilter::Sparc),
        6 => FilterSpec::Bcj(BcjFilter::Ia64),
        7 => FilterSpec::Delta { offset: 0 },
        other => FilterSpec::Unknown(other),
    }
}

fn parse_compression(ctype: u8, prop: u8) -> (CompressionType, BackendProps) {
    match ctype {
        0 => (CompressionType::None, BackendProps::None),
        1 => (
            CompressionType::Lzma,
            BackendProps::Lzma { dict_prop: prop },
        ),
        2 => (
            CompressionType::Zpaq,
            BackendProps::Zpaq {
                level: prop >> 4,
                block_size: prop & 0x0f,
            },
        ),
        3 => (
            CompressionType::Bzip3,
            BackendProps::Bzip3 {
                block_size_code: prop & 0x0f,
            },
        ),
        _ if (ctype & 0x0f) == 4 => (
            CompressionType::Zstd {
                strategy: ctype >> 4,
            },
            BackendProps::Zstd { level: prop },
        ),
        other => (CompressionType::Unknown(other), BackendProps::None),
    }
}

fn hash_len(hash: HashKind) -> Option<usize> {
    match hash {
        HashKind::Crc => None,
        HashKind::Md5 => Some(16),
        HashKind::Ripemd => Some(20),
        HashKind::Sha256 => Some(32),
        HashKind::Sha384 => Some(48),
        HashKind::Sha512 => Some(64),
        HashKind::Sha3_256 => Some(32),
        HashKind::Sha3_512 => Some(64),
        HashKind::Shake128_16 => Some(16),
        HashKind::Shake128_32 => Some(32),
        HashKind::Shake128_64 => Some(64),
        HashKind::Shake256_16 => Some(16),
        HashKind::Shake256_32 => Some(32),
        HashKind::Shake256_64 => Some(64),
        HashKind::Unknown(_) => None,
    }
}

fn read_var_le(bytes: &[u8], offset: usize, len: usize) -> Result<u64, RcdError> {
    let needed = offset + len;
    if bytes.len() < needed {
        return Err(RcdError::TooShort {
            needed,
            available: bytes.len(),
        });
    }
    let mut buf = [0u8; 8];
    buf[..len].copy_from_slice(&bytes[offset..offset + len]);
    Ok(u64::from_le_bytes(buf))
}

fn read_var_le_block(bytes: &[u8], offset: usize, len: usize) -> Result<u64, BlockError> {
    let needed = offset + len;
    if bytes.len() < needed {
        return Err(BlockError::TooShort {
            needed,
            available: bytes.len(),
        });
    }
    let mut buf = [0u8; 8];
    buf[..len].copy_from_slice(&bytes[offset..offset + len]);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_magic_v14_lzma() {
        let mut magic = [0u8; MAGIC_LEN_V11];
        magic[0..4].copy_from_slice(b"LRZI");
        magic[4] = 0;
        magic[5] = 14;
        magic[6..14].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
        magic[14] = 1;
        magic[15] = 0;
        magic[16] = 0;
        magic[17] = 1;
        magic[18] = 0x2d;
        magic[19] = 0x79;
        magic[20] = 5;

        let parsed = MagicHeader::parse(&magic).expect("parse magic");
        assert_eq!(parsed.major, 0);
        assert_eq!(parsed.minor, 14);
        assert_eq!(parsed.expected_size, Some(0x1122334455667788));
        assert_eq!(parsed.hash, HashKind::Md5);
        assert_eq!(parsed.compression, CompressionType::Lzma);
        assert_eq!(parsed.backend_props, BackendProps::Lzma { dict_prop: 0x2d });
        assert_eq!(parsed.levels, CompressionLevels { rzip: 7, lrzip: 9 });
        assert_eq!(parsed.comment_len, 5);
    }

    #[test]
    fn parse_magic_zstd_strategy() {
        let mut magic = [0u8; MAGIC_LEN_V11];
        magic[0..4].copy_from_slice(b"LRZI");
        magic[4] = 0;
        magic[5] = 12;
        magic[6..14].copy_from_slice(&0u64.to_le_bytes());
        magic[17] = (3 << 4) | 4;
        magic[18] = 10;

        let parsed = MagicHeader::parse(&magic).expect("parse magic");
        assert_eq!(parsed.compression, CompressionType::Zstd { strategy: 3 });
        assert_eq!(parsed.backend_props, BackendProps::Zstd { level: 10 });
    }

    #[test]
    fn parse_rcd_unencrypted_two_streams() {
        let mut data = Vec::new();
        data.push(2);
        data.push(1);
        data.extend_from_slice(&0x1234u16.to_le_bytes());

        data.push(1);
        data.extend_from_slice(&0x0102u16.to_le_bytes());
        data.extend_from_slice(&0x0304u16.to_le_bytes());
        data.extend_from_slice(&0x0506u16.to_le_bytes());

        data.push(2);
        data.extend_from_slice(&0x1112u16.to_le_bytes());
        data.extend_from_slice(&0x1314u16.to_le_bytes());
        data.extend_from_slice(&0x1516u16.to_le_bytes());

        let (rcd, consumed) = parse_rcd_header(&data, 0, false, 2).expect("rcd");
        assert_eq!(consumed, data.len());
        assert_eq!(rcd.chunk_bytes, 2);
        assert!(rcd.is_last_chunk);
        assert_eq!(rcd.chunk_size, Some(0x1234));
        assert_eq!(rcd.streams.len(), 2);
        assert_eq!(rcd.streams[0].ctype, 1);
        assert_eq!(rcd.streams[0].compressed_len, 0x0102);
        assert_eq!(rcd.streams[0].uncompressed_len, 0x0304);
        assert_eq!(rcd.streams[0].next_head, 0x0506);
        assert_eq!(rcd.streams[1].ctype, 2);
        assert_eq!(rcd.streams[1].compressed_len, 0x1112);
        assert_eq!(rcd.streams[1].uncompressed_len, 0x1314);
        assert_eq!(rcd.streams[1].next_head, 0x1516);
    }

    #[test]
    fn parse_rcd_encrypted_two_streams() {
        let mut data = Vec::new();
        data.push(4);
        data.push(0);

        let salt_a = [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        data.extend_from_slice(&salt_a);
        data.push(1);
        data.extend_from_slice(&0x0102030405060708u64.to_le_bytes());
        data.extend_from_slice(&0x1112131415161718u64.to_le_bytes());
        data.extend_from_slice(&0x2122232425262728u64.to_le_bytes());

        let salt_b = [0x20u8, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27];
        data.extend_from_slice(&salt_b);
        data.push(2);
        data.extend_from_slice(&0x3132333435363738u64.to_le_bytes());
        data.extend_from_slice(&0x4142434445464748u64.to_le_bytes());
        data.extend_from_slice(&0x5152535455565758u64.to_le_bytes());

        let (rcd, consumed) = parse_rcd_header(&data, 0, true, 2).expect("rcd");
        assert_eq!(consumed, data.len());
        assert_eq!(rcd.chunk_bytes, 4);
        assert!(!rcd.is_last_chunk);
        assert_eq!(rcd.chunk_size, None);
        assert_eq!(rcd.streams.len(), 2);
        assert_eq!(rcd.streams[0].header_salt, Some(salt_a));
        assert_eq!(rcd.streams[0].ctype, 1);
        assert_eq!(rcd.streams[0].compressed_len, 0x0102030405060708);
        assert_eq!(rcd.streams[0].uncompressed_len, 0x1112131415161718);
        assert_eq!(rcd.streams[0].next_head, 0x2122232425262728);
        assert_eq!(rcd.streams[1].header_salt, Some(salt_b));
        assert_eq!(rcd.streams[1].ctype, 2);
        assert_eq!(rcd.streams[1].compressed_len, 0x3132333435363738);
        assert_eq!(rcd.streams[1].uncompressed_len, 0x4142434445464748);
        assert_eq!(rcd.streams[1].next_head, 0x5152535455565758);
    }

    #[test]
    fn integrity_layout_hash_lengths() {
        assert_eq!(
            IntegrityLayout::from_hash(HashKind::Crc),
            IntegrityLayout {
                crc32_len: 4,
                file_hash_len: None
            }
        );
        assert_eq!(
            IntegrityLayout::from_hash(HashKind::Md5),
            IntegrityLayout {
                crc32_len: 4,
                file_hash_len: Some(16)
            }
        );
        assert_eq!(
            IntegrityLayout::from_hash(HashKind::Sha512),
            IntegrityLayout {
                crc32_len: 4,
                file_hash_len: Some(64)
            }
        );
    }
}

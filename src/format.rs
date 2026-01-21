use thiserror::Error;

pub const MAGIC_LEN_V11: usize = 21;

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
}

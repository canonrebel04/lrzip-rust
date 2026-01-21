use std::path::Path;

use lrzip_rust::format::{parse_rcd_header, MagicHeader, MAGIC_LEN_V11};
use lrzip_rust::format::walk_stream_blocks;

#[test]
fn parse_fixture_headers() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("baritone.tar.lrz");
    let data = std::fs::read(&fixture).expect("read fixture");
    assert!(data.len() >= MAGIC_LEN_V11);

    let magic = MagicHeader::parse(&data[..MAGIC_LEN_V11]).expect("parse magic");
    let header_end = MAGIC_LEN_V11 + magic.comment_len as usize;
    assert!(data.len() >= header_end);

    let encrypted = magic.encryption.is_some();
    let _rcd = parse_rcd_header(&data, header_end, encrypted, 2).expect("parse rcd");
}

#[test]
fn walk_fixture_stream_block_headers() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("baritone.tar.lrz");
    let data = std::fs::read(&fixture).expect("read fixture");
    let magic = MagicHeader::parse(&data[..MAGIC_LEN_V11]).expect("parse magic");
    let header_end = MAGIC_LEN_V11 + magic.comment_len as usize;
    let encrypted = magic.encryption.is_some();

    // Walk both stream header chains (NUM_STREAMS = 2 in lrzip-next).
    for stream in 0..2 {
        let blocks = walk_stream_blocks(&data, header_end, stream, 2, encrypted, 1_000_000)
            .expect("walk blocks");
        assert!(!blocks.is_empty());
    }
}

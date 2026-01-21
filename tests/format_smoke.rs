use std::path::Path;

use lrzip_rust::format::{parse_rcd_header, MagicHeader, MAGIC_LEN_V11};

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

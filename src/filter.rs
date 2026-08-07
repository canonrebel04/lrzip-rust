//! x86 BCJ branch converter — reversible transform for x86 code.
//!
//! Ported 1:1 from liblzma's `src/liblzma/simple/x86.c` (0BSD, Igor Pavlov /
//! Lasse Collin) — the same implementation python's `lzma.FILTER_X86` uses,
//! which lets us verify byte-for-byte against the reference.
//!
//! Makes call/jmp (0xE8/0xE9) targets position-independent:
//!   encode: dest = src + (now_pos + pos + 5)
//!   decode: dest = src - (now_pos + pos + 5)
//! The stored high byte encodes dest's bit 24 as its sign (0x00/0xFF), and
//! the `prev_mask` loop corrects overlapping/adjacent matches so the
//! transform is exactly invertible for every candidate.
//!
//! Whole-file use: single call with now_pos = 0, prev_mask = 0,
//! prev_pos = -5 (fresh state, exactly like lzma_bcj_x86_encode).

const MASK_TO_BIT_NUMBER: [u32; 5] = [0, 1, 2, 2, 3];

#[inline(always)]
fn test86_msbyte(b: u8) -> bool {
    b == 0 || b == 0xFF
}

/// Apply the x86 BCJ transform to `data` in place.
/// `encoding = true`  -> make call/jmp targets position-independent
/// `encoding = false` -> exact inverse
pub fn x86_convert(data: &mut [u8], encoding: bool) {
    let mut prev_mask: u32 = 0;
    let mut prev_pos: i64 = -5;
    let size = data.len();
    if size < 5 {
        return;
    }
    let now_pos: u32 = 0;
    let limit = size - 5;
    let mut buffer_pos = 0usize;

    while buffer_pos <= limit {
        let b = data[buffer_pos];
        if b != 0xE8 && b != 0xE9 {
            buffer_pos += 1;
            continue;
        }

        let offset = (now_pos as i64) + (buffer_pos as i64) - prev_pos;
        prev_pos = (now_pos as i64) + (buffer_pos as i64);

        if offset > 5 {
            prev_mask = 0;
        } else {
            for _ in 0..offset {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }

        let b = data[buffer_pos + 4];
        if test86_msbyte(b) && (prev_mask >> 1) <= 4 && (prev_mask >> 1) != 3 {
            let src = ((b as u32) << 24)
                | ((data[buffer_pos + 3] as u32) << 16)
                | ((data[buffer_pos + 2] as u32) << 8)
                | (data[buffer_pos + 1] as u32);
            let mut src = src;
            let mut dest;
            loop {
                let c = now_pos.wrapping_add(buffer_pos as u32).wrapping_add(5);
                dest = if encoding {
                    src.wrapping_add(c)
                } else {
                    src.wrapping_sub(c)
                };
                if prev_mask == 0 {
                    break;
                }
                let i = MASK_TO_BIT_NUMBER[(prev_mask >> 1) as usize];
                let bb = ((dest >> (24 - i * 8)) & 0xFF) as u8;
                if !test86_msbyte(bb) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - i * 8)) - 1);
            }

            data[buffer_pos + 4] = if ((dest >> 24) & 1) == 1 { 0xFF } else { 0x00 };
            data[buffer_pos + 3] = (dest >> 16) as u8;
            data[buffer_pos + 2] = (dest >> 8) as u8;
            data[buffer_pos + 1] = dest as u8;
            buffer_pos += 5;
            prev_mask = 0;
        } else {
            buffer_pos += 1;
            prev_mask |= 1;
            if test86_msbyte(b) {
                prev_mask |= 0x10;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &mut [u8]) -> bool {
        let original = data.to_vec();
        x86_convert(data, true);
        x86_convert(data, false);
        data == original.as_slice()
    }

    #[test]
    fn roundtrip_empty_and_small() {
        let mut empty: Vec<u8> = vec![];
        x86_convert(&mut empty, true);
        x86_convert(&mut empty, false);

        for len in 0..8 {
            let mut d = vec![0xE8u8; len];
            let orig = d.clone();
            x86_convert(&mut d, true);
            x86_convert(&mut d, false);
            assert_eq!(d, orig, "len {}", len);
        }
    }

    #[test]
    fn roundtrip_random_fuzz() {
        let mut seed: u64 = 0x9E3779B97F4A7C15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for case in 0..10000 {
            let len = (rnd() % 16384) as usize;
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                let r = rnd();
                let b = match r % 16 {
                    0..=1 => 0xE8u8,
                    2 => 0xE9,
                    3 => 0x00,
                    4 => 0xFF,
                    _ => (r >> 8) as u8,
                };
                data.push(b);
            }
            assert!(roundtrip(&mut data), "fuzz case {} (len {})", case, len);
        }
    }

    #[test]
    fn roundtrip_realistic_x86() {
        let mut code = Vec::new();
        for i in 0..2000u32 {
            code.extend_from_slice(&[0xB8, (i & 0xFF) as u8, (i >> 8) as u8, 0, 0]);
            code.extend_from_slice(&[0xE8, 0x10, 0x00, 0x00, 0x00]);
            code.extend_from_slice(&[0x85, 0xC0, 0x74, 0xFB]);
            code.extend_from_slice(&[0xE9, 0x00, 0x01, 0x00, 0x00]);
        }
        assert!(roundtrip(&mut code));
        let mut a = code.clone();
        x86_convert(&mut a, true);
        assert_ne!(a, code, "transform should change x86 call/jmp targets");
    }
}

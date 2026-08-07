use libc::{c_int, c_long, c_uchar};

pub type ProgressCallback = extern "C" fn(pct: c_int, thread: c_long, userdata: *mut std::ffi::c_void);

unsafe extern "C" {
    pub fn zpaq_compress(
        c_buf: *mut c_uchar,
        c_len: *mut i64,
        s_buf: *const c_uchar,
        s_len: i64,
        level: c_int,
        callback: Option<ProgressCallback>,
        userdata: *mut std::ffi::c_void,
        thread: c_long,
    );

    pub fn zpaq_compress_method(
        c_buf: *mut c_uchar,
        c_len: *mut i64,
        s_buf: *const c_uchar,
        s_len: i64,
        method: *const std::ffi::c_char,
        callback: Option<ProgressCallback>,
        userdata: *mut std::ffi::c_void,
        thread: c_long,
    );

    pub fn zpaq_decompress(
        s_buf: *mut c_uchar,
        d_len: *mut i64,
        c_buf: *const c_uchar,
        c_len: i64,
        callback: Option<ProgressCallback>,
        userdata: *mut std::ffi::c_void,
        thread: c_long,
    );
}

pub fn compress(
    input: &[u8],
    level: u8,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Vec<u8> {
    let mut out = vec![0u8; input.len() * 2 + 1024];
    let mut out_len: i64 = 0;

    unsafe {
        zpaq_compress(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            level as c_int,
            callback,
            userdata,
            0,
        );
    }

    out.truncate(out_len as usize);
    out
}

/// Compress with an arbitrary zpaq method string (level digit 0-9 or an
/// advanced config). See libzpaq's method syntax; the level digits 1-5 are
/// the built-ins and 6-9 expand to the level-5 model.
pub fn compress_method(
    input: &[u8],
    method: &str,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Vec<u8> {
    let mut out = vec![0u8; input.len() * 2 + 1024];
    let mut out_len: i64 = 0;
    let method_c = std::ffi::CString::new(method).expect("method contains NUL byte");

    unsafe {
        zpaq_compress_method(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            method_c.as_ptr(),
            callback,
            userdata,
            0,
        );
    }

    out.truncate(out_len as usize);
    out
}

pub fn decompress(
    input: &[u8],
    expected_size: usize,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Vec<u8> {
    let cap = (expected_size * 2).max(65536);
    let mut out = vec![0u8; cap];
    let mut out_len: i64 = 0;

    unsafe {
        zpaq_decompress(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            callback,
            userdata,
            0,
        );
    }

    out.truncate(out_len as usize);
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zpaq_roundtrip() {
        let data = b"Hello world! This is a test of ZPAQ compression in lrzip-rust.";
        let compressed = compress(data, 3, None, std::ptr::null_mut());
        assert!(!compressed.is_empty());
        let decompressed = decompress(&compressed, data.len(), None, std::ptr::null_mut());
        assert_eq!(data, &decompressed[..]);
    }


}


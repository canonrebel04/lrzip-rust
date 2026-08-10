use libc::{c_int, c_long, c_uchar};

pub mod lzo;

pub type ProgressCallback = extern "C" fn(pct: c_int, thread: c_long, userdata: *mut std::ffi::c_void);

// All shims return 0 on success, non-zero on error. libzpaq signals errors by
// throwing C++ exceptions; the shims catch them at the boundary (see
// libzpaq.cpp) and print the detail to stderr, so a non-zero status here maps
// to a clean Rust error instead of "Rust cannot catch foreign exceptions".

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
    ) -> c_int;

    pub fn zpaq_compress_method(
        c_buf: *mut c_uchar,
        c_len: *mut i64,
        s_buf: *const c_uchar,
        s_len: i64,
        method: *const std::ffi::c_char,
        callback: Option<ProgressCallback>,
        userdata: *mut std::ffi::c_void,
        thread: c_long,
    ) -> c_int;

    pub fn zpaq_compress_block(
        c_buf: *mut c_uchar,
        c_len: *mut i64,
        s_buf: *const c_uchar,
        s_len: i64,
        level: c_int,
        block_mb: c_int,
        callback: Option<ProgressCallback>,
        userdata: *mut std::ffi::c_void,
        thread: c_long,
    ) -> c_int;

    pub fn zpaq_decompress(
        s_buf: *mut c_uchar,
        d_len: *mut i64,
        c_buf: *const c_uchar,
        c_len: i64,
        callback: Option<ProgressCallback>,
        userdata: *mut std::ffi::c_void,
        thread: c_long,
    ) -> c_int;
}

/// Error returned when a zpaq call fails. libzpaq prints the detailed
/// message ("libzpaq error: ...") to stderr before throwing, so this type
/// carries only a summary; it implements std::error::Error so `?` converts
/// into anyhow-style errors at the call sites.
#[derive(Debug)]
pub struct ZpaqError(pub String);

impl std::fmt::Display for ZpaqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ZpaqError {}

fn zpaq_err(what: &str) -> ZpaqError {
    ZpaqError(format!(
        "zpaq {} failed (see 'libzpaq error:' on stderr)",
        what
    ))
}

pub fn compress(
    input: &[u8],
    level: u8,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Result<Vec<u8>, ZpaqError> {
    let mut out = vec![0u8; input.len() * 2 + 1024];
    let mut out_len: i64 = 0;

    let rc = unsafe {
        zpaq_compress(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            level as c_int,
            callback,
            userdata,
            0,
        )
    };
    if rc != 0 {
        return Err(zpaq_err("compression"));
    }

    out.truncate(out_len as usize);
    Ok(out)
}

/// Compress with an arbitrary zpaq method string (level digit 0-9 or an
/// advanced config). See libzpaq's method syntax; the level digits 1-5 are
/// the built-ins and 6-9 expand to the level-5 model.
pub fn compress_method(
    input: &[u8],
    method: &str,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Result<Vec<u8>, ZpaqError> {
    let mut out = vec![0u8; input.len() * 2 + 1024];
    let mut out_len: i64 = 0;
    let method_c = std::ffi::CString::new(method).expect("method contains NUL byte");

    let rc = unsafe {
        zpaq_compress_method(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            method_c.as_ptr(),
            callback,
            userdata,
            0,
        )
    };
    if rc != 0 {
        return Err(zpaq_err("compression"));
    }

    out.truncate(out_len as usize);
    Ok(out)
}

/// Compress at a level digit, splitting the input into blocks of `block_mb`
/// MiB (C++ lrzip's -zpaqbs). Each block is an independent zpaq segment, so
/// the model sizes scale with the block size; decompression is unchanged.
pub fn compress_block(
    input: &[u8],
    level: u8,
    block_mb: u32,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Result<Vec<u8>, ZpaqError> {
    let mut out = vec![0u8; input.len() * 2 + 1024];
    let mut out_len: i64 = 0;

    let rc = unsafe {
        zpaq_compress_block(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            level as c_int,
            block_mb as c_int,
            callback,
            userdata,
            0,
        )
    };
    if rc != 0 {
        return Err(zpaq_err("compression"));
    }

    out.truncate(out_len as usize);
    Ok(out)
}

pub fn decompress(
    input: &[u8],
    expected_size: usize,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Result<Vec<u8>, ZpaqError> {
    let cap = (expected_size * 2).max(65536);
    let mut out = vec![0u8; cap];
    let mut out_len: i64 = 0;

    let rc = unsafe {
        zpaq_decompress(
            out.as_mut_ptr(),
            &mut out_len,
            input.as_ptr(),
            input.len() as i64,
            callback,
            userdata,
            0,
        )
    };
    if rc != 0 {
        return Err(zpaq_err("decompression"));
    }

    out.truncate(out_len as usize);
    Ok(out)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zpaq_roundtrip() {
        let data = b"Hello world! This is a test of ZPAQ compression in lrzip-rust.";
        let compressed = compress(data, 3, None, std::ptr::null_mut()).unwrap();
        assert!(!compressed.is_empty());
        let decompressed = decompress(&compressed, data.len(), None, std::ptr::null_mut()).unwrap();
        assert_eq!(data, &decompressed[..]);
    }

    #[test]
    fn test_zpaq_error_does_not_abort() {
        // Regression: libzpaq reports errors by throwing C++ exceptions; the
        // FFI shims must catch them and return a status, otherwise the
        // process aborts with "Rust cannot catch foreign exceptions" (the
        // 58GB-archive "Out of memory" crash). Truncating a valid archive
        // mid-stream makes libzpaq throw ("unexpected end of file") — assert
        // we get Err, not an abort.
        let data = b"Hello world! This is a test of ZPAQ compression in lrzip-rust.";
        let compressed = compress(data, 3, None, std::ptr::null_mut()).unwrap();
        assert!(compressed.len() > 16, "archive implausibly small");
        let truncated = &compressed[..compressed.len() / 2];
        let res = decompress(truncated, data.len(), None, std::ptr::null_mut());
        assert!(res.is_err(), "expected Err from truncated archive, got {:?}", res);
        let err = res.unwrap_err();
        assert!(err.0.contains("zpaq decompression failed"), "unexpected error: {}", err.0);
    }


}


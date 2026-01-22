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

pub fn decompress(
    input: &[u8],
    expected_size: usize,
    callback: Option<ProgressCallback>,
    userdata: *mut std::ffi::c_void,
) -> Vec<u8> {
    let mut out = vec![0u8; expected_size];
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

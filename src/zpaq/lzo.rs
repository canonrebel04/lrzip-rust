//! Vendored LZO 2.10 FFI (lzo1x subset: 1x1 + 1x999 compress, safe
//! decompress). Built from src/zpaq/lzo/ by build.rs; replaces the
//! cmake-dependent lzo-sys crate and the 1x1-only minilzo-rs.

use libc::{c_int, c_uint, c_void};

pub const LZO_E_OK: c_int = 0;
pub const LZO_VERSION: c_uint = 0x20a0; // 2.10

/// LZO's public `lzo_init()` is a macro expanding to `__lzo_init_v2` with
/// version + type-size checks; replicate it here (same as lzo-sys does).
pub unsafe fn lzo_init() -> c_int {
    unsafe {
        __lzo_init_v2(
            LZO_VERSION,
            std::mem::size_of::<i16>() as c_int,
            std::mem::size_of::<c_int>() as c_int,
            std::mem::size_of::<libc::c_long>() as c_int,
            std::mem::size_of::<u32>() as c_int,
            std::mem::size_of::<usize>() as c_int,
            std::mem::size_of::<*mut u8>() as c_int,
            std::mem::size_of::<*mut libc::c_char>() as c_int,
            std::mem::size_of::<*mut c_void>() as c_int,
            std::mem::size_of::<usize>() as c_int, // lzo_callback_t is opaque/empty
        )
    }
}

/// Work memory sizes (bytes) from lzo1x.h — the compressors require them
/// aligned; we allocate u64 buffers.
pub const LZO1X_1_MEM_COMPRESS: usize = 16384 * std::mem::size_of::<usize>();
pub const LZO1X_999_MEM_COMPRESS: usize = 14 * 16384 * 2; // 14 * 16384 * sizeof(short)
pub const LZO1X_MEM_DECOMPRESS: usize = 0;

unsafe extern "C" {
    fn __lzo_init_v2(
        v: c_uint,
        s1: c_int,
        s2: c_int,
        s3: c_int,
        s4: c_int,
        s5: c_int,
        s6: c_int,
        s7: c_int,
        s8: c_int,
        s9: c_int,
    ) -> c_int;
    pub fn lzo1x_1_compress(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
        wrkmem: *mut c_void,
    ) -> c_int;
    pub fn lzo1x_999_compress(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
        wrkmem: *mut c_void,
    ) -> c_int;
    pub fn lzo1x_decompress_safe(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
        wrkmem: *mut c_void,
    ) -> c_int;
}

fn main() {
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.cpp");
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.h");
    println!("cargo:rerun-if-env-changed=LRZIP_NOJIT");
    println!("cargo:rerun-if-env-changed=LRZIP_JIT");
    println!("cargo:rerun-if-env-changed=LRZIP_NOOPENMP");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/zpaq/libzpaq.cpp")
        .warnings(false)
        .extra_warnings(false)
        .flag_if_supported("-O3")
        .flag_if_supported("-mavx2")
        .flag_if_supported("-mpclmul")
        .flag_if_supported("-msse4.2")
        .flag_if_supported("/arch:AVX2");

    // Parallel divsufsort (suffix-array construction for -L2/-L3 LZ77-SA).
    // The vendored libdivsufsort has #ifdef _OPENMP parallel sssort regions;
    // they activate with -fopenmp (GCC/Clang) or /openmp (MSVC). The suffix
    // array is a deterministic sort result regardless of thread count, so
    // archives stay byte-identical. Set LRZIP_NOOPENMP=1 to force serial.
    let openmp = std::env::var("LRZIP_NOOPENMP").is_err();
    if openmp {
        build.flag_if_supported("-fopenmp").flag_if_supported("/openmp");
    }

    // ZPAQL JIT is disabled by default. libzpaq's JIT miscompiles the L3
    // compression HCOMP program (SIGILL at -z -L3 compress; L1/L2 and
    // decompression work). Both upstream projects force the interpreter:
    // lrzip-next configure.ac:194 "must use -DNOJIT for compiling zpaq"
    // and the zpaq fork's own Makefile uses -DNOJIT. This is the parity
    // configuration. Set LRZIP_JIT=1 to opt into JIT (for L1/L2 or after
    // a fork-level JIT assembler fix), LRZIP_NOJIT=1 to force interpreter.
    let force_jit = std::env::var("LRZIP_JIT").is_ok();
    let force_nojit = std::env::var("LRZIP_NOJIT").is_ok();
    if force_nojit || !force_jit {
        build.define("NOJIT", None);
    }

    build.compile("zpaq");

    // GCC/Clang's -fopenmp does not propagate the OpenMP runtime to the
    // final Rust link (MSVC's /openmp auto-links vcomp via the object).
    let target = std::env::var("TARGET").unwrap_or_default();
    if openmp && !target.contains("windows-msvc") {
        println!("cargo:rustc-link-lib=gomp");
    }

    // Vendored LZO 2.10 (lzo1x subset: 1x1 + 1x999 compress, safe
    // decompress) — replaces lzo-sys/minilzo-rs so no cmake is needed.
    // LZO is GPL-2+ with the static-linking exception (same surface as the
    // lzo-sys crate; lrzip is GPL-3).
    println!("cargo:rerun-if-changed=src/zpaq/lzo/src");
    println!("cargo:rerun-if-changed=src/zpaq/lzo/include");
    let mut lzo = cc::Build::new();
    lzo.cpp(false)
        .files([
            "src/zpaq/lzo/src/lzo_init.c",
            "src/zpaq/lzo/src/lzo_crc.c",
            "src/zpaq/lzo/src/lzo_ptr.c",
            "src/zpaq/lzo/src/lzo_str.c",
            "src/zpaq/lzo/src/lzo_util.c",
            "src/zpaq/lzo/src/lzo1x_1.c",
            "src/zpaq/lzo/src/lzo1x_9x.c",
            "src/zpaq/lzo/src/lzo1x_d2.c",
        ])
        .include("src/zpaq/lzo/src")
        .include("src/zpaq/lzo/include")
        .warnings(false)
        .extra_warnings(false)
        .flag_if_supported("-O2");
    lzo.compile("lzo_vendored");
}


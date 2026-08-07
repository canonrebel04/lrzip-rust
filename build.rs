fn main() {
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.cpp");
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.h");
    println!("cargo:rerun-if-env-changed=LRZIP_NOJIT");

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



}


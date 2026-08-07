fn main() {
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.cpp");
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.h");

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
        .flag_if_supported("/arch:AVX2")
        .define("NOJIT", None)
        .compile("zpaq");



}


fn main() {
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.cpp");
    println!("cargo:rerun-if-changed=src/zpaq/libzpaq.h");

    cc::Build::new()
        .cpp(true)
        .file("src/zpaq/libzpaq.cpp")
        .warnings(false)
        .extra_warnings(false)
        .flag_if_supported("-O3")
        // .flag_if_supported("-DNOJIT") // Easier for portability for now
        .compile("zpaq");
}

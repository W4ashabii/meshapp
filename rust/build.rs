fn main() {
    // Tell Cargo to link against the standard C library
    println!("cargo:rustc-link-lib=dylib=c");
}



// Builds the OpenSSL shim against Homebrew's OpenSSL 3, the build used for the earlier
// external baseline. Override the prefix with OPENSSL_PREFIX.
fn main() {
    let prefix = std::env::var("OPENSSL_PREFIX").unwrap_or_else(|_| "/opt/homebrew/opt/openssl@3".into());
    println!("cargo:rerun-if-changed=src/openssl_shim.c");
    println!("cargo:rerun-if-env-changed=OPENSSL_PREFIX");
    cc::Build::new()
        .file("src/openssl_shim.c")
        .include(format!("{prefix}/include"))
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror")
        .compile("openssl_shim");
    println!("cargo:rustc-link-search=native={prefix}/lib");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{prefix}/lib");
}

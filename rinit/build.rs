fn main() {
    println!("cargo:rustc-link-search={}/extern-libs", env!("CARGO_MANIFEST_DIR"));
}

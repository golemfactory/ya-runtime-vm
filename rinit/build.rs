use std::process::Command;

fn main() {
    println!(
        "cargo:rustc-link-search={}/extern-libs",
        env!("CARGO_MANIFEST_DIR")
    );
    let status = Command::new("make")
        .args(&["extern-libs/libseccomp.a"])
        .status()
        .unwrap();
    if !status.success() {
        panic!("Error building libseccomp.a library");
    }
}

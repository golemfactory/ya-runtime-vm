fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_FEATURE_FREESTANDING").is_ok()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        for argument in ["-nostartfiles", "-static", "-no-pie"] {
            println!("cargo:rustc-link-arg-bin=ya-vm-guest-agent={argument}");
        }
    }
}

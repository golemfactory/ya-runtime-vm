use std::env;
use std::path::PathBuf;
use std::process::Command;

static RERUN_IF_CHANGED: &'static str = "cargo:rerun-if-changed";

fn main() {
    let root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let init_dir = root_dir.join("init-container").canonicalize().unwrap();

    Command::new("make")
        .current_dir(&init_dir)
        .status()
        .expect("error building init");

    let include_dir = init_dir.join("include");
    let src_dir = init_dir.join("src");

    println!(
        "{}",
        format!(
            r#"
        {rerun}={root}/Makefile
        {rerun}={include}/communication.h
        {rerun}={include}/cyclic_buffer.h
        {rerun}={include}/process_bookkeeping.h
        {rerun}={include}/proto.h
        {rerun}={src}/communication.c
        {rerun}={src}/cyclic_buffer.c
        {rerun}={src}/process_bookkeeping.c
        {rerun}={src}/init.c
        "#,
            rerun = RERUN_IF_CHANGED,
            root = init_dir.display(),
            include = include_dir.display(),
            src = src_dir.display(),
        )
    );
}

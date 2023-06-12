use anyhow::Context;
use std::env;
use std::ops::Not;
use std::path::PathBuf;
use std::process::Command;

static RERUN_IF_CHANGED: &str = "cargo:rerun-if-changed";

fn main() -> anyhow::Result<()> {
    // skip build for CI
    if env::var("CI").is_ok() {
        return Ok(());
    }

    let root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let init_dir = root_dir.join("init-container").canonicalize().unwrap();
    let include_dir = init_dir.join("include");
    let src_dir = init_dir.join("src");

    let make_result = Command::new("make")
        .current_dir(&init_dir)
        .status()
        .context("error building init")?;
    if make_result.success().not() {
        if let Some(code) = make_result.code() {
            anyhow::bail!("make failed with code {:?}", code)
        } else {
            anyhow::bail!("make failed")
        }
    }

    println!(
        r#"
    {rerun}={root}/Makefile
    {rerun}={include}/communication.h
    {rerun}={include}/cyclic_buffer.h
    {rerun}={include}/forward.h
    {rerun}={include}/network.h
    {rerun}={include}/process_bookkeeping.h
    {rerun}={include}/proto.h
    {rerun}={src}/communication.c
    {rerun}={src}/cyclic_buffer.c
    {rerun}={src}/forward.c
    {rerun}={src}/network.c
    {rerun}={src}/process_bookkeeping.c
    {rerun}={src}/init.c
    "#,
        rerun = RERUN_IF_CHANGED,
        root = init_dir.display(),
        include = include_dir.display(),
        src = src_dir.display(),
    );
    Ok(())
}

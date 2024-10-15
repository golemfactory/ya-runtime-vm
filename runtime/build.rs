use anyhow::Context;
use serde_json::{Map, Value};
use std::env;
use std::fs::File;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process::Command;

static RERUN_IF_CHANGED: &str = "cargo:rerun-if-changed";

fn make_init(root_dir: &Path) -> anyhow::Result<()> {
    // skip build for CI
    if env::var("CI").is_ok() {
        return Ok(());
    }

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

fn update_conf(root_dir: &Path, version: String) {
    let fname = root_dir.join("conf/ya-runtime-vm.json.in");
    let fin = File::open(fname).unwrap();
    let fname = root_dir.join("conf/ya-runtime-vm.json");
    let fout = File::create(fname).unwrap();

    let mut json: Vec<Map<String, Value>> = serde_json::from_reader(fin).unwrap();
    json[0].insert(String::from("version"), Value::from(version));
    serde_json::to_writer_pretty(fout, &json).unwrap();
}

fn main() -> anyhow::Result<()> {
    let root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let version = env::var("CARGO_PKG_VERSION").unwrap();

    make_init(&root_dir)?;
    update_conf(&root_dir, version);

    Ok(())
}

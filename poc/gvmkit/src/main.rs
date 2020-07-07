mod docker;
mod image_builder;
mod rwbuf;

use std::{env, path::Path};
use structopt::StructOpt;

const INTERNAL_LOG_LEVEL: &str = "hyper=warn,bollard=warn";
const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
// TODO: additional volumes
struct CmdArgs {
    #[structopt(short = "o", long = "output")]
    output: String,
    image_name: String, // positional
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut log_level = String::from(DEFAULT_LOG_LEVEL);
    if let Ok(level) = env::var(env_logger::DEFAULT_FILTER_ENV) {
        log_level = level;
    }

    env::set_var(
        env_logger::DEFAULT_FILTER_ENV,
        format!("{},{}", INTERNAL_LOG_LEVEL, log_level),
    );
    env_logger::init();

    let cmdargs = CmdArgs::from_args();
    image_builder::build_image(&cmdargs.image_name, Path::new(&cmdargs.output)).await?;
    Ok(())
}

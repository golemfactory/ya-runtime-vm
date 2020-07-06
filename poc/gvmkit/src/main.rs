mod docker;
mod image_builder;
mod rwbuf;
use std::env;
use structopt::StructOpt;

use crate::image_builder::ImageBuilder;

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
    match env::var(env_logger::DEFAULT_FILTER_ENV) {
        Err(_) => env::set_var(
            env_logger::DEFAULT_FILTER_ENV,
            format!("{},{}", INTERNAL_LOG_LEVEL, DEFAULT_LOG_LEVEL),
        ),
        Ok(var) => env::set_var(
            env_logger::DEFAULT_FILTER_ENV,
            format!("{},{}", var, INTERNAL_LOG_LEVEL),
        ),
    };
    env_logger::init();

    let cmdargs = CmdArgs::from_args();
    let mut img = ImageBuilder::new().await?;
    img.build(&cmdargs.image_name, &cmdargs.output).await?;
    Ok(())
}

mod docker;
mod image_builder;
mod progress;
mod rwbuf;
mod upload;

use std::{env, path::Path};
use structopt::StructOpt;

const INTERNAL_LOG_LEVEL: &str = "hyper=warn,bollard=warn";
const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
// TODO: additional volumes
struct CmdArgs {
    /// Output image name
    #[structopt(short, long)]
    output: String,
    /// Upload image to repository
    #[structopt(short, long)]
    push: bool,
    /// Input Docker image name
    image_name: String, // positional
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    let log_level = env::var(env_logger::DEFAULT_FILTER_ENV).unwrap_or(DEFAULT_LOG_LEVEL.into());
    let log_filter = format!("{},{}", INTERNAL_LOG_LEVEL, log_level);
    env::set_var(env_logger::DEFAULT_FILTER_ENV, log_filter);
    env_logger::init();

    let cmdargs = CmdArgs::from_args();

    crate::progress::set_total_steps(if cmdargs.push {
        image_builder::STEPS + upload::STEPS
    } else {
        image_builder::STEPS
    });

    image_builder::build_image(&cmdargs.image_name, Path::new(&cmdargs.output)).await?;
    if cmdargs.push {
        upload::upload_image(&cmdargs.output).await?;
    }

    Ok(())
}

mod docker;
mod image_builder;
mod rwbuf;

use structopt::StructOpt;

use crate::image_builder::ImageBuilder;

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
// TODO: additional volumes
struct CmdArgs {
    #[structopt(short = "o", long = "output")]
    output: String,
    image_name: String, // positional
}

// TODO: use logger
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmdargs = CmdArgs::from_args();
    let mut img = ImageBuilder::new().await?;
    img.build(&cmdargs.image_name, &cmdargs.output).await?;
    Ok(())
}

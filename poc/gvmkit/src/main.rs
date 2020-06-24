mod docker;
mod image_builder;
mod rwbuf;

use structopt::StructOpt;

use crate::image_builder::ImageBuilder;

#[derive(StructOpt)]
enum Commands {
    Build {
        #[structopt(short, long)]
        image_name: String,
    },
    Run {
        #[structopt(short = "e", long = "entrypoint")]
        entrypoint: String,
        args: Vec<String>,
    },
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct CmdArgs {
    #[structopt(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmdargs = CmdArgs::from_args();
    match cmdargs.command {
        Commands::Build { image_name } => {
            let mut img = ImageBuilder::new().await?;
            img.build(&image_name).await?;
        }

        Commands::Run { entrypoint, args } => {
            println!("Running: entrypoint {}, args {:?}", entrypoint, args);
        }
    };
    Ok(())
}

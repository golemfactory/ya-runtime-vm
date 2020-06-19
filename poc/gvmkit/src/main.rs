mod docker;
mod image;
mod rwbuf;

use bollard::service::ContainerConfig;
use bytes::Bytes;
use futures::executor::block_on;
use structopt::StructOpt;

use crate::docker::DockerInstance;
use crate::image::Image;

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

async fn repack_image(
    tar_bytes: Bytes,
    container_id: &str,
    config: &ContainerConfig,
) -> anyhow::Result<()> {
    let mut img = Image::from_bytes(&tar_bytes)?;

    let env = &config.env;
    let entrypoint = &config.entrypoint;
    let cmd = &config.cmd;
    let volumes = &config.volumes;
    dbg!(env, entrypoint, cmd, volumes);

    match env {
        // Vec<String>
        Some(val) => img.add_file(".env", val.join("\n").as_bytes())?,
        None => img.add_file(".env", &[])?,
    }

    match entrypoint {
        // Vec<String>
        Some(val) => img.add_file(".entrypoint", val.join("\n").as_bytes())?,
        None => img.add_file(".entrypoint", &[])?,
    }

    match cmd {
        // Vec<String>
        Some(val) => img.add_file(".cmd", val.join("\n").as_bytes())?,
        None => img.add_file(".cmd", &[])?,
    }

    match volumes {
        // HashMap<String, HashMap<(), (), RandomState>, RandomState>
        // TODO: test this for non-empty map
        Some(val) => img.add_file(
            ".vols",
            val.keys()
                .collect::<Vec<&String>>()
                .iter()
                .fold(String::new(), |mut result, element| {
                    result.push_str(element);
                    result
                })
                .as_bytes(),
        )?,
        None => img.add_file(".vols", &[])?,
    }

    img.finish()?;
    Ok(())
}

async fn build_image(image_name: &str) -> anyhow::Result<()> {
    println!("Building image from '{}'...", image_name);
    let mut docker = DockerInstance::new().await?;

    let cont_name = "gvmkit-cont";
    docker.create_container(image_name, cont_name).await?;

    let (hash, cfg) = docker.get_config(cont_name).await?;

    //let mut out_dir = String::from("out-");
    //out_dir.push_str(hash);
    //fs::create_dir_all(&out_dir)?;

    let tar_bytes = docker.export_container(cont_name).await?;
    repack_image(tar_bytes, &hash, &cfg).await?;

    //fs::remove_dir_all(out_dir)?;

    docker.remove_container(cont_name).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmdargs = CmdArgs::from_args();
    match cmdargs.command {
        Commands::Build { image_name } => {
            block_on(build_image(&image_name))?;
        }

        Commands::Run { entrypoint, args } => {
            println!("Running: entrypoint {}, args {:?}", entrypoint, args);
        }
    };
    Ok(())
}

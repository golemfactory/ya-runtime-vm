use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use structopt::StructOpt;

#[derive(StructOpt)]
enum Commands {
    Deploy {},
    Start {},
    Run {
        #[structopt(short = "e", long = "entrypoint")]
        entrypoint: String,
        args: Vec<String>,
    },
}

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
struct CmdArgs {
    #[structopt(short, long)]
    workdir: PathBuf,
    #[structopt(short, long)]
    task_package: PathBuf,
    #[structopt(subcommand)]
    command: Commands,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeployResult {
    pub valid: Result<String, String>,
}

fn main() -> anyhow::Result<()> {
    let cmdargs = CmdArgs::from_args();
    match cmdargs.command {
        Commands::Deploy {} => {
            let result = DeployResult {
                valid: Ok(format!("Not doing anything, but OK.")),
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Start {} => (),
        Commands::Run { entrypoint, args } => {
            let mut exe = cmdargs.workdir;
            exe.push("gvmkit");

            Command::new(exe)
                .arg("run")
                .arg(cmdargs.task_package)
                .arg(entrypoint)
                .args(args)
                .spawn()?
                .wait()?;
        }
    };
    Ok(())
}

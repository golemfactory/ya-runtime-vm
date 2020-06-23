use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::env;
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

fn get_gvmkit_path(current_exe: PathBuf) -> anyhow::Result<PathBuf> {
    let base_dir = current_exe
        .parent()
        .ok_or(anyhow!("exe path has no parent"))?;
    Ok(base_dir.join("poc/gvmkit"))
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
            Command::new(get_gvmkit_path(env::current_exe()?)?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_gvmkit_path_absolute() {
        let gvmkit_path = get_gvmkit_path(PathBuf::from("/foo/bar/ya-runtime-vm"));
        assert!(gvmkit_path.is_ok());
        assert_eq!(gvmkit_path.unwrap(), PathBuf::from("/foo/bar/poc/gvmkit"));
    }

    #[test]
    fn test_get_gvmkit_path_relative() {
        let gvmkit_path = get_gvmkit_path(PathBuf::from("./ya-runtime-vm"));
        assert!(gvmkit_path.is_ok());
        assert_eq!(gvmkit_path.unwrap(), PathBuf::from("./poc/gvmkit"));
    }
}

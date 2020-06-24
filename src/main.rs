use anyhow::anyhow;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::{env, fs, io, path::PathBuf, process::Command, str};
use structopt::StructOpt;
use uuid::Uuid;

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
    #[serde(default)]
    pub vols: Vec<ContainerVolume>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContainerVolume {
    pub name: String,
    pub path: String,
}

fn get_gvmkit_path(current_exe: PathBuf) -> anyhow::Result<PathBuf> {
    let base_dir = current_exe
        .parent()
        .ok_or(anyhow!("exe path has no parent"))?;
    Ok(base_dir.join("poc/gvmkit"))
}

fn get_volumes<Input: io::Read + io::Seek>(
    mut input: Input,
) -> anyhow::Result<Vec<ContainerVolume>> {
    let json_len = (|| -> anyhow::Result<u32> {
        input.seek(io::SeekFrom::End(-8))?;
        let mut buf = [0; 8];
        input.read_exact(&mut buf)?;
        debug!("raw json length: {:?}", buf);
        let buf_str = str::from_utf8(&buf)?;
        debug!("string json length: {:?}", buf_str);
        Ok(buf_str.parse()?)
    })()?;
    debug!("parsed json length: {:?}", json_len);
    let json = (|| -> anyhow::Result<serde_json::Value> {
        input.seek(io::SeekFrom::End(-1 * (json_len + 8) as i64))?;

        // use std::io::Read;
        // let mut buf = String::new();
        // input.take(json_len as u64).read_to_string(&mut buf)?;
        // debug!("read json: {:?}", buf);
        // Ok(serde_json::from_str(&buf)?)

        Ok(serde_json::from_reader(input.take(json_len as u64))?)
    })()?;
    let volumes = json
        .get("Volumes")
        .ok_or(anyhow!("Volumes key not found"))?;
    if volumes.is_null() {
        return Ok(Vec::new());
    }
    Ok(volumes
        .as_object()
        .ok_or(anyhow!("Volumes is not an object"))?
        .iter()
        .map(|(key, _value)| ContainerVolume {
            name: format!("vol-{}", Uuid::new_v4()),
            path: key.to_string(),
        })
        .collect())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cmdargs = CmdArgs::from_args();
    match cmdargs.command {
        Commands::Deploy {} => {
            let volumes = match get_volumes(fs::File::open(cmdargs.task_package)?) {
                Ok(volumes) => volumes,
                Err(err) => {
                    warn!("failed to get volumes: {}", err);
                    Vec::new()
                }
            };

            for vol in &volumes {
                fs::create_dir(cmdargs.workdir.join(&vol.name))?;
            }
            let result = DeployResult {
                valid: Ok("Ok".to_string()),
                vols: volumes,
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

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_get_gvmkit_path_absolute() -> anyhow::Result<()> {
        let gvmkit_path = get_gvmkit_path(PathBuf::from("/foo/bar/ya-runtime-vm"))?;
        assert_eq!(gvmkit_path, PathBuf::from("/foo/bar/poc/gvmkit"));
        Ok(())
    }

    #[test]
    fn test_get_gvmkit_path_relative() -> anyhow::Result<()> {
        let gvmkit_path = get_gvmkit_path(PathBuf::from("./ya-runtime-vm"))?;
        assert_eq!(gvmkit_path, PathBuf::from("./poc/gvmkit"));
        Ok(())
    }

    #[test]
    fn test_get_volumes() -> anyhow::Result<()> {
        init_logger();
        use std::collections::HashSet;
        let data = io::Cursor::new(b"abc{\"Volumes\":{\"/a\":{},\"/b\":{}}}00000029".to_vec());
        let volumes = get_volumes(data)?;

        // make sure names are unique
        assert_eq!(
            volumes
                .iter()
                .map(|v| v.name.as_ref())
                .collect::<HashSet<&str>>()
                .len(),
            2
        );

        let paths = volumes
            .iter()
            .map(|v| v.path.as_ref())
            .collect::<HashSet<_>>();
        println!("{:?}", paths);
        let expected_paths: HashSet<&str> = ["/a", "/b"].to_vec().into_iter().collect();
        assert_eq!(expected_paths, paths);

        Ok(())
    }

    #[test]
    fn test_get_volumes_garbage() {
        init_logger();
        let data = io::Cursor::new(b"aaoraskntr){uanktomaoouka+;a{)(gsk+)g,k.".to_vec());
        let volumes = get_volumes(data);
        assert!(volumes.is_err());
    }

    #[test]
    fn test_get_volumes_no_key() {
        init_logger();
        let data = io::Cursor::new(b"abc{}00000002".to_vec());
        let volumes = get_volumes(data);
        assert!(volumes.is_err());
    }

    #[test]
    fn test_get_volumes_null_value() -> anyhow::Result<()> {
        // this is valid case, when no volumes are declared
        init_logger();
        let data = io::Cursor::new(b"abc{\"Volumes\":null}00000016".to_vec());
        let volumes = get_volumes(data)?;
        assert!(volumes.is_empty());
        Ok(())
    }
}

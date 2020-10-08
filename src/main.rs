#![allow(dead_code)]
use anyhow::anyhow;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    str,
};
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
    #[structopt(long)]
    cpu_cores: Option<usize>,
    #[structopt(long)]
    mem_gib: Option<f64>,
    #[structopt(long)]
    storage_gib: Option<f64>,
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

fn get_runtime_path(current_exe: PathBuf) -> anyhow::Result<PathBuf> {
    let base_dir = current_exe
        .parent()
        .ok_or(anyhow!("exe path has no parent"))?;
    Ok(base_dir.join("runtime"))
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

fn to_string_for_qemu(path: &Path) -> String {
    // escape commas for qemu -drive file=path
    path.display().to_string().replace(",", ",,")
}

fn make_vmrt_command(
    runtime_path: &Path,
    workdir: &Path,
    task_package: &Path,
    smp_cpus: Option<usize>,
    mem_gib: Option<f64>,
    volumes: Vec<ContainerVolume>,
    entrypoint: String,
    args: Vec<String>,
) -> Command {
    /*
    special chars in paths to consider:
      - " "
      - "\""
      - "," (see qemu -drive file=path)
     */
    
    let mem = mem_gib
        .map(|gib| (gib * 1024.0).round() as u32)
        .unwrap_or(200);

    let mut append: Vec<String> = Vec::new();
    let mut cmd = Command::new("./vmrt");
    let pid = std::process::id();

    cmd.current_dir(runtime_path)
        .arg("-m")
        .arg(format!("{}m", mem))
        .arg("-nographic")
        .arg("-vga")
        .arg("none")
        .arg("-kernel")
        .arg("vmlinuz-virt")
        .arg("-initrd")
        .arg("initramfs-virt")
        .arg("-net")
        .arg("none")
        .arg("-accel")
        .arg("kvm")
        .arg("-cpu")
        .arg("host");

    if let Some(cores) = smp_cpus {
        let _ = cmd.arg("-smp").arg(cores.to_string());
    }

    cmd.arg("-device")
        .arg("virtio-serial,id=ser0")
        .arg("-device")
        .arg("virtserialport,chardev=foo,name=org.fedoraproject.port.0")
        .arg("-chardev")
        .arg(format!(
            "socket,path=/tmp/ya_runtime_vm-{}.sock,server,nowait,id=foo",
            pid
        ))
        .arg("-drive")
        .arg(format!(
            "file={},cache=none,readonly=on,format=raw,if=virtio",
            to_string_for_qemu(&task_package)
        ))
        .arg("-no-reboot");

    for (tag, vol) in volumes.iter().enumerate() {
        let src = workdir.join(&vol.name);
        let dst = &vol.path;
        cmd.arg("-virtfs")
            .arg(format!(
                "local,path={src},id=vol{tag},mount_tag=vol{tag},security_model=none",
                src = to_string_for_qemu(&src),
                tag = tag
            ))
            .arg("-device")
            .arg(format!(
                "virtio-9p-pci,fsdev=vol{tag},mount_tag=vol{tag}",
                tag = tag
            ));
        append.push(format!("volmnt=vol{}:{}", tag, dst));
    }

    append.push(format!("apparg=\"{}\"", entrypoint.replace("\"", "\\\"")));
    for arg in args {
        append.push(format!("apparg=\"{}\"", arg.replace("\"", "\\\"")));
    }

    cmd.arg("-append")
        .arg(format!("console=ttyS0 panic=1 {}", append.join(" ")));

    cmd
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

            {
                let f = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(cmdargs.workdir.join("vols.json"))?;
                serde_json::to_writer_pretty(&mut io::BufWriter::new(f), &volumes)?;
            }

            let result = DeployResult {
                valid: Ok("Ok".to_string()),
                vols: volumes,
            };

            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Start {} => (),
        Commands::Run { entrypoint, args } => {
            make_vmrt_command(
                &get_runtime_path(env::current_exe()?)?,
                &cmdargs.workdir,
                &cmdargs.task_package,
                cmdargs.cpu_cores,
                cmdargs.mem_gib,
                serde_json::from_str(&fs::read_to_string(cmdargs.workdir.join("vols.json"))?)?,
                entrypoint,
                args,
            )
            .spawn()?
            .wait()?;
        }
    };
    Ok(())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_get_runtime_path_absolute() -> anyhow::Result<()> {
        let runtime_path = get_runtime_path(PathBuf::from("/foo/bar/ya-runtime-vm"))?;
        assert_eq!(runtime_path, PathBuf::from("/foo/bar/runtime"));
        Ok(())
    }

    #[test]
    fn test_get_runtime_path_relative() -> anyhow::Result<()> {
        let runtime_path = get_runtime_path(PathBuf::from("./ya-runtime-vm"))?;
        assert_eq!(runtime_path, PathBuf::from("./runtime"));
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

    #[test]
    fn test_make_vmrt_command() {
        let pid = std::process::id();
        let cmd = format!(
            "{:?}",
            make_vmrt_command(
                // put " ", "\"", "," in paths
                &PathBuf::from("/fo o/run\"ti,me"),
                &PathBuf::from("/ba r/wo\"rk,dir"),
                &PathBuf::from("/qu x/task_\"package,golem-app"),
                Some(4),
                Some(0.2),
                vec![
                    ContainerVolume {
                        name: "vol-a".to_string(),
                        path: "/a".to_string(),
                    },
                    ContainerVolume {
                        name: "vol-b".to_string(),
                        path: "/b".to_string(),
                    },
                ],
                "ls".to_string(),
                vec!["/a".to_string(), "/b".to_string(),],
            )
        );
        // one level of quotes and backslash escaping is added by debug formatting of Command
        let expected_sock = format!(
            r#""-chardev" "socket,path=/tmp/ya_runtime_vm-{}.sock,server,nowait,id=foo""#,
            pid
        );
        let expected_cmd = &[
            r#""./vmrt""#,
            r#""-m" "205m""#,
            r#""-nographic""#,
            r#""-vga" "none""#,
            r#""-kernel" "vmlinuz-virt""#,
            r#""-initrd" "initramfs-virt""#,
            r#""-net" "none""#,
            r#""-accel" "kvm""#,
            r#""-cpu" "host""#,
            r#""-smp" "4""#,
            r#""-device" "virtio-serial,id=ser0""#,
            r#""-device" "virtserialport,chardev=foo,name=org.fedoraproject.port.0""#,
            expected_sock.as_str(),
            r#""-drive" "file=/qu x/task_\"package,,golem-app,cache=none,readonly=on,format=raw,if=virtio""#,
            r#""-no-reboot""#,
            r#""-virtfs" "local,path=/ba r/wo\"rk,,dir/vol-a,id=vol0,mount_tag=vol0,security_model=none""#,
            r#""-device" "virtio-9p-pci,fsdev=vol0,mount_tag=vol0""#,
            r#""-virtfs" "local,path=/ba r/wo\"rk,,dir/vol-b,id=vol1,mount_tag=vol1,security_model=none""#,
            r#""-device" "virtio-9p-pci,fsdev=vol1,mount_tag=vol1""#,
            r#""-append" "console=ttyS0 panic=1 volmnt=vol0:/a volmnt=vol1:/b apparg=\"ls\" apparg=\"/a\" apparg=\"/b\"""#,
        ].join(" ");
        assert_eq!(&cmd, expected_cmd);
    }
}

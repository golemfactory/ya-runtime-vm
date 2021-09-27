use bollard_stubs::models::ContainerConfig;
use crc::crc32;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio_byteorder::LittleEndian;
use uuid::Uuid;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Deployment {
    #[serde(default)]
    pub cpu_cores: usize,
    #[serde(default)]
    pub mem_mib: usize,
    #[serde(default)]
    pub task_package: PathBuf,
    pub user: (u32, u32),
    pub volumes: Vec<ContainerVolume>,
    pub config: Config,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(flatten)]
    pub container: ContainerConfig,
    #[serde(rename = "Filesystem")]
    #[serde(default)]
    pub fs: Fs,
}

/// Root filesystem overlay mode
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fs {
    /// Mount the overlay on disk (default)
    Disk,
    /// Keep the overlay in RAM (limit: 128 MB)
    Ram,
    /// Mount the overlay on disk but keep /tmp in RAM (limit: 128 MB)
    RamTmp,
}

impl Fs {
    pub fn in_memory(&self) -> bool {
        match self {
            Self::Ram => true,
            _ => false,
        }
    }
}

impl Default for Fs {
    fn default() -> Self {
        Self::Disk
    }
}

impl Deployment {
    pub async fn try_from_input(
        task_package: PathBuf,
        cpu_cores: usize,
        mem_mib: usize,
    ) -> Result<Self, anyhow::Error> {
        let mut input = tokio::fs::File::open(&task_package).await?;

        let json_len: u32 = {
            let mut buf = [0; 8];
            input.seek(SeekFrom::End(-8)).await?;
            input.read_exact(&mut buf).await?;
            std::str::from_utf8(&buf)?.parse()?
        };
        let crc: u32 = {
            let offset = 4 + json_len as i64 + 8;
            input.seek(SeekFrom::End(-offset)).await?;
            tokio_byteorder::AsyncReadBytesExt::read_u32::<LittleEndian>(&mut input).await?
        };
        let json = {
            let mut buf = String::new();
            let pos = -1 * (json_len + 8) as i64;
            input.seek(SeekFrom::End(pos)).await?;
            input.take(json_len as u64).read_to_string(&mut buf).await?;
            buf
        };

        if crc32::checksum_ieee(json.as_bytes()) != crc {
            return Err(anyhow::anyhow!("Invalid ContainerConfig crc32 sum"));
        }

        let config: Config = serde_json::from_str(&json)?;
        Ok(Deployment {
            cpu_cores,
            mem_mib,
            task_package,
            user: parse_user(config.container.user.as_ref())?,
            volumes: parse_volumes(config.container.volumes.as_ref()),
            config,
        })
    }

    pub fn env(&self) -> Vec<&str> {
        self.config
            .container
            .env
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(Vec::new)
    }

    pub fn init_args(&self) -> String {
        format!("-f {}", serde_json::to_string(&self.config.fs).unwrap())
    }
}

fn parse_user(user: Option<&String>) -> anyhow::Result<(u32, u32)> {
    let user = user.map(|s| s.trim()).unwrap_or("");
    if user.is_empty() {
        return Ok((0, 0));
    }

    let mut split = user.splitn(2, ":");
    let uid: u32 = split
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing UID"))?
        .parse()?;
    let gid: u32 = split
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing GID"))?
        .parse()?;
    Ok((uid, gid))
}

fn parse_volumes(volumes: Option<&HashMap<String, HashMap<(), ()>>>) -> Vec<ContainerVolume> {
    let volumes = match volumes {
        Some(v) => v,
        _ => return Vec::new(),
    };
    volumes
        .keys()
        .map(|key| ContainerVolume {
            name: format!("vol-{}", Uuid::new_v4()),
            path: key.to_string(),
        })
        .collect()
}

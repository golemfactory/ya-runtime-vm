use bollard_stubs::models::ContainerConfig;
use crc::crc32;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
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
    pub config: ContainerConfig,
}

impl Deployment {
    pub async fn try_from_input<Input>(
        mut input: Input,
        cpu_cores: usize,
        mem_mib: usize,
        task_package: PathBuf,
    ) -> Result<Self, anyhow::Error>
    where
        Input: AsyncRead + AsyncSeek + Unpin,
    {
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

        let config: ContainerConfig = serde_json::from_str(&json)?;
        Ok(Deployment {
            cpu_cores,
            mem_mib,
            task_package,
            user: parse_user(config.user.as_ref())?,
            volumes: parse_volumes(config.volumes.as_ref()),
            config,
        })
    }

    pub fn env(&self) -> Vec<&str> {
        self.config
            .env
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_else(Vec::new)
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

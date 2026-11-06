use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;

use bollard_stubs::models::ContainerConfig;
use crc::crc32;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use tokio_byteorder::LittleEndian;
use uuid::Uuid;

use ya_client_model::activity::exe_script_command::VolumeMount;
use ya_runtime_sdk::runtime_api::deploy::ContainerVolume;

const MAX_CONFIG_JSON_LEN: u32 = 1024 * 1024;

pub(crate) fn validate_cmdline_token(name: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_ascii_control() || c == '"')
    {
        anyhow::bail!("Invalid {name} for kernel cmdline: {value:?}");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentMount {
    pub name: String,
    pub guest_path: String,
    pub mount: VolumeMount,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Deployment {
    #[serde(default)]
    pub cpu_cores: usize,
    #[serde(default)]
    pub mem_mib: usize,
    #[serde(default)]
    pub task_packages: Vec<PathBuf>,
    pub user: (u32, u32),
    pub volumes: Vec<ContainerVolume>,
    pub mounts: Vec<DeploymentMount>,
    pub hostname: String,
    pub config: ContainerConfig,
}

impl Deployment {
    pub async fn try_from_input<Input>(
        mut input: Input,
        cpu_cores: usize,
        mem_mib: usize,
        task_packages: &[PathBuf],
        volume_override: HashMap<String, VolumeMount>,
        hostname: String,
    ) -> Result<Self, anyhow::Error>
    where
        Input: AsyncRead + AsyncSeek + Unpin,
    {
        validate_cmdline_token("hostname", &hostname)?;
        for (path, mount) in &volume_override {
            validate_cmdline_token("volume path", path)?;
            if let VolumeMount::Storage {
                errors: Some(errors),
                ..
            } = mount
            {
                validate_cmdline_token("volume errors policy", errors)?;
            }
        }

        let json_len: u32 = {
            let mut buf = [0; 8];
            input.seek(SeekFrom::End(-8)).await?;
            input.read_exact(&mut buf).await?;
            std::str::from_utf8(&buf)?.parse()?
        };
        if json_len > MAX_CONFIG_JSON_LEN {
            return Err(anyhow::anyhow!(
                "ContainerConfig JSON length {json_len} exceeds maximum {MAX_CONFIG_JSON_LEN} bytes"
            ));
        }
        let crc: u32 = {
            let offset = 4 + json_len as i64 + 8;
            input.seek(SeekFrom::End(-offset)).await?;
            tokio_byteorder::AsyncReadBytesExt::read_u32::<LittleEndian>(&mut input).await?
        };
        let json = {
            let mut buf = String::new();
            let pos = -((json_len + 8) as i64);
            input.seek(SeekFrom::End(pos)).await?;
            input.take(json_len as u64).read_to_string(&mut buf).await?;
            buf
        };
        if crc32::checksum_ieee(json.as_bytes()) != crc {
            return Err(anyhow::anyhow!("Invalid ContainerConfig crc32 sum"));
        }

        let config: ContainerConfig = serde_json::from_str(&json)?;

        let mut volumes = parse_volumes(config.volumes.as_ref());

        // Host mount type is not permitted for rootfs
        for (path, mount) in &volume_override {
            if let VolumeMount::Host {} = mount {
                // catches `/` as well as `` and `///`  etc.
                if path.bytes().all(|b| b == b'/') {
                    return Err(anyhow::anyhow!(
                        r#"Volume of type `host` specified for path="/""#
                    ));
                }
            }
        }

        let mounts = volume_override
            .into_iter()
            .filter_map(|(path, vol_mount)| match vol_mount {
                VolumeMount::Host {} => {
                    let volume_present = volumes.iter().any(|vol| vol.path == path);
                    if !volume_present {
                        volumes.push(ContainerVolume {
                            name: format!("vol-{}", Uuid::new_v4()),
                            path,
                        });
                    }

                    None
                }

                VolumeMount::Ram { .. } => {
                    volumes.retain(|vol| vol.path != path);
                    Some(DeploymentMount {
                        name: format!("tmpfs-{}", Uuid::new_v4()),
                        guest_path: path,
                        mount: vol_mount,
                    })
                }

                VolumeMount::Storage { .. } => {
                    volumes.retain(|vol| vol.path != path);
                    Some(DeploymentMount {
                        name: format!("vol-{}.img", Uuid::new_v4()),
                        guest_path: path,
                        mount: vol_mount,
                    })
                }
            })
            .collect();

        Ok(Deployment {
            cpu_cores,
            mem_mib,
            task_packages: task_packages.into(),
            user: parse_user(config.user.as_ref()).unwrap_or((0, 0)),
            volumes,
            mounts,
            hostname,
            config,
        })
    }

    pub fn env(&self) -> Vec<&str> {
        self.config
            .env
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }
}

fn parse_user(user: Option<&String>) -> anyhow::Result<(u32, u32)> {
    let user = user
        .map(|s| s.trim())
        .ok_or_else(|| anyhow::anyhow!("User field missing"))?;
    let mut split = user.splitn(2, ':');
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn rejects_oversized_footer_json_length_and_unsafe_cmdline_tokens() {
        let mut fake_image = vec![0u8; 32];
        // Footer claiming 99,999,999 bytes of JSON (> 1 MiB cap).
        fake_image.extend_from_slice(b"99999999");
        let err = Deployment::try_from_input(
            Cursor::new(fake_image),
            1,
            256,
            &[],
            HashMap::new(),
            "golem".into(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));

        for bad in ["", "golem init=/bin/sh", "golem\n", "golem\"quote"] {
            assert!(validate_cmdline_token("hostname", bad).is_err());
        }
        assert!(validate_cmdline_token("hostname", "golem-node_1").is_ok());
    }
}

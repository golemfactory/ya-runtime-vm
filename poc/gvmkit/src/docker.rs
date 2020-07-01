use anyhow::anyhow;
use bollard::exec::{CreateExecOptions, StartExecOptions};
use bollard::image::CreateImageOptions;
use bollard::service::{ContainerConfig, HostConfig, Mount, MountTypeEnum};
use bollard::{container, Docker};
use bytes::{Bytes, BytesMut};
use futures_util::stream::TryStreamExt;

use crate::image_builder::DirectoryMount;

pub struct DockerInstance {
    docker: Docker,
}

impl DockerInstance {
    pub async fn new() -> anyhow::Result<DockerInstance> {
        Ok(DockerInstance {
            docker: Docker::connect_with_local_defaults()?,
        })
    }

    pub async fn create_image(&mut self, image_name: &str) -> anyhow::Result<()> {
        print!("Creating image '{}'...", image_name);
        let options = CreateImageOptions {
            from_image: image_name,
            ..Default::default()
        };
        self.docker
            .create_image(Some(options), None, None)
            .try_collect::<Vec<_>>()
            .await?;
        println!("OK");
        Ok(())
    }

    pub async fn try_create_container(
        &mut self,
        image_name: &str,
        container_name: &str,
        mounts: Option<Vec<DirectoryMount>>,
        cmd: Option<Vec<String>>,
    ) -> anyhow::Result<()> {
        let options = container::CreateContainerOptions {
            name: container_name,
        };

        let host_config = HostConfig {
            mounts: match mounts {
                None => None,
                Some(m) => Some(
                    m.iter()
                        .map(|mount_point| Mount {
                            // TODO: don't clone, use references?
                            target: Some(mount_point.guest.clone()),
                            source: Some(mount_point.host.clone()),
                            read_only: Some(mount_point.readonly),
                            _type: Some(MountTypeEnum::BIND),
                            ..Default::default()
                        })
                        .collect(),
                ),
            },
            ..Default::default()
        };

        let config = container::Config {
            cmd: cmd,
            image: Some(image_name.to_string()),
            host_config: Some(host_config),
            ..Default::default()
        };

        self.docker.create_container(Some(options), config).await?;
        Ok(())
    }

    pub async fn create_container(
        &mut self,
        image_name: &str,
        container_name: &str,
        mounts: Option<Vec<DirectoryMount>>,
        cmd: Option<Vec<String>>,
    ) -> anyhow::Result<()> {
        print!(
            "Creating container '{}' from image '{}'...",
            container_name, image_name
        );

        let result = self
            .try_create_container(image_name, container_name, mounts.clone(), cmd.clone())
            .await;

        match result {
            Ok(_) => (),
            Err(err) => {
                if err.to_string().contains("No such image") {
                    // TODO: better way
                    println!("Required image not found locally");
                    self.create_image(image_name).await?;
                    self.try_create_container(image_name, container_name, mounts, cmd)
                        .await?;
                }
                return Err(err);
            }
        }
        println!("OK");
        Ok(())
    }

    pub async fn start_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        print!("Starting container '{}'...", container_name);
        self.docker
            .start_container(
                container_name,
                None::<container::StartContainerOptions<String>>,
            )
            .await?;
        println!("OK");
        Ok(())
    }

    pub async fn run_command(
        &mut self,
        container_name: &str,
        cmd: Vec<&str>,
        dir: &str,
    ) -> anyhow::Result<()> {
        print!("Running '{:?}' in container '{}'...", cmd, container_name);
        let config = CreateExecOptions {
            cmd: Some(cmd),
            working_dir: Some(dir),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };

        let result = self.docker.create_exec(container_name, config).await?;

        let options = StartExecOptions {
            detach: false, // run synchronously
        };

        let result = self
            .docker
            .start_exec(&result.id, Some(options))
            .try_collect::<Vec<_>>()
            .await?;

        println!("OK");
        println!("Cmd output: {:#?}", result); // TODO: prettify, stream progress
        Ok(())
    }

    pub async fn stop_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        print!("Stopping container '{}'...", container_name);
        self.docker
            .stop_container(container_name, None::<container::StopContainerOptions>)
            .await?;
        println!("OK");
        Ok(())
    }

    pub async fn remove_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        print!("Removing container '{}'...", container_name);
        let options = container::RemoveContainerOptions {
            force: true,
            ..Default::default()
        };

        self.docker
            .remove_container(container_name, Some(options))
            .await?;
        println!("OK");
        Ok(())
    }

    pub async fn export_container(&mut self, container_name: &str) -> anyhow::Result<Bytes> {
        println!("Exporting FS of container '{}'...", container_name);

        let options = container::DownloadFromContainerOptions { path: "/" };
        let chunks: Vec<Bytes> = self
            .docker
            .download_from_container(container_name, Some(options))
            .try_collect()
            .await?;

        dbg!(chunks.len());
        // transform chunks into a single Bytes instance
        let tar = chunks.iter().fold(BytesMut::new(), |mut buf, chunk| {
            buf.extend_from_slice(chunk as &[u8]);
            buf
        });

        println!("Total image size: {}", tar.len());
        Ok(tar.freeze())
    }

    pub async fn get_config(
        &mut self,
        container_name: &str,
    ) -> anyhow::Result<(String, ContainerConfig)> {
        let cont = self
            .docker
            .inspect_container(container_name, None::<container::InspectContainerOptions>)
            .await?;

        let hash = cont.id.ok_or(anyhow!("Container has no id"))?;
        println!("Container ID: {}", hash);

        let cfg = cont.config.ok_or(anyhow!("Container has no config"))?;
        Ok((hash, cfg))
    }
}

use anyhow::anyhow;
use bollard::{
    container, exec, image,
    service::{ContainerConfig, HostConfig, Mount, MountTypeEnum},
    Docker,
};
use bytes::{BufMut, Bytes, BytesMut};
use futures::TryStreamExt;

#[derive(Debug, Clone)]
pub struct DirectoryMount {
    pub host: String,
    pub guest: String,
    pub readonly: bool,
}

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
        log::debug!("Pulling image '{}'", image_name);
        let options = image::CreateImageOptions {
            from_image: image_name,
            ..Default::default()
        };
        self.docker
            .create_image(Some(options), None, None)
            .try_collect::<Vec<_>>()
            .await?;
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
            mounts: mounts.map(|mut mounts| {
                mounts
                    .drain(..)
                    .map(|mount| Mount {
                        target: Some(mount.guest),
                        source: Some(mount.host),
                        read_only: Some(mount.readonly),
                        typ: Some(MountTypeEnum::BIND),
                        ..Default::default()
                    })
                    .collect()
            }),
            ..Default::default()
        };

        let config = container::Config {
            cmd,
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
        log::debug!(
            "Creating container '{}' from image '{}'",
            container_name,
            image_name
        );

        match self
            .try_create_container(image_name, container_name, mounts.clone(), cmd.clone())
            .await
        {
            Ok(_) => (),
            Err(err) => {
                if err.to_string().contains("No such image") {
                    // TODO: better way
                    self.create_image(image_name).await?;
                    self.try_create_container(image_name, container_name, mounts, cmd)
                        .await?;
                } else {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub async fn start_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        log::debug!("Starting container '{}'", container_name);
        let options = None::<container::StartContainerOptions<String>>;
        self.docker.start_container(container_name, options).await?;
        Ok(())
    }

    pub async fn run_command<F: Fn(String) -> ()>(
        &mut self,
        container_name: &str,
        cmd: Vec<&str>,
        dir: &str,
        on_output: F,
    ) -> anyhow::Result<()> {
        log::debug!("Running '{:?}' in container '{}'", cmd, container_name);
        let config = exec::CreateExecOptions {
            cmd: Some(cmd),
            working_dir: Some(dir),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            ..Default::default()
        };

        let result = self.docker.create_exec(container_name, config).await?;
        self.docker
            .start_exec(&result.id, Some(exec::StartExecOptions { detach: false }))
            .try_for_each(|results| async {
                match results {
                    exec::StartExecResults::Attached { log } => on_output(log.to_string()),
                    exec::StartExecResults::Detached => (),
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn stop_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        log::debug!("Stopping container '{}'", container_name);
        self.docker
            .stop_container(container_name, None::<container::StopContainerOptions>)
            .await?;
        Ok(())
    }

    pub async fn remove_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        log::debug!("Removing container '{}'", container_name);
        let options = container::RemoveContainerOptions {
            v: true,
            force: true,
            ..Default::default()
        };

        self.docker
            .remove_container(container_name, Some(options))
            .await?;
        Ok(())
    }

    pub async fn download(&mut self, container_name: &str, path: &str) -> anyhow::Result<BytesMut> {
        log::debug!("Downloading '{}' from container '{}'", path, container_name);

        let options = container::DownloadFromContainerOptions { path };
        let bytes = self
            .docker
            .download_from_container(container_name, Some(options))
            .try_fold(BytesMut::new(), |mut bytes, b| async move {
                bytes.put(b);
                Ok(bytes)
            })
            .await?;

        Ok(bytes)
    }

    pub async fn upload(
        &mut self,
        container_name: &str,
        path: &str,
        data: Bytes,
    ) -> anyhow::Result<()> {
        log::debug!("Uploading to '{}' in container '{}'", path, container_name);

        let options = container::UploadToContainerOptions {
            path,
            ..Default::default()
        };

        self.docker
            .upload_to_container(container_name, Some(options), data.into())
            .await?;
        Ok(())
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
        log::debug!("Container ID: {}", &hash);

        let cfg = cont.config.ok_or(anyhow!("Container has no config"))?;
        Ok((hash, cfg))
    }
}

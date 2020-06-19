use anyhow::anyhow;
use bollard::{container, service::ContainerConfig, Docker};
use bytes::{Bytes, BytesMut};
use futures_util::stream::TryStreamExt;

pub struct DockerInstance {
    docker: Docker,
}

impl DockerInstance {
    pub async fn new() -> anyhow::Result<DockerInstance> {
        Ok(DockerInstance {
            docker: Docker::connect_with_local_defaults()?,
        })
    }

    pub async fn create_container(
        &mut self,
        image_name: &str,
        container_name: &str,
    ) -> anyhow::Result<()> {
        let options = Some(container::CreateContainerOptions {
            name: container_name,
        });
        let config = container::Config {
            image: Some(image_name),
            ..Default::default()
        };

        let result = self.docker.create_container(options, config).await?;
        dbg!(result);
        Ok(())
    }

    pub async fn remove_container(&mut self, container_name: &str) -> anyhow::Result<()> {
        let options = Some(container::RemoveContainerOptions {
            force: true,
            ..Default::default()
        });

        self.docker
            .remove_container(container_name, options)
            .await?;
        Ok(())
    }

    pub async fn export_container(&mut self, container_name: &str) -> anyhow::Result<Bytes> {
        println!("Exporting FS of container {}...", container_name);

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
        let options = Some(container::InspectContainerOptions { size: false });
        let cont = self
            .docker
            .inspect_container(container_name, options)
            .await?;

        let hash = cont.id.ok_or(anyhow!("Container has no id"))?;
        println!("Container ID: {}", hash);

        let cfg = cont.config.ok_or(anyhow!("Container has no config"))?;
        Ok((hash, cfg))
    }
}

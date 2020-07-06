use bollard::service::ContainerConfig;
use bytes::Bytes;
use crc::crc32;
use log::{debug, info};
use std::io::Write;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tar;

use crate::docker::DockerInstance;
use crate::rwbuf::RWBuffer;

pub struct ImageBuilder {
    tar: Option<tar::Builder<RWBuffer>>,
    docker: DockerInstance,
}

impl ImageBuilder {
    async fn new() -> anyhow::Result<ImageBuilder> {
        let buf = RWBuffer::new();
        Ok(ImageBuilder {
            tar: Some(tar::Builder::new(buf)),
            docker: DockerInstance::new().await?,
        })
    }

    pub async fn build_image(image_name: &str, output: &Path) -> anyhow::Result<()> {
        info!("Building image from '{}'", image_name);

        let mut builder = ImageBuilder::new().await?;
        let cont_name = "gvmkit-tmp";
        builder
            .docker
            .create_container(image_name, cont_name, None, None)
            .await?;

        let (hash, cfg) = builder.docker.get_config(cont_name).await?;

        let tar_bytes = builder.docker.download(cont_name, "/").await?;
        debug!("Docker image size: {}", tar_bytes.len());

        builder.tar_from_bytes(&tar_bytes)?;

        builder.docker.remove_container(cont_name).await?;

        let mut work_dir = PathBuf::from(&format!("work-{}", hash));
        fs::create_dir_all(&work_dir)?; // path must exist for canonicalize()
        work_dir = work_dir.canonicalize()?;
        let work_dir_out = work_dir.join("out");
        fs::create_dir_all(&work_dir_out)?;

        builder.add_metadata_inside(&cfg)?;
        let squashfs_image_path = builder.repack(&work_dir_out).await?;
        builder.add_metadata_outside(&squashfs_image_path, &cfg)?;
        fs::copy(&squashfs_image_path, output)?;
        fs::remove_dir_all(work_dir)?;
        info!("Image built successfully: {}", output.display());

        Ok(())
    }

    fn add_meta_file(&mut self, path: &Path, strings: &Option<Vec<String>>) -> anyhow::Result<()> {
        debug!("Adding metadata file '{}': {:?}", path.display(), strings);
        match strings {
            Some(val) => self.add_file(path, val.join("\n").as_bytes())?,
            None => self.add_file(path, &[])?,
        }
        Ok(())
    }

    fn add_metadata_inside(&mut self, config: &ContainerConfig) -> anyhow::Result<()> {
        self.add_meta_file(Path::new(".env"), &config.env)?;
        self.add_meta_file(Path::new(".entrypoint"), &config.entrypoint)?;
        self.add_meta_file(Path::new(".cmd"), &config.cmd)?;
        Ok(())
    }

    fn add_metadata_outside(
        &mut self,
        image_path: &Path,
        config: &ContainerConfig,
    ) -> anyhow::Result<()> {
        let mut json_buf = RWBuffer::new();
        serde_json::to_writer(&mut json_buf, config)?;
        let mut file = fs::OpenOptions::new().append(true).open(image_path)?;
        let meta_size = json_buf.bytes.len();
        let crc = crc32::checksum_ieee(&json_buf.bytes);
        info!("Image metadata checksum: 0x{:x}", crc);
        file.write(&crc.to_le_bytes())?;
        file.write(&json_buf.bytes)?;
        file.write(format!("{:08}", meta_size).as_bytes())?;
        Ok(())
    }

    async fn repack(&mut self, dir_out: &Path) -> anyhow::Result<PathBuf> {
        let img_as_tar = self.finish_tar()?;

        let squashfs_image = "prekucki/squashfs-tools:latest";
        let squashfs_cont = "sqfs-tools";
        let start_cmd = vec!["tail", "-f", "/dev/null"]; // prevent container from exiting

        self.docker
            .create_container(
                squashfs_image,
                squashfs_cont,
                None,
                Some(start_cmd.iter().map(|s| s.to_string()).collect()),
            )
            .await?;
        self.docker.start_container(squashfs_cont).await?;

        let path_in = "/work/in";
        let path_out = "/work/out/image.squashfs";

        self.docker
            .upload(squashfs_cont, path_in, img_as_tar.bytes.freeze())
            .await?;

        self.docker
            .run_command(
                squashfs_cont,
                vec![
                    "mksquashfs",
                    path_in,
                    path_out,
                    "-info",
                    "-comp",
                    "lzo",
                    "-noappend",
                ],
                "/",
            )
            .await?;

        let final_img_tar = self.docker.download(squashfs_cont, path_out).await?;

        let mut tar = tar::Archive::new(RWBuffer::from_bytes(&final_img_tar)?);
        tar.unpack(dir_out)?;

        self.docker.stop_container(squashfs_cont).await?;
        self.docker.remove_container(squashfs_cont).await?;

        Ok(dir_out.join(Path::new(path_out).file_name().unwrap()))
    }

    fn add_file(&mut self, path: &Path, data: &[u8]) -> anyhow::Result<()> {
        let mut header = tar::Header::new_ustar();
        header.set_path(path)?;
        header.set_size(data.len() as u64);
        header.set_cksum();

        self.tar.as_mut().unwrap().append(&header, data)?;
        Ok(())
    }

    fn tar_from_bytes(&mut self, bytes: &Bytes) -> anyhow::Result<()> {
        // the tar builder doesn't have any method for constructing an archive from in-memory
        // representation of the whole file, so we need to do that in chunks

        let mut offset: usize = 0;
        loop {
            if offset + 2 * 0x200 > bytes.len() {
                // tar file is terminated by two zeroed chunks
                debug!(
                    "reading tar: Break at offset 0x{:x}: EOF (incomplete file)",
                    offset
                );
                break;
            }

            // check for zeroed chunks (TODO: better way)
            let term = &bytes[offset..offset + 2 * 0x200];
            if term.iter().fold(0, |mut val, b| {
                val |= b;
                val
            }) == 0
            {
                debug!("reading tar: Break at offset 0x{:x}: EOF", offset);
                break;
            }

            let hdr = tar::Header::from_byte_slice(&bytes[offset..offset + 0x200]);
            let entry_size = hdr.entry_size()? as usize;
            offset += 0x200;
            self.tar
                .as_mut()
                .unwrap()
                .append(&hdr, &bytes[offset..offset + entry_size])?;
            offset = offset + entry_size;
            if entry_size > 0 && entry_size % 0x200 != 0 {
                // round up to chunk size
                offset |= 0x1ff;
                offset += 1;
            }
        }

        Ok(())
    }

    fn finish_tar(&mut self) -> anyhow::Result<RWBuffer> {
        let buf = self.tar.take().unwrap().into_inner()?;
        debug!("Bytes in tar archive: {}", buf.bytes.len());
        Ok(buf)
    }
}

use bollard::service::ContainerConfig;
use bytes::Bytes;
use crc::crc32;
use std::io::Write;
use std::{env, fs, path::PathBuf};
use tar;

use crate::docker::DockerInstance;
use crate::rwbuf::RWBuffer;

#[derive(Debug, Clone)]
pub struct DirectoryMount {
    pub host: String,
    pub guest: String,
    pub readonly: bool,
}

fn path_to_str(path: &PathBuf) -> anyhow::Result<String> {
    let mut path_str = path.to_str().unwrap().to_string();
    if cfg!(windows) {
        // canonicalize creates paths with extended syntax, prefixed with \\?\
        // docker API doesn't like that
        path_str = path_str.split_off(4);
    }
    Ok(path_str)
}

pub struct ImageBuilder {
    tar: Option<tar::Builder<RWBuffer>>,
    docker: DockerInstance,
}

impl ImageBuilder {
    pub async fn new() -> anyhow::Result<ImageBuilder> {
        let buf = RWBuffer::new();
        Ok(ImageBuilder {
            tar: Some(tar::Builder::new(buf)),
            docker: DockerInstance::new().await?,
        })
    }

    pub async fn build(&mut self, image_name: &str) -> anyhow::Result<()> {
        println!("Building image from '{}'...", image_name);

        let cont_name = "gvmkit-tmp";
        self.docker
            .create_container(image_name, cont_name, None, None)
            .await?;

        let (hash, cfg) = self.docker.get_config(cont_name).await?;

        let tar_bytes = self.docker.export_container(cont_name).await?;
        self.from_bytes(&tar_bytes)?;

        self.docker.remove_container(cont_name).await?;

        let mut work_dir_name = String::from("work-");
        work_dir_name.push_str(&hash);
        let mut work_dir = PathBuf::from(&work_dir_name);
        fs::create_dir_all(&work_dir)?; // path must exist for canonicalize()
        work_dir = work_dir.canonicalize()?;
        let work_dir_in = work_dir.join("in");
        let work_dir_out = work_dir.join("out");
        dbg!(&work_dir_in);
        fs::create_dir_all(&work_dir_in)?;
        fs::create_dir_all(&work_dir_out)?;

        self.add_metadata_inside(&cfg).await?;
        let squashfs_image = self.repack(&work_dir_in, &work_dir_out).await?;
        self.add_metadata_outside(&squashfs_image, &cfg).await?;
        fs::copy(&squashfs_image, env::current_dir().unwrap().join("out.img"))?; // TODO: final output name from cmd
        fs::remove_dir_all(work_dir)?;

        Ok(())
    }

    async fn add_metadata_inside(&mut self, config: &ContainerConfig) -> anyhow::Result<()> {
        let env = &config.env;
        let entrypoint = &config.entrypoint;
        let cmd = &config.cmd;
        let volumes = &config.volumes;
        dbg!(env, entrypoint, cmd, volumes);

        // TODO: cleanup
        match env {
            // Vec<String>
            Some(val) => self.add_file(".env", val.join("\n").as_bytes())?,
            None => self.add_file(".env", &[])?,
        }

        match entrypoint {
            // Vec<String>
            Some(val) => self.add_file(".entrypoint", val.join("\n").as_bytes())?,
            None => self.add_file(".entrypoint", &[])?,
        }

        match cmd {
            // Vec<String>
            Some(val) => self.add_file(".cmd", val.join("\n").as_bytes())?,
            None => self.add_file(".cmd", &[])?,
        }
        Ok(())
    }

    async fn add_metadata_outside(
        &mut self,
        image_path: &PathBuf,
        config: &ContainerConfig,
    ) -> anyhow::Result<()> {
        let mut json_buf = RWBuffer::new();
        serde_json::to_writer(&mut json_buf, config)?;
        let mut file = fs::OpenOptions::new().append(true).open(image_path)?;
        let meta_size = json_buf.bytes.len();
        let crc = crc32::checksum_ieee(&json_buf.bytes);
        println!("Image metadata checksum: 0x{:x}", crc);
        file.write(&crc.to_le_bytes())?;
        file.write(&json_buf.bytes)?;
        file.write(format!("{:08}", meta_size).as_bytes())?;
        Ok(())
    }

    async fn repack(
        &mut self,
        work_dir_in: &PathBuf,
        work_dir_out: &PathBuf,
    ) -> anyhow::Result<PathBuf> {
        let buf = self.finish()?; // final image as .tar

        // TODO: tar::Archive can't extract files outside of the target path (no stripping leading / like normal tar)
        // ...so we end up using the tar command anyway :/ (inside the squashfs-tools container)
        //let mut ar = tar::Archive::new(buf);

        fs::File::create(work_dir_in.join("img.tar"))?.write_all(&buf.bytes)?;

        let squashfs_image = "prekucki/squashfs-tools:latest";
        let mounts = vec![
            DirectoryMount {
                readonly: true,
                guest: String::from("/work/in"),
                host: path_to_str(work_dir_in)?,
            },
            DirectoryMount {
                readonly: false,
                guest: String::from("/work/out"),
                host: path_to_str(work_dir_out)?,
            },
        ];

        let sqfs = "sqfs-tools";
        let start_cmd = vec!["tail", "-f", "/dev/null"]; // prevent container from exiting
        self.docker
            .create_container(
                squashfs_image,
                sqfs,
                Some(mounts.clone()),
                Some(start_cmd.iter().map(|s| s.to_string()).collect()),
            )
            .await?;
        self.docker.start_container(sqfs).await?;

        self.docker
            .run_command(sqfs, vec!["tar", "xf", "/work/in/img.tar"], "/work/out")
            .await?;

        self.docker
            .run_command(
                sqfs,
                vec![
                    "mksquashfs",
                    "/work/in",
                    "/work/out/image.squashfs",
                    "-info",
                    "-comp",
                    "lzo",
                    "-noappend",
                ],
                "/",
            )
            .await?;

        self.docker.stop_container(sqfs).await?;
        self.docker.remove_container(sqfs).await?;

        Ok(work_dir_out.join("image.squashfs"))
    }

    pub fn add_file(&mut self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let mut header = tar::Header::new_ustar();
        header.set_path(path)?;
        header.set_size(data.len() as u64);
        header.set_cksum();

        self.tar.as_mut().unwrap().append(&header, data)?;
        Ok(())
    }

    fn from_bytes(&mut self, bytes: &Bytes) -> anyhow::Result<()> {
        // the tar builder doesn't have any method for constructing an archive from in-memory
        // representation of the whole file, so we need to do that in chunks

        let mut offset: usize = 0;
        loop {
            if offset + 2 * 0x200 > bytes.len() {
                // tar file is terminated by two zeroed chunks
                println!("Break at offset {:x}: EOF (incomplete file)", offset);
                break;
            }

            // check for zeroed chunks (TODO: better way)
            let term = &bytes[offset..offset + 2 * 0x200];
            if term.iter().fold(0, |mut val, b| {
                val |= b;
                val
            }) == 0
            {
                println!("Break at offset {:x}: EOF", offset);
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

    pub fn finish(&mut self) -> anyhow::Result<RWBuffer> {
        let buf = self.tar.take().unwrap().into_inner()?;
        println!("Bytes in archive: {}", buf.bytes.len());
        Ok(buf)
    }
}

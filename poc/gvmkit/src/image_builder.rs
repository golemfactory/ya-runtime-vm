use bollard::service::ContainerConfig;
use bytes::Bytes;
use std::fs;
use std::io::Write;
use tar;

use crate::docker::DockerInstance;
use crate::rwbuf::RWBuffer;

pub struct ImageBuilder {
    tar: tar::Builder<RWBuffer>,
    docker: DockerInstance,
}

impl ImageBuilder {
    pub async fn new() -> anyhow::Result<ImageBuilder> {
        let buf = RWBuffer::new();
        Ok(ImageBuilder {
            tar: tar::Builder::new(buf),
            docker: DockerInstance::new().await?,
        })
    }

    pub async fn build(&mut self, image_name: &str) -> anyhow::Result<()> {
        println!("Building image from '{}'...", image_name);

        let cont_name = "gvmkit-tmp";
        self.docker
            .create_container(image_name, cont_name, None)
            .await?;

        let (hash, cfg) = self.docker.get_config(cont_name).await?;

        //let mut out_dir = String::from("out-");
        //out_dir.push_str(hash);
        //fs::create_dir_all(&out_dir)?;

        let tar_bytes = self.docker.export_container(cont_name).await?;
        self.docker.remove_container(cont_name).await?;

        self.repack(tar_bytes, &hash, &cfg).await?;

        //fs::remove_dir_all(out_dir)?;

        Ok(())
    }

    async fn repack(
        &mut self,
        tar_bytes: Bytes,
        container_id: &str,
        config: &ContainerConfig,
    ) -> anyhow::Result<()> {
        self.from_bytes(&tar_bytes)?;

        let env = &config.env;
        let entrypoint = &config.entrypoint;
        let cmd = &config.cmd;
        let volumes = &config.volumes;
        dbg!(env, entrypoint, cmd, volumes);

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
        /* // this should only be in image metadata
                match volumes {
                    // HashMap<String, HashMap<(), (), RandomState>, RandomState>
                    // TODO: test this for non-empty map
                    Some(val) => self.add_file(
                        ".vols",
                        val.keys()
                            .collect::<Vec<&String>>()
                            .iter()
                            .fold(String::new(), |mut result, element| {
                                result.push_str(element);
                                result
                            })
                            .as_bytes(),
                    )?,
                    None => self.add_file(".vols", &[])?,
                }
        */
        Ok(())
    }

    pub fn add_file(&mut self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let mut header = tar::Header::new_ustar();
        header.set_path(path)?;
        header.set_size(data.len() as u64);
        header.set_cksum();
        self.tar.append(&header, data)?;
        Ok(())
    }

    fn from_bytes(&mut self, bytes: &Bytes) -> anyhow::Result<()> {
        // the tar crate doesn't have any method for constructing an archive from in-memory
        // representation of the whole file, so we need to do that in chunks

        let mut offset: usize = 0;
        loop {
            //println!("offset: {:x}", offset);
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
            // println!(
            //     "tar entry size {:x}, path {:?}",
            //     hdr.entry_size()?,
            //     hdr.path()?
            // );
            offset += 0x200;
            self.tar.append(&hdr, &bytes[offset..offset + entry_size])?;
            offset = offset + entry_size;
            if entry_size > 0 && entry_size % 0x200 != 0 {
                // round up to chunk size
                offset |= 0x1ff;
                offset += 1;
            }
        }

        Ok(())
    }

    pub fn finish(self) -> anyhow::Result<()> {
        let buf = &self.tar.into_inner()?;
        println!("Bytes in image: {}", buf.bytes.len());

        let mut f = fs::File::create("out.tar")?;
        f.write_all(&buf.bytes)?;
        Ok(())
    }
}

use crate::rwbuf::RWBuffer;
use bytes::Bytes;
use std::fs;
use std::io::Write;
use tar;

pub struct Image {
    tar: tar::Builder<RWBuffer>,
}

impl Image {
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> anyhow::Result<()> {
        let mut header = tar::Header::new_ustar();
        header.set_path(path)?;
        header.set_size(data.len() as u64);
        header.set_cksum();
        self.tar.append(&header, data)?;
        Ok(())
    }

    pub fn from_bytes(bytes: &Bytes) -> anyhow::Result<Image> {
        // the tar crate doesn't have any method for constructing an archive from in-memory
        // representation of the whole file, so we need to do that in chunks
        let buf = RWBuffer::new();
        let mut tar = tar::Builder::new(buf);

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
            offset = offset + 0x200;
            tar.append(&hdr, &bytes[offset..offset + entry_size])?;
            offset = offset + entry_size;
            if entry_size > 0 && entry_size % 0x200 != 0 {
                // round up to chunk size
                offset |= 0x1ff;
                offset += 1;
            }
        }

        Ok(Image { tar })
    }

    pub fn finish(self) -> anyhow::Result<()> {
        let buf = &self.tar.into_inner()?;
        println!("Bytes in image: {}", buf.bytes.len());

        let mut f = fs::File::create("out.tar")?;
        f.write_all(&buf.bytes)?;
        Ok(())
    }
}

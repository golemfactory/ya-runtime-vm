use std::io::{Result, SeekFrom};

use tokio::io::{AsyncSeekExt, AsyncWriteExt};

// Almost completely reverse-engineered
// No educational value at all, look elsewhere.
const QCOW2_HEADER: &[u8] = include_bytes!("10k.header");
const QCOW2_SIZE_OFFSET: u64 = 24;

const QCOW2_L1_SIZE_DIV: u64 = 512 * 1024 * 1024;
const QCOW2_L1_ENTRIES_OFFSET: u64 = 32;

const QCOW2_MYSTERY_CONST1: u64 = 0x0000_0000_0002_0000;
const QCOW2_MYSTERY_CONST1_OFFSET: u64 = 0x1_0000;

const QCOW2_CLUSTERS_MIN: u64 = 4;
const QCOW2_CLUSTERS_SZ_DIV: u64 = 4 * 1024 * 1024 * 1024 * 1024;
const QCOW2_CLUSTERS_SZ_DIV2: u64 = 1024 * 1024 * 1024 * 1024;
const QCOW2_CLUSTERS_OFFSET: u64 = 0x2_0000;
const QCOW2_CLUSTER_OFFSET: u64 = 0x30000;
const QCOW2_CLUSTER_SIZE: u64 = 16384;

/// Qcow2 image parameters
pub struct Qcow2Image {
    /// Virtual size
    pub size: u64,
    /// Image file will be no smaller than [`Self::preallocate`]
    pub preallocate: u64,
}

impl Qcow2Image {
    pub fn new(size: u64, preallocate: u64) -> Self {
        Qcow2Image { size, preallocate }
    }

    /// Writes a valid qcow2 image according to the parameters.
    ///
    /// Resultant `qemu-img info`:
    /// ```
    /// cluster_size: 65536
    /// Format specific information:
    ///     compat: 1.1
    ///     compression type: zlib
    ///     lazy refcounts: false
    ///     refcount bits: 16
    ///     corrupt: false
    ///     extended l2: false
    /// ```
    pub async fn write<W: AsyncWriteExt + AsyncSeekExt + Unpin>(
        &self,
        mut writer: W,
    ) -> Result<()> {
        let clusters = ((self.size - 1) / QCOW2_CLUSTERS_SZ_DIV + 4).max(QCOW2_CLUSTERS_MIN);
        let clusters2 = self.size.div_ceil(QCOW2_CLUSTERS_SZ_DIV2);
        let mut file_sz = self
            .preallocate
            .max(clusters2 * QCOW2_CLUSTER_SIZE + QCOW2_CLUSTER_OFFSET);

        const BLOCK_SZ: u64 = 4096;
        let block: &'static [u8] = &[0; BLOCK_SZ as usize];

        while file_sz >= BLOCK_SZ {
            writer.write_all(&block).await?;
            file_sz -= BLOCK_SZ as u64;
        }
        if file_sz > 0 {
            writer.write_all(&block[0..file_sz as usize]).await?;
        }

        writer.rewind().await?;
        writer.write_all(QCOW2_HEADER).await?;

        writer.seek(SeekFrom::Start(QCOW2_SIZE_OFFSET)).await?;
        writer.write_all(&self.size.to_be_bytes()).await?;

        writer
            .seek(SeekFrom::Start(QCOW2_L1_ENTRIES_OFFSET))
            .await?;
        let l1_entries = self.size.div_ceil(QCOW2_L1_SIZE_DIV);
        writer.write_all(&l1_entries.to_be_bytes()).await?;

        writer
            .seek(SeekFrom::Start(QCOW2_MYSTERY_CONST1_OFFSET))
            .await?;
        writer
            .write_all(&QCOW2_MYSTERY_CONST1.to_be_bytes())
            .await?;

        for k in 0..clusters {
            let offset = QCOW2_CLUSTERS_OFFSET + 2 * k;
            writer.seek(SeekFrom::Start(offset)).await?;
            writer.write_all(&[0, 1]).await?;
        }

        Ok(())
    }
}

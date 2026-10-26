//! Host-controlled limits for guest mutations, including unlinked pinned files.
use super::{Object, check_metadata, component, lock_directory, name_bytes, pin};
use cap_fs_ext::MetadataExt;
use cap_std::fs::Metadata;
use fuse::protocol::fuse_kstatfs;
use mesh::MeshPayload;
use std::{collections::HashMap, fs::File};

pub(super) type Identity = (u64, u64);
pub(super) fn identity(metadata: &Metadata) -> Identity {
    (metadata.dev(), metadata.ino())
}

#[derive(Clone, Copy, MeshPayload)]
pub(crate) struct ShareLimits {
    pub max_bytes: u64,
    pub max_entries: u64,
}
impl Default for ShareLimits {
    fn default() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024 * 1024,
            max_entries: 100_000,
        }
    }
}
impl ShareLimits {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        fn value(name: &str, default: u64) -> anyhow::Result<u64> {
            match std::env::var(name) {
                Ok(value) => value
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid {name}: {e}")),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(e) => Err(anyhow::anyhow!("invalid {name}: {e}")),
            }
        }
        let default = Self::default();
        let limits = Self {
            max_bytes: value("YA_RUNTIME_VM_SHARE_MAX_BYTES", default.max_bytes)?,
            max_entries: value("YA_RUNTIME_VM_SHARE_MAX_ENTRIES", default.max_entries)?,
        };
        limits.validate().map_err(|_| {
            anyhow::anyhow!("share limits require 1..=i64::MAX bytes and 1..=1000000 entries")
        })?;
        Ok(limits)
    }
    fn validate(self) -> lx::Result<()> {
        if self.max_bytes == 0
            || self.max_bytes > i64::MAX as u64
            || !(1..=1_000_000).contains(&self.max_entries)
        {
            return Err(lx::Error::EINVAL);
        }
        Ok(())
    }
}

struct Charge {
    bytes: u64,
    linked: bool,
}
#[derive(Default)]
pub(super) struct Quota {
    limits: ShareLimits,
    objects: HashMap<Identity, Charge>,
    bytes: u64,
    pending_entries: u64,
}
impl Quota {
    pub fn scan(root: &File, limits: ShareLimits) -> lx::Result<Self> {
        limits.validate()?;
        let mut quota = Self {
            limits,
            objects: HashMap::new(),
            bytes: 0,
            pending_entries: 0,
        };
        quota.observe(&Metadata::from_file(root)?)?;
        let root = lock_directory(root)?;
        let entries = root.entries()?;
        let mut stack = vec![(root, entries)];
        // Iterative DFS bounds both call-stack use and simultaneous directory FDs.
        while let Some((dir, entries)) = stack.last_mut() {
            let Some(item) = entries.next() else {
                stack.pop();
                continue;
            };
            let name = item?.file_name();
            if name_bytes(&name).is_none_or(|raw| component(raw).is_err()) {
                continue;
            }
            let object = match pin(dir, &name) {
                Ok(object) => object,
                Err(lx::Error::ELOOP | lx::Error::EPERM) => continue,
                Err(e) => return Err(e),
            };
            quota.observe(&object.metadata()?)?;
            if let Object::Directory(file) = object {
                if stack.len() >= 128 {
                    return Err(lx::Error::ELOOP);
                }
                let dir = lock_directory(&file)?;
                let entries = dir.entries()?;
                stack.push((dir, entries));
            }
        }
        Ok(quota)
    }
    pub fn capacity(&self) -> lx::Result<()> {
        if self.objects.len() as u64 + self.pending_entries >= self.limits.max_entries {
            return Err(lx::Error::ENOSPC);
        }
        Ok(())
    }
    pub fn reserve_entry(&mut self) -> lx::Result<()> {
        self.capacity()?;
        self.pending_entries += 1;
        Ok(())
    }
    pub fn cancel_entry(&mut self) {
        self.pending_entries -= 1;
    }
    pub fn observe_reserved(&mut self, metadata: &Metadata) -> lx::Result<()> {
        self.pending_entries -= 1;
        let result = self.observe(metadata);
        if result.is_err() {
            self.pending_entries += 1;
        }
        result
    }
    pub fn observe(&mut self, metadata: &Metadata) -> lx::Result<()> {
        check_metadata(metadata)?;
        let key = identity(metadata);
        // Quota accounting requires stable per-filesystem inode identities.
        if key.1 == 0 {
            return Err(lx::Error::EINVAL);
        }
        let size = if metadata.is_file() {
            metadata.len()
        } else {
            0
        };
        if !self.objects.contains_key(&key) {
            self.capacity()?;
            if size > self.limits.max_bytes.saturating_sub(self.bytes) {
                return Err(lx::Error::ENOSPC);
            }
            self.objects.insert(
                key,
                Charge {
                    bytes: size,
                    linked: true,
                },
            );
            self.bytes += size;
        } else {
            self.reserve(key, size)?;
        }
        Ok(())
    }
    /// Reserve worst-case logical growth before issuing any host write/truncate.
    pub fn reserve(&mut self, key: Identity, size: u64) -> lx::Result<()> {
        let old = self.objects.get(&key).ok_or(lx::Error::ENOENT)?.bytes;
        let total = self.bytes - old;
        if size > self.limits.max_bytes.saturating_sub(total) {
            return Err(lx::Error::ENOSPC);
        }
        self.objects.get_mut(&key).unwrap().bytes = size;
        self.bytes = total + size;
        Ok(())
    }
    // Guest writes are serialized under State's mutex. On failure keep the
    // reservation unless fstat confirms how much space can safely be refunded.
    pub fn reconcile(&mut self, key: Identity, size: u64) {
        if let Some(charge) = self.objects.get_mut(&key)
            && size < charge.bytes
        {
            self.bytes -= charge.bytes - size;
            charge.bytes = size;
        }
    }
    pub fn unlink(&mut self, key: Identity) {
        if let Some(charge) = self.objects.get_mut(&key) {
            charge.linked = false;
        }
    }
    pub fn collect(&mut self, key: Identity) {
        if self.objects.get(&key).is_some_and(|charge| !charge.linked) {
            let charge = self.objects.remove(&key).unwrap();
            self.bytes -= charge.bytes;
        }
    }
    pub fn stats(&self) -> fuse_kstatfs {
        let free = self.limits.max_bytes.saturating_sub(self.bytes) / 4096;
        fuse_kstatfs {
            blocks: self.limits.max_bytes.div_ceil(4096),
            bfree: free,
            bavail: free,
            files: self.limits.max_entries,
            ffree: self.limits.max_entries - self.objects.len() as u64 - self.pending_entries,
            bsize: 4096,
            namelen: 255,
            frsize: 4096,
            padding: 0,
            spare: [0; 6],
        }
    }
}

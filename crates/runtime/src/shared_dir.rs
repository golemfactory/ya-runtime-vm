//! Minimal host directory export. Guest identities and modes never reach the host.
//!
//! Every node pins a host handle. Names accepted from FUSE are single components;
//! directory handles, rather than cached relative paths, anchor every operation.
//! This also prevents a host rename/symlink swap from redirecting a cached inode.
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use cap_fs_ext::{FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use fuse::protocol::*;
use fuse::{DirEntryWriter, Fuse, Request, SessionInfo};
use mesh::MeshPayload;
use parking_lot::Mutex;
use virtio::resolve::{ResolvedVirtioDevice, VirtioResolveInput};
use vm_resource::kind::VirtioDeviceHandle;
use vm_resource::{ResolveResource, ResourceId, declare_static_resolver};

mod host;
pub(crate) use host::open_root;
use host::{
    check_metadata, component, filesystem_stats, lock_directory, name_bytes, pin, remove_entry,
    rename_entry, reopen, reopen_for_times, sync_directory,
};

const MAX_NODES: usize = 8192;
const MAX_HANDLES: usize = 1024;
const MAX_IO: usize = 1024 * 1024;
const MAX_REQUEST: u32 = 128 * 1024;
// Bounds host memory held by the name snapshots of all open directory
// handles of a share: about 1.2M entries with 24-byte names in total.
const MAX_DIRECTORY_BYTES: usize = 64 * 1024 * 1024;
// Snapshot cost of one entry besides its name bytes.
const ENTRY_BYTES: usize = size_of::<(OsString, u32)>();
// libfuse's FUSE_UNKNOWN_INO. Never 0: glibc < 2.37 readdir() skips d_ino == 0.
const UNKNOWN_INO: u64 = 0xffff_ffff;

#[derive(MeshPayload)]
pub(crate) struct SharedDirHandle {
    pub tag: String,
    pub root: File,
}
impl ResourceId<VirtioDeviceHandle> for SharedDirHandle {
    const ID: &'static str = "ya-runtime-shared-dir";
}
pub struct SharedDirResolver;
declare_static_resolver!(SharedDirResolver, (VirtioDeviceHandle, SharedDirHandle));
vm_resource::register_static_resolvers! { SharedDirResolver }
impl ResolveResource<VirtioDeviceHandle, SharedDirHandle> for SharedDirResolver {
    type Output = ResolvedVirtioDevice;
    type Error = anyhow::Error;
    fn resolve(
        &self,
        resource: SharedDirHandle,
        input: VirtioResolveInput<'_>,
    ) -> anyhow::Result<Self::Output> {
        let fs = SharedDir::new(resource.root)?;
        Ok(
            virtiofs::virtio::VirtioFsDevice::new(input.driver_source, &resource.tag, fs, 0, None)
                .into(),
        )
    }
}

#[derive(Clone)]
enum Object {
    Directory(Arc<File>),
    File(Arc<File>),
}
impl Object {
    fn metadata(&self) -> lx::Result<Metadata> {
        let metadata = match self {
            Self::Directory(dir) => Metadata::from_file(dir)?,
            Self::File(file) => Metadata::from_file(file)?,
        };
        check_metadata(&metadata)?;
        Ok(metadata)
    }
    fn directory(&self) -> lx::Result<Dir> {
        match self {
            Self::Directory(dir) => lock_directory(dir),
            _ => Err(lx::Error::ENOTDIR),
        }
    }
}
struct Node {
    object: Object,
    lookups: u64,
    // Namespace cache only. All I/O uses object handles, never this name.
    location: Option<(u64, OsString)>,
}
struct OpenFile {
    node: u64,
    file: File,
    read: bool,
    write: bool,
    append: bool,
}
struct OpenDirectory {
    node: u64,
    entries: Vec<(OsString, u32)>,
    bytes: usize,
}
#[derive(Default)]
struct State {
    next: u64,
    nodes: HashMap<u64, Node>,
    names: HashMap<(u64, OsString), u64>,
    files: HashMap<u64, OpenFile>,
    directories: HashMap<u64, OpenDirectory>,
    directory_bytes: usize,
}
impl State {
    fn id(&mut self) -> lx::Result<u64> {
        self.next = self.next.checked_add(1).ok_or(lx::Error::EOVERFLOW)?;
        Ok(self.next)
    }
    fn object(&self, id: u64) -> lx::Result<Object> {
        self.nodes
            .get(&id)
            .map(|node| node.object.clone())
            .ok_or(lx::Error::ENOENT)
    }
    fn directory(&self, id: u64) -> lx::Result<Dir> {
        self.object(id)?.directory()
    }
    fn handle_capacity(&self) -> lx::Result<()> {
        if self.files.len() + self.directories.len() >= MAX_HANDLES {
            return Err(lx::Error::EMFILE);
        }
        Ok(())
    }
    fn collect(&mut self, id: u64) {
        if id == FUSE_ROOT_ID {
            return;
        }
        if self.nodes.get(&id).is_none_or(|n| n.lookups != 0)
            || self.files.values().any(|f| f.node == id)
            || self.directories.values().any(|d| d.node == id)
        {
            return;
        }
        if let Some(Node {
            location: Some(location),
            ..
        }) = self.nodes.remove(&id)
        {
            self.names.remove(&location);
        }
    }
    fn entry(&mut self, parent: u64, name: OsString, object: Object) -> lx::Result<fuse_entry_out> {
        let metadata = object.metadata()?;
        let key = (parent, name);
        if let Some(&id) = self.names.get(&key) {
            let old = self.object(id)?.metadata();
            if old.is_ok_and(|old| old.dev() == metadata.dev() && old.ino() == metadata.ino()) {
                let node = self.nodes.get_mut(&id).unwrap();
                node.lookups = node.lookups.checked_add(1).ok_or(lx::Error::EOVERFLOW)?;
                return Ok(entry(id, &metadata));
            }
            self.detach(&key);
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(lx::Error::ENFILE);
        }
        let id = self.id()?;
        self.nodes.insert(
            id,
            Node {
                object,
                lookups: 1,
                location: Some(key.clone()),
            },
        );
        self.names.insert(key, id);
        Ok(entry(id, &metadata))
    }
    fn detach(&mut self, key: &(u64, OsString)) -> Option<u64> {
        let id = self.names.remove(key)?;
        self.nodes.get_mut(&id).unwrap().location = None;
        Some(id)
    }
}

pub(crate) struct SharedDir(Mutex<State>);
impl SharedDir {
    fn new(root: File) -> io::Result<Self> {
        let metadata = Metadata::from_file(&root)?;
        check_metadata(&metadata).map_err(io::Error::other)?;
        if !metadata.is_dir() {
            return Err(io::Error::other("share root is not a directory"));
        }
        let mut state = State {
            next: FUSE_ROOT_ID,
            ..State::default()
        };
        state.nodes.insert(
            FUSE_ROOT_ID,
            Node {
                object: Object::Directory(Arc::new(root)),
                lookups: 1,
                location: None,
            },
        );
        Ok(Self(Mutex::new(state)))
    }
}

fn attributes(id: u64, metadata: &Metadata) -> fuse_attr {
    let time = |t: io::Result<cap_std::time::SystemTime>| {
        t.ok()
            .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
            .unwrap_or_default()
    };
    let atime = time(metadata.accessed());
    let mtime = time(metadata.modified());
    fuse_attr {
        ino: id,
        size: metadata.len(),
        blocks: metadata.len().div_ceil(512),
        atime: atime.as_secs(),
        mtime: mtime.as_secs(),
        ctime: mtime.as_secs(),
        atimensec: atime.subsec_nanos(),
        mtimensec: mtime.subsec_nanos(),
        ctimensec: mtime.subsec_nanos(),
        mode: (if metadata.is_dir() {
            lx::S_IFDIR
        } else {
            lx::S_IFREG
        }) | 0o777,
        nlink: 1,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        padding: 0,
    }
}
fn entry(id: u64, metadata: &Metadata) -> fuse_entry_out {
    fuse_entry_out::new(id, Duration::ZERO, Duration::ZERO, attributes(id, metadata))
}
fn access_flags(flags: u32) -> lx::Result<(bool, bool)> {
    match flags as i32 & lx::O_ACCESS_MASK {
        lx::O_RDONLY => Ok((true, false)),
        lx::O_WRONLY => Ok((false, true)),
        lx::O_RDWR => Ok((true, true)),
        _ => Err(lx::Error::EINVAL),
    }
}
fn open_file(state: &mut State, node: u64, flags: u32) -> lx::Result<fuse_open_out> {
    log::trace!("share open node={node} flags={flags:#x}");
    state.handle_capacity()?;
    let (read, write) = access_flags(flags)?;
    let Object::File(file) = state.object(node)? else {
        return Err(lx::Error::EISDIR);
    };
    let file = reopen(&file, read, write)?;
    check_metadata(&Metadata::from_file(&file)?)?;
    if flags as i32 & lx::O_TRUNC != 0 {
        if !write {
            return Err(lx::Error::EACCES);
        }
        file.set_len(0)?;
    }
    let fh = state.id()?;
    state.files.insert(
        fh,
        OpenFile {
            node,
            file,
            read,
            write,
            append: flags as i32 & lx::O_APPEND != 0,
        },
    );
    // Normal FUSE page cache permits executable/private mmap on Linux 5.10.
    // Entry/attribute validity is zero; do not request writeback caching.
    Ok(fuse_open_out::new(fh, 0))
}

impl Fuse for SharedDir {
    fn init(&self, info: &mut SessionInfo) {
        // We do not implement killpriv or atomic truncate on OPEN itself until
        // after validating the pinned file; permission bits are synthetic.
        info.want &= !(FUSE_HANDLE_KILLPRIV | FUSE_WRITEBACK_CACHE);
        // Bound page-backed requests below the virtqueue descriptor limit,
        // including the FUSE header and reply descriptors (Linux 5.10).
        info.max_write = info.max_write.min(MAX_REQUEST);
        info.max_readahead = info.max_readahead.min(MAX_REQUEST);
    }
    fn lookup(&self, request: &Request, name: &lx::LxStr) -> lx::Result<fuse_entry_out> {
        log::trace!("share lookup node={} name={:?}", request.node_id(), name);
        let name = component(name.as_bytes())?;
        let mut state = self.0.lock();
        let object = pin(&state.directory(request.node_id())?, &name)?;
        state.entry(request.node_id(), name, object)
    }
    fn forget(&self, node: u64, count: u64) {
        let mut state = self.0.lock();
        if let Some(n) = state.nodes.get_mut(&node) {
            n.lookups = n.lookups.saturating_sub(count);
        }
        state.collect(node);
    }
    fn get_attr(&self, request: &Request, flags: u32, fh: u64) -> lx::Result<fuse_attr_out> {
        log::trace!(
            "share getattr node={} flags={flags:#x} fh={fh}",
            request.node_id()
        );
        let state = self.0.lock();
        let metadata = if flags & FUSE_GETATTR_FH != 0 {
            let metadata =
                if let Some(file) = state.files.get(&fh).filter(|f| f.node == request.node_id()) {
                    Metadata::from_file(&file.file)?
                } else if state
                    .directories
                    .get(&fh)
                    .is_some_and(|d| d.node == request.node_id())
                {
                    state.object(request.node_id())?.metadata()?
                } else {
                    return Err(lx::Error::EBADF);
                };
            check_metadata(&metadata)?;
            metadata
        } else {
            state.object(request.node_id())?.metadata()?
        };
        Ok(fuse_attr_out::new(
            Duration::ZERO,
            attributes(request.node_id(), &metadata),
        ))
    }
    fn set_attr(&self, request: &Request, arg: &fuse_setattr_in) -> lx::Result<fuse_attr_out> {
        log::trace!(
            "share setattr node={} valid={:#x}",
            request.node_id(),
            arg.valid
        );
        {
            let state = self.0.lock();
            let object = state.object(request.node_id())?;
            object.metadata()?;
            if arg.valid & FATTR_SIZE != 0 {
                if let Object::File(file) = object {
                    if arg.valid & FATTR_FH != 0 {
                        let open = state
                            .files
                            .get(&arg.fh)
                            .filter(|f| f.node == request.node_id() && f.write)
                            .ok_or(lx::Error::EBADF)?;
                        open.file.set_len(arg.size)?;
                    } else {
                        reopen(&file, false, true)?.set_len(arg.size)?;
                    }
                } else {
                    return Err(lx::Error::EISDIR);
                }
            }
            let times = FATTR_ATIME | FATTR_MTIME | FATTR_ATIME_NOW | FATTR_MTIME_NOW;
            if arg.valid & times != 0 {
                let file = match state.object(request.node_id())? {
                    Object::File(file) | Object::Directory(file) => reopen_for_times(&file)?,
                };
                let mut times = std::fs::FileTimes::new();
                let time = |sec, nsec| {
                    if nsec >= 1_000_000_000 {
                        return Err(lx::Error::EINVAL);
                    }
                    UNIX_EPOCH
                        .checked_add(Duration::new(sec, nsec))
                        .ok_or(lx::Error::EINVAL)
                };
                if arg.valid & FATTR_ATIME_NOW != 0 {
                    times = times.set_accessed(std::time::SystemTime::now());
                } else if arg.valid & FATTR_ATIME != 0 {
                    times = times.set_accessed(time(arg.atime, arg.atimensec)?);
                }
                if arg.valid & FATTR_MTIME_NOW != 0 {
                    times = times.set_modified(std::time::SystemTime::now());
                } else if arg.valid & FATTR_MTIME != 0 {
                    times = times.set_modified(time(arg.mtime, arg.mtimensec)?);
                }
                file.set_times(times)?;
            }
            // Guest chmod/chown are accepted without mutating host ownership
            // or permissions. UID, GID and modes are synthesized below.
        }
        self.get_attr(request, 0, 0)
    }
    fn symlink(&self, _: &Request, _: &lx::LxStr, _: &lx::LxStr) -> lx::Result<fuse_entry_out> {
        Err(lx::Error::EPERM)
    }
    fn read_link(&self, _: &Request) -> lx::Result<lx::LxString> {
        Err(lx::Error::EPERM)
    }
    fn link(&self, _: &Request, _: &lx::LxStr, _: u64) -> lx::Result<fuse_entry_out> {
        Err(lx::Error::EPERM)
    }
    fn mknod(&self, _: &Request, _: &lx::LxStr, _: &fuse_mknod_in) -> lx::Result<fuse_entry_out> {
        Err(lx::Error::EPERM)
    }
    fn mkdir(
        &self,
        request: &Request,
        name: &lx::LxStr,
        _: &fuse_mkdir_in,
    ) -> lx::Result<fuse_entry_out> {
        let name = component(name.as_bytes())?;
        let mut state = self.0.lock();
        if state.nodes.len() >= MAX_NODES {
            return Err(lx::Error::ENFILE);
        }
        let parent = state.directory(request.node_id())?;
        #[allow(unused_mut)]
        let mut options = cap_std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use cap_std::fs::DirBuilderExt;
            options.mode(0o700);
        }
        parent.create_dir_with(&name, &options)?;
        state.entry(request.node_id(), name.clone(), pin(&parent, &name)?)
    }
    fn create(
        &self,
        request: &Request,
        name: &lx::LxStr,
        arg: &fuse_create_in,
    ) -> lx::Result<fuse::CreateOut> {
        let name = component(name.as_bytes())?;
        let mut state = self.0.lock();
        state.handle_capacity()?;
        if state.nodes.len() >= MAX_NODES {
            return Err(lx::Error::ENFILE);
        }
        let parent = state.directory(request.node_id())?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            // Guest execute bits are synthetic; never copy them to host files.
            options.mode(0o600);
        }
        let object = match parent.open_with(&name, &options) {
            Ok(file) => Object::File(Arc::new(file.into_std())),
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    && arg.flags as i32 & lx::O_EXCL == 0 =>
            {
                pin(&parent, &name)?
            }
            Err(error) => {
                log::debug!("creating shared file failed: {error}");
                return Err(error.into());
            }
        };
        let entry = state.entry(request.node_id(), name, object)?;
        match open_file(&mut state, entry.nodeid, arg.flags) {
            Ok(open) => Ok(fuse::CreateOut { entry, open }),
            Err(error) => {
                state.nodes.get_mut(&entry.nodeid).unwrap().lookups -= 1;
                state.collect(entry.nodeid);
                Err(error)
            }
        }
    }
    fn open(&self, request: &Request, flags: u32) -> lx::Result<fuse_open_out> {
        open_file(&mut self.0.lock(), request.node_id(), flags)
    }
    fn read(&self, request: &Request, arg: &fuse_read_in) -> lx::Result<Vec<u8>> {
        log::trace!(
            "share read node={} fh={} offset={} size={}",
            request.node_id(),
            arg.fh,
            arg.offset,
            arg.size
        );
        if arg.size as usize > MAX_IO || arg.offset > i64::MAX as u64 {
            return Err(lx::Error::EINVAL);
        }
        let mut state = self.0.lock();
        let file = state
            .files
            .get_mut(&arg.fh)
            .filter(|f| f.node == request.node_id() && f.read)
            .ok_or(lx::Error::EBADF)?;
        check_metadata(&Metadata::from_file(&file.file)?)?;
        let mut data = vec![0; arg.size as usize];
        file.file.seek(SeekFrom::Start(arg.offset))?;
        let n = file.file.read(&mut data)?;
        data.truncate(n);
        Ok(data)
    }
    fn write(&self, request: &Request, arg: &fuse_write_in, data: &[u8]) -> lx::Result<usize> {
        log::trace!(
            "share write node={} fh={} offset={} size={}",
            request.node_id(),
            arg.fh,
            arg.offset,
            arg.size
        );
        if data.len() > MAX_IO || data.len() != arg.size as usize || arg.offset > i64::MAX as u64 {
            return Err(lx::Error::EINVAL);
        }
        let mut state = self.0.lock();
        let file = state
            .files
            .get_mut(&arg.fh)
            .filter(|f| f.node == request.node_id() && f.write)
            .ok_or(lx::Error::EBADF)?;
        check_metadata(&Metadata::from_file(&file.file)?)?;
        file.file.seek(if file.append {
            SeekFrom::End(0)
        } else {
            SeekFrom::Start(arg.offset)
        })?;
        Ok(file.file.write(data)?)
    }
    fn release(&self, request: &Request, arg: &fuse_release_in) -> lx::Result<()> {
        let mut state = self.0.lock();
        if state
            .files
            .get(&arg.fh)
            .is_none_or(|f| f.node != request.node_id())
        {
            return Err(lx::Error::EBADF);
        }
        state.files.remove(&arg.fh);
        state.collect(request.node_id());
        Ok(())
    }
    fn flush(&self, request: &Request, arg: &fuse_flush_in) -> lx::Result<()> {
        let state = self.0.lock();
        state
            .files
            .get(&arg.fh)
            .filter(|f| f.node == request.node_id())
            .ok_or(lx::Error::EBADF)?;
        Ok(())
    }
    fn fsync(&self, request: &Request, fh: u64, flags: u32) -> lx::Result<()> {
        let state = self.0.lock();
        let file = &state
            .files
            .get(&fh)
            .filter(|f| f.node == request.node_id())
            .ok_or(lx::Error::EBADF)?
            .file;
        if flags & 1 != 0 {
            file.sync_data()?;
        } else {
            file.sync_all()?;
        }
        Ok(())
    }
    fn access(&self, request: &Request, _: u32) -> lx::Result<()> {
        self.0
            .lock()
            .object(request.node_id())?
            .metadata()
            .map(|_| ())
    }
    fn unlink(&self, request: &Request, name: &lx::LxStr) -> lx::Result<()> {
        let name = component(name.as_bytes())?;
        let mut state = self.0.lock();
        remove_entry(&state.directory(request.node_id())?, &name, false)?;
        state.detach(&(request.node_id(), name));
        Ok(())
    }
    fn rmdir(&self, request: &Request, name: &lx::LxStr) -> lx::Result<()> {
        let name = component(name.as_bytes())?;
        let mut state = self.0.lock();
        remove_entry(&state.directory(request.node_id())?, &name, true)?;
        state.detach(&(request.node_id(), name));
        Ok(())
    }
    fn rename(
        &self,
        request: &Request,
        name: &lx::LxStr,
        new_dir: u64,
        new_name: &lx::LxStr,
        flags: u32,
    ) -> lx::Result<()> {
        if flags != 0 {
            return Err(lx::Error::EINVAL);
        }
        let name = component(name.as_bytes())?;
        let new_name = component(new_name.as_bytes())?;
        let mut state = self.0.lock();
        let from = (request.node_id(), name);
        let to = (new_dir, new_name);
        if from == to {
            return Ok(());
        }
        let parent = state.directory(from.0)?;
        // Validate the source too; rename itself never follows the final component.
        pin(&parent, &from.1)?;
        rename_entry(&parent, &from.1, &state.directory(to.0)?, &to.1)?;
        state.detach(&to);
        if let Some(id) = state.detach(&from) {
            state.nodes.get_mut(&id).unwrap().location = Some(to.clone());
            state.names.insert(to, id);
        }
        Ok(())
    }
    fn open_dir(&self, request: &Request, _: u32) -> lx::Result<fuse_open_out> {
        let mut state = self.0.lock();
        state.handle_capacity()?;
        let dir = state.directory(request.node_id())?;
        let mut entries = vec![
            (OsString::from("."), lx::S_IFDIR),
            (OsString::from(".."), lx::S_IFDIR),
        ];
        let mut bytes = 2 * ENTRY_BYTES + 3;
        for item in dir.entries()? {
            let item = item?;
            let name = item.file_name();
            let Some(raw) = name_bytes(&name) else {
                continue;
            };
            if component(raw).is_err() {
                continue;
            }
            let object = match pin(&dir, &name) {
                Ok(object) => object,
                Err(_) => continue, // inaccessible/special/link entries are not exported
            };
            bytes += raw.len() + ENTRY_BYTES;
            if state.directory_bytes + bytes > MAX_DIRECTORY_BYTES {
                return Err(lx::Error::ENOMEM);
            }
            let kind = match object {
                Object::Directory(_) => lx::S_IFDIR,
                Object::File(_) => lx::S_IFREG,
            };
            entries.push((name, kind));
        }
        if state.directory_bytes + bytes > MAX_DIRECTORY_BYTES {
            return Err(lx::Error::ENOMEM);
        }
        let fh = state.id()?;
        state.directory_bytes += bytes;
        state.directories.insert(
            fh,
            OpenDirectory {
                node: request.node_id(),
                entries,
                bytes,
            },
        );
        Ok(fuse_open_out::new(fh, 0))
    }
    fn read_dir(&self, request: &Request, arg: &fuse_read_in) -> lx::Result<Vec<u8>> {
        if arg.size as usize > MAX_IO {
            return Err(lx::Error::EINVAL);
        }
        let state = self.0.lock();
        let dir = state
            .directories
            .get(&arg.fh)
            .filter(|d| d.node == request.node_id())
            .ok_or(lx::Error::EBADF)?;
        let offset = usize::try_from(arg.offset).map_err(|_| lx::Error::EINVAL)?;
        let node = request.node_id();
        let mut data = Vec::with_capacity(arg.size as usize);
        for (index, (name, kind)) in dir.entries.iter().enumerate().skip(offset) {
            let raw = name_bytes(name).ok_or(lx::Error::EINVAL)?;
            // Match getattr for known nodes; entries not looked up yet have no node ID.
            let ino = match index {
                0 => node,
                1 if node == FUSE_ROOT_ID => node,
                1 => state
                    .nodes
                    .get(&node)
                    .and_then(|n| n.location.as_ref())
                    .map_or(UNKNOWN_INO, |l| l.0),
                _ => state
                    .names
                    .get(&(node, name.clone()))
                    .copied()
                    .unwrap_or(UNKNOWN_INO),
            };
            if !data.dir_entry(
                lx::LxStr::from_bytes(raw),
                ino,
                index as u64 + 1,
                *kind >> 12,
            ) {
                break;
            }
        }
        Ok(data)
    }
    fn statfs(&self, _: &Request) -> lx::Result<fuse_kstatfs> {
        let root = self.0.lock().directory(FUSE_ROOT_ID)?;
        filesystem_stats(&root)
    }
    fn fsync_dir(&self, request: &Request, fh: u64, _: u32) -> lx::Result<()> {
        let state = self.0.lock();
        state
            .directories
            .get(&fh)
            .filter(|d| d.node == request.node_id())
            .ok_or(lx::Error::EBADF)?;
        match state.object(request.node_id())? {
            Object::Directory(file) => sync_directory(&file),
            Object::File(_) => Err(lx::Error::ENOTDIR),
        }
    }
    fn release_dir(&self, request: &Request, arg: &fuse_release_in) -> lx::Result<()> {
        let mut state = self.0.lock();
        if state
            .directories
            .get(&arg.fh)
            .is_none_or(|d| d.node != request.node_id())
        {
            return Err(lx::Error::EBADF);
        }
        let dir = state.directories.remove(&arg.fh).unwrap();
        state.directory_bytes -= dir.bytes;
        state.collect(request.node_id());
        Ok(())
    }
}

#[cfg(test)]
mod tests;

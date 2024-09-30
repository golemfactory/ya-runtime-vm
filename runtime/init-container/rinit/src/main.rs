use libc::{
    c_char, c_int, ifreq, reboot, size_t, strncpy, sync, IFF_LOOPBACK, IFF_UP, RB_POWER_OFF,
};
use nix::errno::Errno;
use nix::mount::{mount, MsFlags};
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::eventfd::EventFd;
use nix::sys::signal::{self, sigprocmask, SigSet};
use nix::sys::signalfd::{self, SignalFd};
use nix::sys::signalfd::{signalfd, SfdFlags};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use nix::sys::stat::{mknod, Mode, SFlag};
use nix::unistd::{chdir, chroot, fsync, symlinkat};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::mem::transmute;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{
    arch::asm,
    env,
    io::{Error, ErrorKind},
    os::unix::fs::PermissionsExt,
    path::Path,
    ptr,
};

use libc::{
    in_addr, mode_t, open, prctl, snprintf, sockaddr_in, AF_INET, O_CLOEXEC, O_DIRECTORY,
    O_NOFOLLOW, O_RDONLY, PR_SET_DUMPABLE,
};

const DEV_VPN: &str = "eth0";
const DEV_INET: &str = "eth1";

const IRWXU_PERMS: mode_t = 0o700;
const DEFAULT_DIR_PERMS: mode_t = 0o755;
const NEW_ROOT: &str = "newroot";
const SYSROOT: &str = "/mnt/newroot";
const OUTPUT_PATH_PREFIX: &str = "/var/tmp/guest_agent_private/fds";
const NONE: Option<&'static [u8]> = None;

const VPORT_CMD: &str = "/dev/vport0p1";
const VPORT_NET: &str = "/dev/vport0p2";
const VPORT_INET: &str = "/dev/vport0p3";

const NET_MEM_DEFAULT: usize = 1048576;
const NET_MEM_MAX: usize = 2097152;
const MTU_VPN: usize = 1220;
const MTU_INET: usize = 65521;

enum EpollFdType {
    Cmds,
    Sig,
    Out,
    In,
}

enum MessageRunProcessType {
    Bin,
    Arg,
    Env,
    Uid,
    Gid,
    Rfd,
    Cwd,
    Ent,
}

enum MessageKillProcessType {
    Pid,
}

enum MessageMountVolumeType {
    Tag,
    Path,
}

enum MessageUploadFileType {
    Path,
    Perm,
    User,
    Group,
    Data,
}

#[derive(Default, Debug)]
enum MessageType {
    #[default]
    None = 0,
    Quit = 1,
    RunProcess,
    KillProcess,
    MountVolume,
    UploadFile,
    QueryOutput,
    PutInput,
    SyncFs,
    NetCtl,
    NetHost,
}

enum Response {
    Ok = 0,
    Error = 3,
}

#[derive(Debug)]
struct MessageHeader {
    pub msg_id: u64,
    pub msg_type: u8,
}

impl MessageType {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Quit,
            2 => Self::RunProcess,
            3 => Self::KillProcess,
            4 => Self::MountVolume,
            5 => Self::UploadFile,
            6 => Self::QueryOutput,
            7 => Self::PutInput,
            8 => Self::SyncFs,
            9 => Self::NetCtl,
            10 => Self::NetHost,
            _ => Self::None,
        }
    }
}

impl MessageHeader {
    fn from_ne_bytes(buf: &[u8]) -> Self {
        Self {
            msg_id: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            msg_type: buf[8],
        }
    }

    fn to_ne_bytes(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[0..8].copy_from_slice(&self.msg_id.to_le_bytes());
        buf[8] = self.msg_type;
        buf
    }
}

static ALIAS_COUNTER: AtomicU32 = AtomicU32::new(0);
static mut SIG_FD: Option<SignalFd> = None;
static mut CMDS_FD: Option<File> = None;
// static mut CMDS_FD: Option<i32> = None;

extern "C" {
    pub fn inet_pton(
        __af: ::std::os::raw::c_int,
        __cp: *const ::std::os::raw::c_char,
        __buf: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}

macro_rules! die {
    ($expr:expr) => {
        unsafe {
            sync();
        }

        loop {
            unsafe {
                eprintln!("Error: {:?}", $expr);
                reboot(RB_POWER_OFF);
                asm!("hlt");
                unreachable!();
            }
        }
    };
}

macro_rules! check {
    ($expr:expr) => {
        if $expr == -1 {
            panic!("Error: {:?}", $expr);
        }
    };
}

macro_rules! check_result {
    ($expr:expr) => {
        if $expr.is_err() {
            die!($expr);
        }
    };
}

macro_rules! check_bool {
    ($expr:expr) => {
        if !$expr {
            die!($expr);
        }
    };
}

impl From<EpollFdType> for u64 {
    fn from(fd_type: EpollFdType) -> Self {
        match fd_type {
            EpollFdType::Cmds => 1,
            EpollFdType::Sig => 2,
            EpollFdType::Out => 3,
            EpollFdType::In => 4,
        }
    }
}

fn write_sys(path: &str, value: usize) {
    std::fs::write(path, format!("{}", value));
}

fn copy_initramfs_recursive(
    dirfd: libc::c_int,
    newdirfd: libc::c_int,
    skip_name: &str,
) -> Result<(), Error> {
    check_bool!(newdirfd != dirfd);
    let d = unsafe { libc::fdopendir(dirfd) };
    check_bool!(!d.is_null());

    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(d) };
        if entry.is_null() {
            check_bool!(unsafe { *libc::__errno_location() } == 0);
            break;
        }
        let entry = unsafe { &*entry };
        let entry_name = unsafe { std::ffi::CStr::from_ptr(entry.d_name.as_ptr()) }
            .to_str()
            .unwrap();
        if entry_name == "." || entry_name == ".." || entry_name == skip_name {
            continue;
        }

        let mut statbuf: libc::stat = unsafe { std::mem::zeroed() };
        check!(unsafe {
            libc::fstatat(
                dirfd,
                entry.d_name.as_ptr(),
                &mut statbuf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        });

        match statbuf.st_mode & libc::S_IFMT {
            libc::S_IFCHR | libc::S_IFBLK | libc::S_IFSOCK | libc::S_IFIFO => {
                check!(unsafe {
                    libc::mknodat(
                        newdirfd,
                        entry.d_name.as_ptr(),
                        statbuf.st_mode,
                        statbuf.st_rdev,
                    )
                });
            }
            libc::S_IFLNK => {
                let buf = vec![0u8; statbuf.st_size as usize + 1];
                let size = unsafe {
                    libc::readlinkat(
                        dirfd,
                        entry.d_name.as_ptr(),
                        buf.as_ptr() as *mut i8,
                        buf.len(),
                    )
                };
                check!(size);
                check_bool!(size == statbuf.st_size as isize);
                let buf = CString::new(&buf[..size as usize]).unwrap();
                check!(unsafe { libc::symlinkat(buf.as_ptr(), newdirfd, entry.d_name.as_ptr()) });
            }
            libc::S_IFREG => {
                let mut size = statbuf.st_size as u64;
                let srcfd = unsafe {
                    libc::openat(
                        dirfd,
                        entry.d_name.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                check!(srcfd);
                let dstfd = unsafe {
                    libc::openat(
                        newdirfd,
                        entry.d_name.as_ptr(),
                        libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_CREAT,
                        statbuf.st_mode & 0o7777,
                    )
                };
                check!(dstfd);
                while size > 0 {
                    let res = unsafe {
                        libc::sendfile(
                            dstfd,
                            srcfd,
                            ptr::null_mut(),
                            size.min(usize::MAX as u64) as libc::size_t,
                        )
                    };
                    check!(res);
                    size -= res as u64;
                }
                check!(unsafe { libc::close(dstfd) });
                check!(unsafe { libc::close(srcfd) });
            }
            libc::S_IFDIR => {
                let old_child_dirfd = unsafe {
                    libc::openat(
                        dirfd,
                        entry.d_name.as_ptr(),
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
                    )
                };
                check!(old_child_dirfd);
                check!(unsafe {
                    libc::mkdirat(newdirfd, entry.d_name.as_ptr(), statbuf.st_mode & 0o7777)
                });
                let new_child_dirfd = unsafe {
                    libc::openat(
                        newdirfd,
                        entry.d_name.as_ptr(),
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
                    )
                };
                check!(new_child_dirfd);
                copy_initramfs_recursive(old_child_dirfd, new_child_dirfd, "")?;
            }
            _ => {
                check_bool!(false);
            }
        }
        check!(unsafe {
            libc::unlinkat(
                dirfd,
                entry.d_name.as_ptr(),
                if (statbuf.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                    libc::AT_REMOVEDIR
                } else {
                    0
                },
            )
        });
    }

    check!(unsafe { libc::closedir(d) });
    check!(unsafe { libc::close(newdirfd) });

    Ok(())
}

fn copy_initramfs() -> Result<(), Error> {
    println!("Copying initramfs from '/' to '/newroot'");

    check_bool!(Path::new("/").exists());
    check_bool!(Path::new("/").join(NEW_ROOT).exists());

    mount(Some(""), "/newroot", Some("tmpfs"), MsFlags::empty(), NONE)?;

    let root = CString::new("/").unwrap();
    let root_fd = unsafe {
        open(
            root.as_ptr(),
            O_DIRECTORY | O_NOFOLLOW | O_RDONLY | O_CLOEXEC,
        )
    };

    let new_dir = CString::new(NEW_ROOT).unwrap();
    let new_dir_fd = unsafe {
        libc::open(
            new_dir.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };

    check!(new_dir_fd);

    copy_initramfs_recursive(root_fd, new_dir_fd, NEW_ROOT)?;

    println!("Initramfs copied successfully");

    Ok(())
}

fn load_module(module: &str) -> io::Result<()> {
    let path = format!("/{}", module);
    println!("Loading kernel module '{}'", path);

    let path = Path::new(&path);
    check_bool!(path.exists());

    let file = File::open(path)?;

    let params = CString::new("").unwrap();

    unsafe {
        let result = libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0);

        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

fn load_modules() -> io::Result<()> {
    let modules = [
        (false, "failover.ko"),
        (false, "virtio.ko"),
        (false, "virtio_ring.ko"),
        (true, "virtio_pci_modern_dev.ko"),
        (true, "virtio_pci_legacy_dev.ko"),
        (false, "virtio_pci.ko"),
        (false, "net_failover.ko"),
        (false, "virtio_net.ko"),
        (false, "virtio_console.ko"),
        (false, "rng-core.ko"),
        (false, "virtio-rng.ko"),
        (false, "virtio_blk.ko"),
        (false, "mbcache.ko"),
        (false, "ext2.ko"),
        (false, "squashfs.ko"),
        (false, "overlay.ko"),
        (true, "netfs.ko"),
        (false, "fscache.ko"),
        (false, "af_packet.ko"),
        (false, "ipv6.ko"),
        (false, "tun.ko"),
        (false, "9pnet.ko"),
        (false, "9pnet_virtio.ko"),
        (false, "9p.ko"),
    ];

    for (check, module) in modules.iter() {
        if *check {
            let path = format!("/{}", module);
            println!("Checking if kernel module '{}' exists", path);
            if Path::new(&path).exists() {
                load_module(module)?;
            }
        } else {
            load_module(module)?;
        }
    }

    if Path::new("/nvidia.ko").exists() {
        load_nvidia_modules()?;
    }

    Ok(())
}

fn load_nvidia_modules() -> io::Result<()> {
    let nvidia_modules = [
        "i2c-core.ko",
        "drm_panel_orientation_quirks.ko",
        "firmware_class.ko",
        "drm.ko",
        "nvidia.ko",
        "nvidia-uvm.ko",
        "fbdev.ko",
        "fb.ko",
        "fb_sys_fops.ko",
        "cfbcopyarea.ko",
        "cfbfillrect.ko",
        "cfbimgblt.ko",
        "syscopyarea.ko",
        "sysfillrect.ko",
        "sysimgblt.ko",
        "drm_kms_helper.ko",
        "nvidia-modeset.ko",
        "nvidia-drm.ko",
    ];

    for module in nvidia_modules.iter() {
        load_module(module)?;
    }

    Ok(())
}

fn mount_core_filesystems() -> io::Result<()> {
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755,size=2M"),
    )?;

    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        NONE,
    )?;

    Ok(())
}

fn chroot_to_new_root() -> io::Result<()> {
    chdir(&Path::new("/").join(NEW_ROOT))?;
    mount(Some("."), "/", NONE, MsFlags::MS_MOVE, NONE)?;
    chroot(".")?;
    mount(NONE, ".", NONE, MsFlags::MS_SHARED, NONE)?;

    Ok(())
}

fn create_directories() -> io::Result<()> {
    for dir in ["/dev", "/sys", SYSROOT] {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;
    }

    for dir in ["/mnt", "/proc", "/mnt/overlay"] {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(IRWXU_PERMS))?;
    }

    Ok(())
}

#[derive(Debug)]
struct Storage {
    path: String,
    dev: String,
    fs_type: String,
    data: Option<String>,
    flags: MsFlags,
}

fn scan_storage() -> io::Result<Vec<Storage>> {
    let block_dir = Path::new("/sys/class/block");

    let mut storage = Vec::new();

    for entry in fs::read_dir(block_dir)? {
        let entry = entry?;
        let path = entry.path();

        let filename = path.file_name().unwrap().to_str().unwrap();

        if !filename.starts_with("vd") {
            continue;
        }

        // println!("Found virtio-blk: '{}'", path.display());

        let serial_path = path.join("serial");

        if !serial_path.exists() {
            println!("Path '{}' does not exist", serial_path.display());
            continue;
        }

        let serial = fs::read_to_string(serial_path)?;

        let dev_path = format!("/dev/{}", filename);

        if serial.starts_with("rootfs-") {
            let rootfs_layer = if let Some((_, layer)) = serial.split_once("rootfs-") {
                layer.parse::<u32>().unwrap()
            } else {
                println!("Failed to parse rootfs layer from '{}'", serial);
                continue;
            };

            let rootfs_path = format!("/mnt/image-{}", rootfs_layer);

            println!(
                "Storage volume {} [{}] to be mounted at {} with data=''.",
                serial, dev_path, rootfs_path
            );

            storage.push(Storage {
                path: rootfs_path,
                dev: dev_path,
                fs_type: "squashfs".to_string(),
                data: None,
                flags: MsFlags::MS_RDONLY | MsFlags::MS_NODEV,
            });

            continue;
        }

        if !serial.starts_with("vol-") {
            println!(
                "Unknown virtio-blk: '{}', with serial '{}'",
                path.display(),
                serial
            );
            continue;
        }

        println!(
            "Found virtio-blk: '{}', with serial '{}', format as ext2",
            path.display(),
            serial
        );

        do_mkfs(&dev_path)?;

        let vol_path = format!("{}-path", serial);
        let mount_point = std::env::var(vol_path.clone()).map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", vol_path),
            )
        })?;

        let vol_errors = format!("{}-errors", serial);
        let errors = std::env::var(vol_errors.clone()).map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", vol_errors),
            )
        })?;
        let data = format!("errors={}", errors);

        println!(
            "Storage volume {} [{}] to be mounted at {} with data='{}'.",
            serial, dev_path, mount_point, data
        );

        storage.push(Storage {
            path: mount_point,
            dev: dev_path,
            fs_type: "ext2".to_string(),
            data: Some(data),
            flags: MsFlags::MS_NODEV,
        });
    }

    for (var, value) in env::vars() {
        if !(var.starts_with("vol-") && var.ends_with("-size")) {
            continue;
        }

        let parts: Vec<&str> = var.split('-').collect();
        let volume_id = parts[1].parse::<u32>().map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Failed to parse volume id from '{}'", var),
            )
        })?;

        let volume_path = format!("vol-{}-path", volume_id);
        let mount_point = std::env::var(volume_path.clone()).map_err(|_| {
            Error::new(
                ErrorKind::NotFound,
                format!("Failed to find '{}' environment variable", volume_path),
            )
        })?;

        let volume_size = value.parse::<u64>().unwrap();

        println!(
            "Found tmpfs volume '{}': '{}', size: {}",
            volume_id, mount_point, volume_size
        );

        let data = format!("mode=0700,size={}", volume_size);

        storage.push(Storage {
            path: mount_point,
            dev: "tmpfs".to_string(),
            fs_type: "tmpfs".to_string(),
            data: Some(data),
            flags: MsFlags::MS_NODEV,
        });
    }

    println!("Found storage:");
    for s in storage.iter() {
        println!(
            " path = '{}' @ '{}' fstype = '{}' data = {:?} flags = {:?}",
            s.path, s.dev, s.fs_type, s.data, s.flags
        );
    }

    Ok(storage)
}

fn do_mkfs(dev_path: &str) -> io::Result<()> {
    std::process::Command::new("/mkfs.ext2")
        .arg(dev_path)
        .spawn()?;

    Ok(())
}

fn mount_overlay(storage: &[Storage]) -> io::Result<()> {
    if let Some(s) = storage.iter().find(|s| s.path == "/") {
        println!(
            "Mounting tmpfs to /mnt/overlay fstype: '{}' flags: '{:?}' data: {:?}",
            s.fs_type, s.flags, s.data
        );

        mount(
            Some(s.dev.as_str()),
            "/mnt/overlay",
            Some(s.fs_type.as_str()),
            s.flags,
            s.data.as_deref(),
        )?;
        // } else {
        //     return Err(Error::new(
        //         ErrorKind::NotFound,
        //         "Failed to find root storage volume for /mnt/overlay",
        //     ));
    }

    for s in storage.iter() {
        if !s.path.starts_with("/mnt/image-") {
            continue;
        }

        println!(
            "Mounting rootfs {} to {} fstype: '{}' flags: {:?} data: {:?}",
            s.dev, s.path, s.fs_type, s.flags, s.data
        );

        fs::create_dir_all(s.path.clone())?;
        fs::set_permissions(s.path.clone(), fs::Permissions::from_mode(IRWXU_PERMS))?;

        mount(
            Some(s.dev.as_str()),
            s.path.as_str(),
            Some(s.fs_type.as_str()),
            s.flags,
            s.data.as_deref(),
        )?;
    }

    for dir in ["/mnt/overlay/upper", "/mnt/overlay/work"] {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(IRWXU_PERMS))?;
    }

    let rootfs_layers: Vec<String> = storage
        .iter()
        .filter(|s| s.path.starts_with("/mnt/image-"))
        .map(|s| s.path.clone())
        .collect();

    let rootfs_layers = rootfs_layers.join(":");
    let overlay_data = format!(
        "lowerdir={},upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work",
        rootfs_layers
    );

    println!(
        "Mounting overlay to /mnt/newroot fstype: 'overlay' flags: '{:?}' data: {:?}",
        MsFlags::MS_NODEV,
        overlay_data
    );

    mount(
        Some("overlay"),
        SYSROOT,
        Some("overlay"),
        MsFlags::MS_NODEV,
        Some(overlay_data.as_str()),
    )?;

    Ok(())
}

fn mount_sysroot() -> io::Result<()> {
    let sysroot = Path::new(SYSROOT);
    for dir in [sysroot.join("dev").as_path(), sysroot.join("tmp").as_path()] {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;
    }

    let default_mount_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;

    mount(
        Some("proc"),
        Path::new("/proc"),
        Some("proc"),
        default_mount_flags,
        NONE,
    )?;

    mount(
        Some("proc"),
        sysroot.join("proc").as_path(),
        Some("proc"),
        default_mount_flags,
        NONE,
    )?;

    mount(
        Some("sysfs"),
        sysroot.join("sys").as_path(),
        Some("sysfs"),
        default_mount_flags,
        NONE,
    )?;

    mount(
        Some("devtmpfs"),
        sysroot.join("dev").as_path(),
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755,size=2M"),
    )?;

    symlinkat("/proc/self/fd", None, sysroot.join("dev/fd").as_path())?;

    mount(
        Some("tmpfs"),
        sysroot.join("tmp").as_path(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755"),
    )?;

    let dev_pts = sysroot.join("dev/pts");
    let dev_shm = sysroot.join("dev/shm");
    for dir in [dev_pts.as_path(), dev_shm.as_path()] {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;
    }

    mount(
        Some("devpts"),
        dev_pts.as_path(),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("gid=5,mode=0620"),
    )?;

    mount(
        Some("tmpfs"),
        dev_shm.as_path(),
        Some("tmpfs"),
        default_mount_flags,
        NONE,
    )?;

    let mode_rw_ugo = Mode::S_IRUSR
        | Mode::S_IWUSR
        | Mode::S_IRGRP
        | Mode::S_IWGRP
        | Mode::S_IROTH
        | Mode::S_IWOTH;

    let dev_null = sysroot.join("dev/null");
    if !dev_null.exists() {
        mknod(
            dev_null.as_path(),
            SFlag::S_IFCHR,
            mode_rw_ugo,
            libc::makedev(1, 3),
        )?;
    }

    let dev_ptmx = sysroot.join("dev/ptmx");
    if !dev_ptmx.exists() {
        mknod(
            dev_ptmx.as_path(),
            SFlag::S_IFCHR,
            mode_rw_ugo,
            libc::makedev(5, 2),
        )?;
    }

    Ok(())
}

fn main() {
    unsafe {
        let result = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        check_bool!(result == 0 || result == 1);
    }

    println!("Program args count: {}, args:", env::args().len());
    for arg in env::args() {
        println!("  {}", arg);
    }

    println!("Environment vars:");
    for (env, val) in env::vars() {
        println!("  {} = {}", env, val);
    }

    let result = copy_initramfs();
    check_result!(result);

    let result = chroot_to_new_root();
    check_result!(result);

    let result = create_directories();
    check_result!(result);

    let result = mount_core_filesystems();
    check_result!(result);

    let result = load_modules();
    check_result!(result);

    let storage = scan_storage();
    check_result!(storage);

    let storage = storage.unwrap();

    let result = mount_overlay(&storage);
    check_result!(result);

    let result = mount_sysroot();
    check_result!(result);

    // TODO(aljen): Handle 'sandbox' environment variable
    // TODO(aljen): Handle 'nvidia_loaded'

    let result = setup_sandbox();
    check_result!(result);

    let result = setup_network();
    check_result!(result);

    let result = setup_agent_directories();
    check_result!(result);

    let result = block_signals();
    check_result!(result);

    let result = setup_sigfd();
    check_result!(result);

    let result = main_loop();
    check_result!(result);

    let result = stop_network();
    check_result!(result);

    die!("Finished");
}

fn stop_network() -> io::Result<()> {
    Ok(())
}

fn main_loop() -> io::Result<()> {
    let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;

    unsafe {
        CMDS_FD = Some(
            File::options()
                .read(true)
                .write(true)
                .append(true)
                .open(VPORT_CMD)?,
        );
        // let cmds_fd = nix::fcntl::open(
        //     VPORT_CMD,
        //     nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_CLOEXEC,
        //     nix::sys::stat::Mode::empty(),
        // )?;
        // CMDS_FD = Some(cmds_fd);

        epoll.add(
            CMDS_FD.as_ref().unwrap(),
            // cmds_fd,
            EpollEvent::new(EpollFlags::EPOLLIN, EpollFdType::Cmds.into()),
        )?;

        epoll.add(
            SIG_FD.as_ref().unwrap(),
            EpollEvent::new(EpollFlags::EPOLLIN, EpollFdType::Sig.into()),
        )?;
    }

    let mut events = [EpollEvent::empty()];

    loop {
        let result = epoll.wait(&mut events, EpollTimeout::NONE)?;

        match result {
            n if n < 0 => {
                return Err(io::Error::last_os_error());
            }
            0 => {
                println!("Timeout");
                break;
            }
            _ => {
                println!("Event: {:?}", events[0]);
                let event = &events[0];
                if event.events() == EpollFlags::EPOLLERR && event.data() == EpollFdType::Out.into()
                {
                    println!("Invalid event");
                    die!("Invalid event");
                }

                match event.data() {
                    x if x == EpollFdType::Cmds.into() => {
                        if event.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN {
                            println!("Command event");
                            handle_message();
                            // let mut buf = [0u8; 8];
                            // g_cmds_fd.read_exact(&mut buf)?;

                            // let cmd = u64::from_ne_bytes(buf);

                            // println!("Command: {}", cmd);

                            // if cmd == 0 {
                            //     break;
                            // }
                        }
                    }
                    x if x == EpollFdType::Sig.into() => {
                        if event.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN {
                            println!("Signal event");
                            handle_sigchld();
                            // let mut buf = [0u8; 8];
                            // SIG_FD.as_ref().unwrap().read_exact(&mut buf)?;

                            // let siginfo = signal::siginfo_t::from_ne_bytes(buf);

                            // println!("Signal: {}", siginfo.ssi_signo);
                        }
                    }
                    x if x == EpollFdType::Out.into() => {
                        die!("Out not implemented");
                    }
                    x if x == EpollFdType::In.into() => {
                        if event.events() & EpollFlags::EPOLLIN == EpollFlags::EPOLLIN {
                            println!("In event [EPOLLIN]");
                        } else if event.events() & EpollFlags::EPOLLHUP == EpollFlags::EPOLLHUP {
                            println!("In event [EPOLLHUP]");
                        }
                    }
                    _ => {
                        die!("Unknown event");
                    }
                }
            }
        }
    }

    Ok(())
}

fn handle_sigchld() {
    let mut buf = [0u8; 16];

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };
    // let mut cmds_fd = unsafe { CMDS_FD.expect("CMDS_FD should be initialized") };

    // let result = cmds_fd.read(&mut buf);
    let result = nix::unistd::read(cmds_fd.as_raw_fd(), &mut buf);

    match result {
        Ok(read) => println!("handle_sigchld: Read {} bytes", read),
        Err(e) => {
            die!(e);
        }
    }
}

fn readn(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        let result = nix::unistd::read(fd, &mut buf[total..])?;
        // let result = fd.read(&mut buf[total..])?;
        if result == 0 {
            println!("Waiting for host connection...");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }

        total += result;
    }

    Ok(total)
}

fn write_fd(fd: i32, buf: &[u8]) -> usize {
    let res = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len() as size_t) };

    res as usize
}

fn writen(fd: i32, buf: &[u8]) -> io::Result<usize> {
    let mut total = 0;

    while total < buf.len() {
        let result = write_fd(fd, &buf[total..]);
        // let result = fd.write(&buf[total..])?;
        if result == 0 {
            println!("Waiting for host connection...");
            std::thread::sleep(std::time::Duration::from_millis(1000));
            continue;
        }

        total += result;
    }

    Ok(total)
}

fn send_i32(fd: i32, value: i32) {
    let buf = value.to_ne_bytes();
    let result = write_fd(fd, &buf);
    // println!("Sent {} bytes", result);
}

fn recv_u8(fd: i32) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    let result = readn(fd, &mut buf)?;

    if result < 1 {
        die!("Failed to read u8");
    }

    Ok(buf[0])
}

fn recv_u64(fd: i32) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    let result = readn(fd, &mut buf)?;

    if result < 8 {
        die!("Failed to read u64");
    }

    Ok(u64::from_ne_bytes(buf))
}

fn handle_message() -> io::Result<()> {
    let mut buf = [0u8; 9];

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };
    // let mut cmds_fd = unsafe { CMDS_FD.expect("CMDS_FD should be initialized") };

    // let result = cmds_fd.read(&mut buf);
    // let result = nix::unistd::read(cmds_fd.as_raw_fd(), &mut buf);
    let size = readn(cmds_fd.as_raw_fd(), &mut buf)?;

    println!("Handling message: {:?}", buf);

    let msg_header = MessageHeader::from_ne_bytes(&buf);
    println!(" Message header: {:?} ({})", msg_header, size);

    let message_type = MessageType::from_u8(msg_header.msg_type);

    match message_type {
        MessageType::Quit => {
            println!("  Quit message");
            handle_quit(msg_header.msg_id);
        }
        MessageType::RunProcess => {
            println!("  Run process message");
        }
        MessageType::KillProcess => {
            println!("  Kill process message");
        }
        MessageType::MountVolume => {
            println!("  Mount volume message");
            handle_mount(msg_header.msg_id);
        }
        MessageType::UploadFile => {
            println!("  Upload file message");
            send_response_error(msg_header.msg_id, libc::EPROTONOSUPPORT as i32);
        }
        MessageType::QueryOutput => {
            println!("  Query output message");
        }
        MessageType::PutInput => {
            println!("  Put input message");
        }
        MessageType::SyncFs => {
            println!("  Sync fs message");
        }
        MessageType::NetCtl => {
            println!("  Net control message");
        }
        MessageType::NetHost => {
            println!("  Net host message");
        }
        _ => {
            die!("  Unknown message type");
        }
    }

    Ok(())
}

fn handle_mount(message_id: u64) {
    let mut done = false;

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") }.as_raw_fd();

    while !done {
        let cmd = recv_u8(cmds_fd).expect("Failed to read command");

        match cmd {
            // VOLUME_END
            0 => {
                println!("    Done");
                done = true;
            }
            // VOLUME_TAG
            1 => {
                println!("   Volume tag");
                let size = recv_u64(cmds_fd).expect("Failed to read size");
                println!("    Size: {}", size);
                let mut buf = vec![0u8; size as usize];
                let result = readn(cmds_fd, &mut buf).expect("Failed to read tag");
                let string = String::from_utf8(buf).expect("Failed to convert tag to string");
                println!("    Tag: {}", string);
            }
            // VOLUME_PATH
            2 => {
                println!("   Volume path");
                let size = recv_u64(cmds_fd).expect("Failed to read size");
                println!("    Size: {}", size);
                let mut buf = vec![0u8; size as usize];
                let result = readn(cmds_fd, &mut buf).expect("Failed to read path");
                let string = String::from_utf8(buf).expect("Failed to convert path to string");
                println!("    Path: {}", string);
            }
            _ => {
                println!("   Unknown command");
                send_response_error(message_id, libc::EPROTONOSUPPORT as i32);
            }
        }
    }

    send_response_ok(message_id);
}

fn send_response_error(msg_id: u64, err_type: i32) {
    send_response_header(msg_id, Response::Error);

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };

    send_i32(cmds_fd.as_raw_fd(), err_type);
}

fn handle_quit(message_id: u64) {
    println!("Quitting...");

    send_response_ok(message_id);

    die!("Exit");
}

fn send_response_ok(message_id: u64) {
    send_response_header(message_id, Response::Ok);
}

fn send_response_header(message_id: u64, msg_type: Response) {
    let header = MessageHeader {
        msg_id: message_id,
        msg_type: msg_type as u8,
    };

    let cmds_fd = unsafe { CMDS_FD.as_ref().expect("CMDS_FD should be initialized") };

    println!(
        " Sending response header: {:?} ({:?})",
        header,
        header.to_ne_bytes(),
    );

    let result = writen(cmds_fd.as_raw_fd(), &header.to_ne_bytes());
    println!("result: {:?} errno: {:?}", result, Errno::last());
}

fn setup_sigfd() -> io::Result<()> {
    let mut set = SigSet::empty();
    set.add(signal::SIGCHLD);

    unsafe {
        SIG_FD = Some(SignalFd::with_flags(&set, SfdFlags::SFD_CLOEXEC)?);
    }

    Ok(())
}

fn block_signals() -> io::Result<()> {
    let mut set = SigSet::empty();
    set.add(signal::SIGCHLD);
    set.add(signal::SIGPIPE);
    sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&set), None)?;

    Ok(())
}

fn setup_agent_directories() -> io::Result<()> {
    let dir = Path::new(OUTPUT_PATH_PREFIX);
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(DEFAULT_DIR_PERMS))?;

    Ok(())
}

fn add_network_hosts(entries: &[(&str, &str)]) -> io::Result<()> {
    let mut f = BufWriter::new(
        File::options()
            .append(true)
            .open(format!("{}/etc/hosts", SYSROOT))?,
    );

    for entry in entries.iter() {
        match f.write_fmt(format_args!("{}\t{}\n", entry.0, entry.1)) {
            Ok(_) => (),
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    f.flush()?;

    match f.into_inner() {
        Ok(file) => fsync(file.as_raw_fd())?,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }

    Ok(())
}

fn set_network_ns(entries: &[&str]) -> io::Result<()> {
    let mut f = BufWriter::new(
        File::options()
            .write(true)
            .truncate(true)
            .open(format!("{}/etc/resolv.conf", SYSROOT))?,
    );

    for entry in entries.iter() {
        match f.write_fmt(format_args!("nameserver {}\n", entry)) {
            Ok(_) => (),
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    f.flush()?;

    match f.into_inner() {
        Ok(file) => fsync(file.as_raw_fd())?,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }

    Ok(())
}

fn net_create_lo(name: &str) -> nix::Result<c_int> {
    // Open a socket with None as the protocol to match the expected Option<SockProtocol> type

    println!("Creating loopback interface '{}'", name);

    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    // Create an empty ifreq struct
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };

    // Set the interface name
    let c_name = CString::new(name).unwrap();
    unsafe {
        strncpy(
            ifr.ifr_name.as_mut_ptr() as *mut c_char,
            c_name.as_ptr(),
            ifr.ifr_name.len() - 1,
        )
    };

    // Set the flags (using pointer casting to access the union field safely)
    let flags_ptr = unsafe { &mut ifr.ifr_ifru.ifru_flags as *mut _ };
    unsafe { *flags_ptr = (IFF_LOOPBACK | IFF_UP) as i16 };

    // Perform the ioctl operation to set interface flags
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCGIFFLAGS.try_into().unwrap(),
            &mut ifr,
        )
    };

    // Return the result of the ioctl operation
    Ok(result)
}

unsafe fn net_if_alias(ifr: &mut ifreq, name: &str) -> nix::Result<c_int> {
    const SUFFIX_LEN: usize = 5;

    // Check if the name length fits with the suffix length constraint
    if name.len() >= ifr.ifr_name.len() - SUFFIX_LEN {
        return Ok(-1);
    }

    // Increment alias counter
    let alias_counter = ALIAS_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;

    // Create the alias string using snprintf
    let alias_name = format!("{}:{}", name, alias_counter);
    let alias_cstring = CString::new(alias_name).unwrap();

    // Copy the alias name into ifr_name, respecting the buffer size
    snprintf(
        ifr.ifr_name.as_mut_ptr() as *mut c_char,
        ifr.ifr_name.len() - 1,
        "%s\0".as_ptr() as *const c_char,
        alias_cstring.as_ptr(),
    );

    Ok(0)
}

// Function to configure the network interface address and netmask
fn net_if_addr(name: &str, ip: &str, mask: &str) -> nix::Result<c_int> {
    // Open a socket
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    // Create an empty ifreq struct
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };

    let c_name = CString::new(name).unwrap();

    // Set the interface name
    unsafe {
        strncpy(
            ifr.ifr_name.as_mut_ptr() as *mut c_char,
            c_name.as_ptr(),
            ifr.ifr_name.len() - 1,
        )
    };

    // Retrieve the current address of the interface
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCGIFADDR.try_into().unwrap(),
            &mut ifr,
        )
    };
    if result == 0 && unsafe { net_if_alias(&mut ifr, name) }? < 0 {
        return Err(nix::Error::last());
    }

    // Set up the sockaddr_in structure for the address
    let sa: *mut sockaddr_in = unsafe { &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut sockaddr_in };

    unsafe {
        (*sa).sin_family = AF_INET as u16;
    }

    let ip_cstr = CString::new(ip).unwrap();

    // Set the IP address
    if unsafe {
        inet_pton(
            AF_INET,
            ip_cstr.as_ptr(),
            &mut (*sa).sin_addr as *mut in_addr as *mut libc::c_void,
        )
    } < 0
    {
        return Err(nix::Error::last());
    }

    // Set the interface address
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFADDR as i32, &mut ifr) };
    if result < 0 {
        return Err(nix::Error::last());
    }

    let ip_mask = CString::new(mask).unwrap();

    // Set the netmask
    if unsafe {
        inet_pton(
            AF_INET,
            ip_mask.as_ptr(),
            &mut (*sa).sin_addr as *mut in_addr as *mut libc::c_void,
        )
    } < 0
    {
        return Err(nix::Error::last());
    }

    // Apply the netmask
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFNETMASK.try_into().unwrap(),
            &mut ifr,
        ) < 0
    } {
        return Err(nix::Error::last());
    }

    // Bring the interface up
    let flags_ptr = unsafe { &mut ifr.ifr_ifru.ifru_flags as *mut _ };
    unsafe { *flags_ptr = (IFF_LOOPBACK | IFF_UP) as i16 };
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFFLAGS.try_into().unwrap(),
            &mut ifr,
        )
    };
    if result < 0 {
        return Err(nix::Error::last());
    }

    // Return the result of the final ioctl operation
    Ok(result)
}

fn setup_network() -> io::Result<()> {
    let hosts = [
        ("127.0.0.1", "localhost"),
        ("::1", "ip6-localhost ip6-loopback"),
        ("fe00::0", "ip6-localnet"),
        ("ff00::0", "ip6-mcastprefix"),
        ("ff02::1", "ip6-allnodes"),
        ("ff02::2", "ip6-allrouters"),
    ];
    let nameservers = ["1.1.1.1", "8.8.8.8"];

    add_network_hosts(&hosts)?;
    set_network_ns(&nameservers)?;

    net_create_lo("lo")?;
    net_if_addr("lo", "127.0.0.1", "255.255.255.0")?;

    write_sys("/proc/sys/net/core/rmem_default", NET_MEM_DEFAULT);
    write_sys("/proc/sys/net/core/rmem_max", NET_MEM_MAX);
    write_sys("/proc/sys/net/core/wmem_default", NET_MEM_DEFAULT);
    write_sys("/proc/sys/net/core/wmem_max", NET_MEM_MAX);

    let result = net_if_mtu(DEV_VPN, MTU_VPN);
    match result {
        Ok(_) => (),
        Err(e) => {
            println!("Failed to set MTU for VPN interface: {:?}", e);
        }
    }
    let result = net_if_mtu(DEV_INET, MTU_INET);
    match result {
        Ok(_) => (),
        Err(e) => {
            println!("Failed to set MTU for INET interface: {:?}", e);
        }
    }

    Ok(())
}

fn net_if_mtu(name: &str, mtu: usize) -> nix::Result<i32> {
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    println!("Setting MTU {} for interface {}", mtu, name);

    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    let c_name = CString::new(name).unwrap();

    unsafe {
        strncpy(
            ifr.ifr_name.as_mut_ptr() as *mut c_char,
            c_name.as_ptr(),
            ifr.ifr_name.len() - 1,
        )
    };

    let sa: *mut sockaddr_in = unsafe { &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut sockaddr_in };
    unsafe {
        (*sa).sin_family = AF_INET as u16;
    }

    let ifr_mtu: *mut c_int = unsafe { &mut ifr.ifr_ifru.ifru_mtu as *mut _ as *mut c_int };
    unsafe { *ifr_mtu = mtu as i32 };

    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFMTU.try_into().unwrap(),
            &mut ifr,
        )
    };

    if result < 0 {
        return Err(nix::Error::last());
    }

    Ok(result)
}

fn setup_sandbox() -> io::Result<()> {
    Ok(())
}

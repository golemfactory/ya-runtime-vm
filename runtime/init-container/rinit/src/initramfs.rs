use std::{ffi::CString, path::Path, ptr};

use libc::{open, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_RDONLY};
use nix::mount::MsFlags;

use crate::{check, check_bool, NEW_ROOT, NONE};

fn copy_initramfs_recursive(
    dirfd: libc::c_int,
    newdirfd: libc::c_int,
    skip_name: &str,
) -> Result<(), nix::Error> {
    check_bool!(newdirfd != dirfd);
    let d = unsafe { libc::fdopendir(dirfd) };
    check_bool!(!d.is_null());

    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(d) };
        if entry.is_null() {
            check_bool!(unsafe { *libc::__errno_location() == 0 });
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

pub fn copy_initramfs() -> Result<(), nix::Error> {
    println!("Copying initramfs from '/' to '/newroot'");

    check_bool!(Path::new("/").exists());
    check_bool!(Path::new("/").join(NEW_ROOT).exists());

    nix::mount::mount(Some(""), "/newroot", Some("tmpfs"), MsFlags::empty(), NONE)?;

    let root = c"/";
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

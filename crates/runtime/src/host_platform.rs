use std::{fs::File, io};
use vm_resource::{IntoResource, Resource};

pub(crate) fn stderr_file() -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(std::io::stderr().as_fd().try_clone_to_owned()?.into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(std::io::stderr().as_handle().try_clone_to_owned()?.into())
    }
}

pub(crate) fn hypervisor() -> anyhow::Result<Resource<hypervisor_resources::HypervisorKind>> {
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context;
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .context("opening /dev/kvm for OpenVMM")?;
        Ok(hypervisor_resources::KvmHandle { kvm }.into_resource())
    }
    #[cfg(windows)]
    {
        Ok(hypervisor_resources::WhpHandle::default().into_resource())
    }
}

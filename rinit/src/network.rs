use std::{
    ffi::CString,
    fs::File,
    io::{BufWriter, Write},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    sync::atomic::Ordering,
};

use libc::{c_char, c_int, ifreq, snprintf, sockaddr_in, strncpy, AF_INET, IFF_LOOPBACK, IFF_UP};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

use crate::{
    fs::write_sys, ALIAS_COUNTER, DEV_INET, DEV_VPN, MTU_INET, MTU_VPN, NET_MEM_DEFAULT,
    NET_MEM_MAX, SYSROOT,
};

fn ipv4_to_u32(ip: &str) -> u32 {
    ip.parse::<Ipv4Addr>().unwrap().into()
}

pub fn stop_network() -> std::io::Result<()> {
    Ok(())
}

pub fn add_network_hosts<S: AsRef<str>>(entries: &[(S, S)]) -> std::io::Result<()> {
    let mut f = BufWriter::new(
        File::options()
            .append(true)
            .open(format!("{}/etc/hosts", SYSROOT))?,
    );

    for entry in entries.iter() {
        match f.write_fmt(format_args!("{}\t{}\n", entry.0.as_ref(), entry.1.as_ref())) {
            Ok(_) => (),
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        }
    }

    f.flush()?;

    match f.into_inner() {
        Ok(file) => nix::unistd::fsync(file.as_raw_fd())?,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }

    Ok(())
}

pub fn set_network_ns(entries: &[&str]) -> std::io::Result<()> {
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
        Ok(file) => nix::unistd::fsync(file.as_raw_fd())?,
        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }

    Ok(())
}

fn net_create_lo(name: &str) -> nix::Result<c_int> {
    // Open a socket with None as the protocol to match the expected Option<SockProtocol> type

    log::info!("Creating loopback interface '{}'", name);

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
pub fn net_if_addr(name: &str, ip: &str, mask: &str) -> nix::Result<c_int> {
    log::info!(
        "Setting address {} and netmask {} for interface {}",
        ip,
        mask,
        name,
    );

    // Open a socket
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    // Create an empty ifreq struct
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };

    let c_name = CString::new(name).map_err(|_| nix::errno::Errno::EINVAL)?;

    // Set the interface name
    unsafe {
        std::ptr::copy_nonoverlapping(
            c_name.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            c_name.to_bytes().len().min(ifr.ifr_name.len() - 1),
        );
        *ifr.ifr_name.as_mut_ptr().add(ifr.ifr_name.len() - 1) = 0;
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

    let ip = ipv4_to_u32(ip);
    let mask = ipv4_to_u32(mask);

    // Set the interface address
    unsafe {
        (*sa).sin_family = AF_INET as u16;
        (*sa).sin_addr.s_addr = ip.to_be();
    }

    // Apply the address
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFADDR.try_into().unwrap(),
            &mut ifr,
        )
    };
    if result < 0 {
        log::error!("Failed to set address for interface '{}'", name);
        return Err(nix::Error::last());
    }

    // Set the interface netmask
    unsafe {
        (*sa).sin_family = AF_INET as u16;
        (*sa).sin_addr.s_addr = mask.to_be();
    }

    // Apply the netmask
    if unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFNETMASK.try_into().unwrap(),
            &mut ifr,
        ) < 0
    } {
        log::error!("Failed to set netmask for interface '{}'", name);
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

    log::info!("Interface '{}' configured successfully", name);

    // Return the result of the final ioctl operation
    Ok(result)
}

pub fn net_if_addr_to_hw_addr(ip: &str) -> [u8; 6] {
    let ip = ipv4_to_u32(ip);

    let mut hw_addr = [0u8; 6];
    hw_addr[0] = 0x90;
    hw_addr[1] = 0x13;
    hw_addr[2] = (ip >> 24) as u8;
    hw_addr[3] = (ip >> 16) as u8;
    hw_addr[4] = (ip >> 8) as u8;
    hw_addr[5] = ip as u8;

    hw_addr
}

pub fn net_if_hw_addr(name: &str, mac: &[u8; 6]) -> nix::Result<c_int> {
    log::info!(
        "Setting hardware address {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} for interface {}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        name,
    );

    // Open a socket
    let fd = socket(
        AddressFamily::Packet,
        SockType::Raw,
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

    // Set up the sockaddr_in structure for the address
    let sa: *mut sockaddr_in = unsafe { &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut sockaddr_in };

    // Set the interface address
    unsafe {
        (*sa).sin_family = AF_INET as u16;
        (*sa).sin_addr.s_addr = 0;
    }

    // Set the hardware address

    let hw_addr: *mut libc::sockaddr =
        unsafe { &mut ifr.ifr_ifru.ifru_hwaddr as *mut libc::sockaddr };
    unsafe {
        (*hw_addr).sa_family = libc::ARPHRD_ETHER as u16;
        for (i, byte) in mac.iter().enumerate() {
            (*hw_addr).sa_data[i] = *byte as i8;
        }
    }

    // Apply the hardware address
    let result = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            libc::SIOCSIFHWADDR.try_into().unwrap(),
            &mut ifr,
        )
    };

    Ok(result)
}

pub fn net_route(
    name: &str,
    ip: Option<&str>,
    mask: Option<&str>,
    via: &str,
) -> std::io::Result<c_int> {
    // Open a socket
    let fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;

    let name_cstr = CString::new(name).unwrap();
    rt.rt_dev = name_cstr.as_ptr() as *mut c_char;

    let via_addr = via.parse::<std::net::Ipv4Addr>().unwrap();
    let via_sockaddr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(via_addr).to_be(),
        },
        sin_zero: [0; 8],
    };
    rt.rt_gateway = unsafe { std::mem::transmute(via_sockaddr) };

    let dst_addr = if let Some(ip) = ip {
        ip.parse::<std::net::Ipv4Addr>().unwrap()
    } else {
        std::net::Ipv4Addr::new(0, 0, 0, 0)
    };
    let dst_sockaddr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst_addr).to_be(),
        },
        sin_zero: [0; 8],
    };
    rt.rt_dst = unsafe { std::mem::transmute(dst_sockaddr) };
    rt.rt_metric = if ip.is_some() { 101 } else { 0 };

    let mask_addr = if let Some(mask) = mask {
        mask.parse::<std::net::Ipv4Addr>().unwrap()
    } else {
        std::net::Ipv4Addr::new(0, 0, 0, 0)
    };
    let mask_sockaddr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(mask_addr).to_be(),
        },
        sin_zero: [0; 8],
    };
    rt.rt_genmask = unsafe { std::mem::transmute(mask_sockaddr) };

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCADDRT.try_into().unwrap(), &mut rt) };

    Ok(ret)
}

pub fn setup_network() -> std::io::Result<()> {
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
            log::error!("Failed to set MTU for VPN interface: {:?}", e);
        }
    }
    let result = net_if_mtu(DEV_INET, MTU_INET);
    match result {
        Ok(_) => (),
        Err(e) => {
            log::error!("Failed to set MTU for INET interface: {:?}", e);
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

    log::info!("Setting MTU {} for interface {}", mtu, name);

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

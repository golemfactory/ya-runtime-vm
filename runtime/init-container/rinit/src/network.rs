use std::{
    ffi::CString,
    fs::File,
    io::{BufWriter, Write},
    os::fd::AsRawFd,
    sync::atomic::Ordering,
};

use libc::{
    c_char, c_int, ifreq, in_addr, snprintf, sockaddr_in, strncpy, AF_INET, IFF_LOOPBACK, IFF_UP,
};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

use crate::{
    fs::write_sys, ALIAS_COUNTER, DEV_INET, DEV_VPN, MTU_INET, MTU_VPN, NET_MEM_DEFAULT,
    NET_MEM_MAX, SYSROOT,
};

fn ipv4_to_u32(ip: &str) -> u32 {
    let octets: Vec<u8> = ip.split('.').map(|octet| octet.parse().unwrap()).collect();
    (octets[0] as u32) << 24
        | (octets[1] as u32) << 16
        | (octets[2] as u32) << 8
        | (octets[3] as u32)
}

pub fn stop_network() -> std::io::Result<()> {
    Ok(())
}

pub fn add_network_hosts(entries: &[(&str, &str)]) -> std::io::Result<()> {
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
        println!("Failed to set address for interface '{}'", name);
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
        println!("Failed to set netmask for interface '{}'", name);
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

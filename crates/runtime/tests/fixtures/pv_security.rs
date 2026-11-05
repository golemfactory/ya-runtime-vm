// Runs only inside a disposable Linux guest. The host never loads msr.ko or
// opens an MSR device. /dev/cpu/N/msr executes safe RDMSR/WRMSR on guest CPU N.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Barrier};

unsafe extern "C" {
    fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
    fn mknod(path: *const std::ffi::c_char, mode: u32, device: u64) -> i32;
}

fn read(msr: &File, index: u64) -> io::Result<u64> {
    let mut bytes = [0; 8];
    msr.read_exact_at(&mut bytes, index)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write(msr: &File, index: u64, value: u64) -> io::Result<()> {
    msr.write_all_at(&value.to_le_bytes(), index)
}

fn rejected<T: std::fmt::Debug>(result: io::Result<T>, operation: &str) {
    let error = match result {
        Err(error) => error,
        Ok(value) => panic!("{operation}: unexpectedly accepted ({value:?})"),
    };
    assert_eq!(
        error.raw_os_error(),
        Some(5), // EIO: guest kernel caught #GP from RDMSR/WRMSR.
        "{operation}: expected guest #GP, not a permissions or device error"
    );
}

pub fn run() {
    let signature = std::arch::x86_64::__cpuid(0x4000_0000);
    assert_eq!(signature.ebx, u32::from_le_bytes(*b"KVMK"));
    let features = std::arch::x86_64::__cpuid(0x4000_0001).eax;
    assert_eq!(features & !0x0100_3aeb, 0, "unexpected KVM PV feature");
    assert_ne!(features & (1 << 6), 0, "PV EOI required by this test");
    assert_ne!(
        features & (1 << 12),
        0,
        "PV poll control required by this test"
    );

    let module = File::open("/mnt/out/test-msr.ko").unwrap();
    // SAFETY: valid open module fd and NUL-terminated kernel module parameters.
    // SYS_finit_module on the x86_64 Linux guest. No host module is loaded.
    let result = unsafe { syscall(313, module.as_raw_fd(), c"allow_writes=on".as_ptr(), 0i32) };
    assert_eq!(
        result,
        0,
        "loading test module: {}",
        io::Error::last_os_error()
    );
    let cpus = fs::read_to_string("/proc/cpuinfo")
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("processor\t"))
        .count();
    assert_eq!(
        cpus, 4,
        "security fixture must exercise every one of four vCPUs"
    );
    let barrier = Arc::new(Barrier::new(cpus));
    std::thread::scope(|scope| {
        for cpu in 0..cpus {
            let barrier = barrier.clone();
            scope.spawn(move || {
                // /tmp is deliberately mounted nodev by the runtime.
                let path = std::ffi::CString::new(format!("/dev/pv-msr-{cpu}")).unwrap();
                // SAFETY: valid path; Linux msr char-device major=202, minor=CPU.
                let result = unsafe { mknod(path.as_ptr(), 0o020600, (202 << 8) | cpu as u64) };
                assert_eq!(
                    result,
                    0,
                    "creating guest MSR device: {}",
                    io::Error::last_os_error()
                );
                let msr = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path.to_str().unwrap())
                    .unwrap();
                const EOI: u64 = 0x4b56_4d04;
                const POLL: u64 = 0x4b56_4d05;
                let saved_eoi = read(&msr, EOI).unwrap();
                let saved_poll = read(&msr, POLL).unwrap();
                // All vCPUs perform the bounded negative and positive probes
                // together. The CI harness also runs two whole VMs together.
                barrier.wait();
                for _ in 0..32 {
                    for index in [0x4b56_4d02, 0x4b56_4d06, 0x4b56_4d07] {
                        rejected(read(&msr, index), "excluded async-PF RDMSR");
                        rejected(write(&msr, index, 0), "excluded async-PF WRMSR");
                    }
                    // Bad alignment, a GPA outside this 512-MiB guest, and a
                    // high invalid GPA. Restore EOI state even after failure:
                    // KVM may have updated its cached mapping before rejecting.
                    for value in [0x2003, 0x4000_0001, 0xffff_ffff_ffff_f001] {
                        let result = write(&msr, EOI, value);
                        write(&msr, EOI, saved_eoi).unwrap();
                        rejected(result, "invalid PV EOI address");
                        assert_eq!(read(&msr, EOI).unwrap(), saved_eoi);
                    }
                    rejected(write(&msr, POLL, 2), "reserved poll-control bit");
                    // Positive control: permitted PV operations still work.
                    write(&msr, POLL, 0).unwrap();
                    assert_eq!(read(&msr, POLL).unwrap(), 0);
                    write(&msr, POLL, saved_poll).unwrap();
                    assert_eq!(read(&msr, POLL).unwrap(), saved_poll);
                    std::thread::yield_now();
                }
                fs::remove_file(path.to_str().unwrap()).unwrap();
            });
        }
    });
    println!("KVM_PV_SECURITY_OK");
}

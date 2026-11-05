#![cfg_attr(target_os = "linux", no_std)]
#![cfg_attr(target_os = "linux", no_main)]

#[cfg(target_os = "linux")]
#[macro_use]
extern crate alloc;
#[cfg(target_os = "linux")]
mod allocator;
#[cfg(target_os = "linux")]
extern crate origin;

#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
unsafe fn origin_main(argc: usize, argv: *mut *mut u8, envp: *mut *mut u8) -> i32 {
    // SAFETY: Origin supplies argc valid C string pointers in argv.
    if argc == 2 && unsafe { core::ffi::CStr::from_ptr((*argv.add(1)).cast()) } == c"--self-check" {
        allocator::self_check();
        ya_vm_guest_agent::linux::io::log(format_args!(
            "NO_STD_SELF_CHECK_OK origin + talc + rustix"
        ));
        return 0;
    }
    if rustix::process::getpid() != rustix::process::Pid::INIT {
        ya_vm_guest_agent::linux::io::log(format_args!("Guest agent must run as PID 1"));
        return 1;
    }
    // SAFETY: Origin supplies a valid NULL-terminated environment array.
    let result = unsafe { ya_vm_guest_agent::linux::run(envp) };
    if let Err(error) = result {
        ya_vm_guest_agent::linux::io::log(format_args!("Guest init failed: {error:#}"));
    }
    ya_vm_guest_agent::linux::shutdown()
}
#[cfg(target_os = "linux")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    ya_vm_guest_agent::linux::io::log(format_args!("Guest init panic: {info}"));
    if rustix::process::getpid() != rustix::process::Pid::INIT {
        origin::program::immediate_exit(101);
    }
    ya_vm_guest_agent::linux::shutdown()
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Build the Linux guest using mise run guest-build");
}

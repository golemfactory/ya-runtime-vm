#![no_std]
#[cfg(target_os = "linux")]
#[macro_use]
extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(target_os = "linux")]
macro_rules! eprintln {
    ($($arg:tt)*) => { $crate::linux::io::log(format_args!($($arg)*)) };
}
#[cfg(target_os = "linux")]
pub mod error;
#[cfg(target_os = "linux")]
pub mod linux;

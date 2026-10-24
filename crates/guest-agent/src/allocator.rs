//! Lock-free global allocation for the agent's single OS thread.
//! New anonymous mappings are retained and reused for the life of PID 1.
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ptr,
};
use rustix::mm::{MapFlags, ProtFlags};
use talc::{
    base::{
        Talc,
        binning::{Binning, DefaultBinning},
    },
    source::Source,
};

#[derive(Debug)]
struct Mmap;
// SAFETY: acquisition uses only syscalls and Talc's borrowed allocator. It
// never allocates recursively, logs, or invokes a callback that can allocate.
unsafe impl Source for Mmap {
    fn acquire<B: Binning>(talc: &mut Talc<Self, B>, layout: Layout) -> Result<(), ()> {
        let minimum = layout
            .size()
            .checked_add(layout.align())
            .and_then(|n| n.checked_add(talc::min_first_heap_size::<B>()))
            .ok_or(())?;
        let size = minimum
            .max(64 * 1024)
            .checked_next_multiple_of(4096)
            .ok_or(())?;
        // SAFETY: request a fresh, private writable mapping with no fixed address.
        let base = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                size,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        }
        .map_err(|_| ())?;
        // SAFETY: this fresh mapping is exclusively owned by this allocator.
        if unsafe { talc.claim(base.cast(), size) }.is_none() {
            // SAFETY: nothing was claimed; the entire fresh mapping can be released.
            let _ = unsafe { rustix::mm::munmap(base, size) };
            return Err(());
        }
        Ok(())
    }
}
struct SingleThread(UnsafeCell<Talc<Mmap, DefaultBinning>>);
// SAFETY: the production executable creates no threads or allocating signal
// handlers. SIGCHLD is consumed via signalfd. After fork, child setup performs
// no allocation before exec/exit. Tests use std's allocator, not this binary.
unsafe impl Sync for SingleThread {}
unsafe impl GlobalAlloc for SingleThread {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller provides a nonzero valid layout; the
        // single-threaded execution invariant grants exclusive allocator access.
        unsafe {
            (&mut *self.0.get())
                .allocate(layout)
                .map_or(ptr::null_mut(), |p| p.as_ptr())
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer/layout came from this allocator and are no longer used.
        unsafe { (&mut *self.0.get()).deallocate(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: SingleThread = SingleThread(UnsafeCell::new(Talc::new(Mmap)));

pub fn self_check() {
    use alloc::vec::Vec;
    for round in 0..64 {
        let mut vectors = Vec::new();
        for size in [1, 17, 4095, 65537, 200_003] {
            vectors.push(vec![round as u8; size]);
        }
        for buffer in vectors {
            assert!(buffer.iter().all(|&v| v == round as u8));
        }
    }
    let layout = Layout::from_size_align(131_073, 65_536).unwrap();
    // SAFETY: allocation has a valid layout; verify it before releasing it.
    unsafe {
        let memory = alloc::alloc::alloc_zeroed(layout);
        assert!(!memory.is_null());
        assert_eq!(memory.addr() % layout.align(), 0);
        assert!(
            core::slice::from_raw_parts(memory, layout.size())
                .iter()
                .all(|&b| b == 0)
        );
        alloc::alloc::dealloc(memory, layout);
    }
}

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use std::cell::UnsafeCell;
use futures::sink::Buffer;
use std::io::prelude::*;
use std::net::Shutdown;

pub struct RawSocketCommunication {
    thread_join_handle : Option<std::thread::JoinHandle<()>>,
    shared_unsafe_data: Option<std::cell::UnsafeCell<SharedUnsafeData>>,
}

pub struct SharedUnsafeData {
    tri: i32,
    vm_stream: std::net::TcpStream,
    p9_streams: Vec<std::net::TcpStream>
}
pub struct SharedUnsafeDataPointer {
    pub obj_ptr: *mut SharedUnsafeData,
}
unsafe impl Send for SharedUnsafeDataPointer {}

impl RawSocketCommunication {
    pub fn new() -> RawSocketCommunication {
        RawSocketCommunication{thread_join_handle: None, shared_unsafe_data: None}
    }

    pub fn start_raw_comm(&mut self, mut vm_stream: std::net::TcpStream, mut p9_streams : Vec<std::net::TcpStream>) {
        log::debug!("Spawning thread no 1");
        self.shared_unsafe_data = Some(UnsafeCell::new(SharedUnsafeData{tri: 1, vm_stream, p9_streams }));


        let unsafe_data = SharedUnsafeDataPointer{obj_ptr: self.shared_unsafe_data.as_ref().unwrap().get()};


        self.thread_join_handle = Some(std::thread::spawn(move || {
            for i in 0..10 {
                let mut buffer = [0; 3];
                unsafe {
                    let read_size = (*(unsafe_data.obj_ptr)).vm_stream.read(&mut buffer).unwrap();

                    assert!(read_size == 3);
                }

//                    log::debug!("Spawned thread no {} {}", i, (*unsafe_data).tri);

            }
            std::thread::sleep(Duration::from_millis(400));
        }));
    }

    pub fn finish_raw_comm(mut self) {
        if let Some(shared_data) = self.shared_unsafe_data {
            unsafe {
                (*shared_data.get()).vm_stream.shutdown(Shutdown::Both);
            }
        }

        if let Some(thread) = self.thread_join_handle {
            log::debug!("Joining thread: thread_join_handle");
            thread.join();
            log::debug!("Thread thread_join_handle joined");
        }
    }
}


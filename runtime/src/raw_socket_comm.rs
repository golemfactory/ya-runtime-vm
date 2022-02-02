use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use std::cell::UnsafeCell;
use std::io::prelude::*;
use std::net::Shutdown;
use std::convert::TryInto;

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

const MAX_PACKET_SIZE : usize = 16384;


impl RawSocketCommunication {
    pub fn new() -> RawSocketCommunication {
        RawSocketCommunication{thread_join_handle: None, shared_unsafe_data: None}
    }

    pub fn start_raw_comm(&mut self, mut vm_stream: std::net::TcpStream, mut p9_streams : Vec<std::net::TcpStream>) {

        log::debug!("Spawning thread no 1");
        self.shared_unsafe_data = Some(UnsafeCell::new(SharedUnsafeData{tri: 1, vm_stream, p9_streams }));


        let unsafe_data = SharedUnsafeDataPointer{obj_ptr: self.shared_unsafe_data.as_ref().unwrap().get()};


        self.thread_join_handle = Some(std::thread::spawn(move || {
            loop {
                unsafe {
                    std::thread::sleep(Duration::from_millis(10));
                    let mut header_buffer = [0; 3];
                    let mut message_buffer = [0; MAX_PACKET_SIZE];

                    match (*unsafe_data.obj_ptr).vm_stream.read_exact(&mut header_buffer) {
                        Ok(()) => {},
                        Err(err) => {
                            log::error!("{}", err);
                            break;
                        }
                    }
                    /*if (read_size_header != 3) {
                        log::error!("read_size_header != 3");
                        break;
                    }*/

                    let (channel_bytes, packet_size_bytes) = header_buffer.split_at(1);
                    let channel = u8::from_le_bytes(channel_bytes.try_into().unwrap()) as usize;

                    if channel >= (*unsafe_data.obj_ptr).p9_streams.len() {
                        log::error!("channel exceeded number of connected p9 servers channel: {}, p9_stream.len: {}", channel, (*unsafe_data.obj_ptr).p9_streams.len());
                        break;
                    }


                    let packet_size = u16::from_le_bytes(packet_size_bytes.try_into().unwrap()) as usize;

                    if packet_size > message_buffer.len() {
                        log::error!("packet_size > message_buffer.len()");
                        break;
                    }

                    match (*unsafe_data.obj_ptr).vm_stream.read_exact(&mut message_buffer[0..packet_size]){
                        Ok(()) => {},
                        Err(err) => {
                            log::error!("{}", err);
                            break;
                        }
                    }



                    /*if read_size_packet != packet_size {
                        log::error!("read_size_packet != packet_size");
                        break;
                    }*/

                    log::debug!("Received packet channel: {}, packet_size: {}", channel, packet_size);
                }
            }
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


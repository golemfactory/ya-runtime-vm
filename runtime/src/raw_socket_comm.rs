use std::cell::UnsafeCell;
use std::convert::TryInto;
use std::io::prelude::*;
use std::net::Shutdown;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default, Debug)]
pub struct RawSocketCommunication {
    vm_stream_thread: Option<std::thread::JoinHandle<()>>,
    p9_stream_threads: Vec<std::thread::JoinHandle<()>>,
    shared_unsafe_data: Option<Box<std::cell::UnsafeCell<SharedUnsafeData>>>,
}

pub struct SharedUnsafeData {
    //tri: i32,
    vm_stream: std::net::TcpStream,
    p9_streams: Vec<std::net::TcpStream>,
    vm_stream_write_mutex: Mutex<i32>,
}

impl Drop for SharedUnsafeData {
    fn drop(&mut self) {
        log::error!("Dropping SharedUnsafeData");
    }
}

#[derive(Copy, Clone)]
pub struct SharedUnsafeDataPointer {
    pub obj_ptr: *mut SharedUnsafeData,
}
unsafe impl Send for SharedUnsafeDataPointer {}

const MAX_PACKET_SIZE: usize = 16384;

const TEST_CONCURRENT_ACCESS: bool = false;

impl RawSocketCommunication {
    pub fn new() -> RawSocketCommunication {
        RawSocketCommunication {
            vm_stream_thread: None,
            p9_stream_threads: vec![],
            shared_unsafe_data: None,
        }
    }

    pub fn start_raw_comm(
        &mut self,
        vm_stream: std::net::TcpStream,
        p9_streams: Vec<std::net::TcpStream>,
    ) {
        let number_of_p9_threads = p9_streams.len();

        self.shared_unsafe_data = Some(Box::new(UnsafeCell::new(SharedUnsafeData {
            vm_stream,
            p9_streams,
            vm_stream_write_mutex: Mutex::new(0),
        })));

        let unsafe_data = SharedUnsafeDataPointer {
            obj_ptr: self.shared_unsafe_data.as_ref().unwrap().get(),
        };

        self.vm_stream_thread = Some(std::thread::spawn(move || {
            let mut header_buffer = [0; 3];
            let mut message_buffer = [0; MAX_PACKET_SIZE];
            loop {
                unsafe {
                    //std::thread::sleep(Duration::from_millis(10));

                    match (*unsafe_data.obj_ptr)
                        .vm_stream
                        .read_exact(&mut header_buffer)
                    {
                        Ok(()) => {}
                        Err(err) => {
                            log::error!("read exact 1: {}", err);
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

                    let packet_size =
                        u16::from_le_bytes(packet_size_bytes.try_into().unwrap()) as usize;

                    if packet_size > message_buffer.len() {
                        log::error!("packet_size > message_buffer.len()");
                        break;
                    }

                    match (*unsafe_data.obj_ptr)
                        .vm_stream
                        .read_exact(&mut message_buffer[0..packet_size])
                    {
                        Ok(()) => {}
                        Err(err) => {
                            log::error!("read exact 2 {}", err);
                            break;
                        }
                    }
                    /*if read_size_packet != packet_size {
                        log::error!("read_size_packet != packet_size");
                        break;
                    }*/

                    //log::debug!("Received packet channel: {}, packet_size: {}", channel, packet_size);

                    let _r6 = (*unsafe_data.obj_ptr).p9_streams[channel]
                        .write_all(&mut message_buffer[0..packet_size]);
                }
            }
        }));

        for channel in 0..number_of_p9_threads {
            self.p9_stream_threads.push(std::thread::spawn(move || {
                let mut message_buffer = [0; MAX_PACKET_SIZE];

                loop {
                    //log::debug!("Thread channel {}", channel);
                    unsafe {
                        let bytes_read = match (*unsafe_data.obj_ptr).p9_streams[channel]
                            .read(&mut message_buffer)
                        {
                            Ok(bytes_read) => bytes_read,
                            Err(err) => {
                                log::error!("read p9 streams {}", err);
                                break;
                            }
                        };
                        {
                            //critical section for writing to common socket
                            let _write_guard =
                                (*unsafe_data.obj_ptr).vm_stream_write_mutex.lock().unwrap();

                            //log::debug!("Sending message back: channel:{}, packet_size:{}", channel, bytes_read);

                            let channel_u8 = channel as u8;
                            let mut channel_bytes = channel_u8.to_le_bytes();
                            let _r5 = (*unsafe_data.obj_ptr)
                                .vm_stream
                                .write_all(&mut channel_bytes);

                            if TEST_CONCURRENT_ACCESS {
                                std::thread::sleep(Duration::from_millis(50));
                            }

                            let bytes_read_u16 = bytes_read as u16;
                            let mut packet_size_bytes = bytes_read_u16.to_le_bytes();

                            let _r = (*unsafe_data.obj_ptr)
                                .vm_stream
                                .write_all(&mut packet_size_bytes);

                            if TEST_CONCURRENT_ACCESS {
                                std::thread::sleep(Duration::from_millis(50));
                                let split_send = bytes_read / 2;
                                let _r1 = (*unsafe_data.obj_ptr)
                                    .vm_stream
                                    .write_all(&mut message_buffer[0..split_send]);
                                std::thread::sleep(Duration::from_millis(50));
                                let _r2 = (*unsafe_data.obj_ptr)
                                    .vm_stream
                                    .write_all(&mut message_buffer[split_send..bytes_read]);
                            } else {
                                let _r3 = (*unsafe_data.obj_ptr)
                                    .vm_stream
                                    .write_all(&mut message_buffer[0..bytes_read]);
                            }

                            drop(_write_guard);
                        }
                    }
                }
            }));
        }
    }

    pub fn finish_raw_comm(self) {
        if let Some(shared_data) = self.shared_unsafe_data {
            unsafe {
                let _res1 = (*shared_data.get()).vm_stream.shutdown(Shutdown::Both);
                let _res = (*shared_data.get())
                    .p9_streams
                    .iter()
                    .map(|p9stream| p9stream.shutdown(Shutdown::Both));
            }
        }

        if let Some(thread) = self.vm_stream_thread {
            log::debug!("Joining thread: thread_join_handle");
            let _join_res = thread.join();
            log::debug!("Thread thread_join_handle joined");
        }
        for thread in self.p9_stream_threads {
            let _join_res = thread.join();
        }
    }
}

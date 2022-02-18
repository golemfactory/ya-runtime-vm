use std::convert::TryInto;
use std::io::{Read, Write};
use std::{thread, net, sync};
use std::sync::{Arc, Mutex};
use futures::channel;
use tokio::io::AsyncReadExt;

const MAX_PACKET_SIZE : usize = 16384;


#[derive(Default, Debug)]
pub struct DemuxSocketCommunication {

}

impl DemuxSocketCommunication {

    pub fn new() -> Self {
        todo!()
    }

    pub fn start_raw_comm(&mut self, mut vm_stream: tokio::net::TcpStream, mut p9_streams: Vec<tokio::net::TcpStream>) -> anyhow::Result<()> {

        let p9_streams_len = p9_streams.len();

        let (mut vm_read_part, mut vm_write_part) = vm_stream.split();

        tokio::spawn(async move {
            loop {
                let mut header_buffer = [0; 3];
                let mut message_buffer = [0; MAX_PACKET_SIZE];
                if let Err(e) = vm_read_part.read_exact(&mut header_buffer).await {
                    log::error!("unable to read dmux data: {}", e);
                    break;
                }
            }
        });



        /*
        let mut senders = Vec::new();
        let vm_stream_writer = Arc::new(Mutex::new(vm_stream.try_clone()?));
        for (channel, mut stream) in p9_streams.into_iter().enumerate() {
            let rx = rx.clone();
            thread::spawn(move || {
                loop {
                    vm_stream_writer.lock().unwrap().write_all(...);
                    rx.send((channel, Vec::new()));
                }
            })
        }


        let rsh= thread::spawn(move || {
            let mut header_buffer = [0; 3];
            let mut message_buffer = [0; MAX_PACKET_SIZE];
            loop {
                if let Err(e) = read_stream.read_exact(&mut header_buffer) {
                    log::error!("unable to read dmux data: {}", e);
                    break;
                }

                let (channel_bytes, packet_size_bytes) = header_buffer.split_at(1);
                let channel = u8::from_le_bytes(channel_bytes.try_into().unwrap()) as usize;

                if channel >= p9_streams_len {
                    log::error!("channel exceeded number of connected p9 servers channel: {}, p9_stream.len: {}", channel, (*unsafe_data.obj_ptr).p9_streams.len());
                    break;
                }
                let packet_size = u16::from_le_bytes(packet_size_bytes.try_into().unwrap()) as usize;

                if packet_size > message_buffer.len() {
                    log::error!("packet_size > message_buffer.len()");
                    break;
                }
                if let Err(e) = p9_write_streams[channel].write_all(&mut message_buffer[0..packet_size]) {
                    log::error!("unable to write dmux data: {}", e);
                    break;
                }
            }
        });*/

        Ok(())

    }

}

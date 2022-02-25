use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const MAX_PACKET_SIZE: usize = 16384;

#[derive(Clone)]
pub struct DemuxSocketHandle {
    tx: tokio::sync::broadcast::Sender<()>,
}

impl Drop for DemuxSocketHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(());
    }
}

#[derive(Default, Debug)]
pub struct DemuxSocketCommunication {}

impl DemuxSocketCommunication {
    pub fn new() -> Self {
        todo!()
    }

    pub fn start_raw_comm(
        &mut self,
        vm_stream: tokio::net::TcpStream,
        p9_streams: Vec<tokio::net::TcpStream>,
    ) -> anyhow::Result<()> {
        let (mut vm_read_part, vm_write_part) = tokio::io::split(vm_stream);

        let mut p9_readers: Vec<ReadHalf<TcpStream>> = vec![];
        let mut p9_writers: Vec<WriteHalf<TcpStream>> = vec![];

        let vm_write_part = Arc::new(Mutex::new(vm_write_part));

        for p9_stream in p9_streams {
            let (vm_read_part, vm_write_part) = tokio::io::split(p9_stream);

            p9_readers.push(vm_read_part);
            p9_writers.push(vm_write_part);
        }

        let _vm_to_p9_splitter = tokio::spawn(async move {
            loop {
                let mut header_buffer = [0; 3];
                let mut message_buffer = [0; MAX_PACKET_SIZE];

                if let Err(err) = vm_read_part.read_exact(&mut header_buffer).await {
                    log::error!("unable to read dmux data: {}", err);
                    break;
                }

                let (channel_bytes, packet_size_bytes) = header_buffer.split_at(1);
                let channel = u8::from_le_bytes(channel_bytes.try_into().unwrap()) as usize;

                if channel >= p9_writers.len() {
                    log::error!("channel exceeded number of connected p9 servers channel: {}, p9_stream.len: {}", channel, p9_writers.len());
                    break;
                }

                let packet_size =
                    u16::from_le_bytes(packet_size_bytes.try_into().unwrap()) as usize;

                if packet_size > message_buffer.len() {
                    log::error!("packet_size > message_buffer.len(), packet_size: {}, message_buffer.len: {}", packet_size, message_buffer.len());
                    break;
                }

                if let Err(err) = vm_read_part
                    .read_exact(&mut message_buffer[0..packet_size])
                    .await
                {
                    log::error!("read exact 2 {}", err);
                    break;
                }

                //check above guarantees that index will succeeded
                if let Err(err) = p9_writers[channel]
                    .write_all(&mut message_buffer[0..packet_size])
                    .await
                {
                    log::error!("Write to p9_writer failed on channel {}: {}", channel, err);
                    break;
                }
            }
        });

        let _p9_to_vm_merger = tokio::spawn(async move {
            let mut message_buffer = [0; MAX_PACKET_SIZE];

            loop {
                let channel = 0;
                let bytes_read = match p9_readers[channel].read(&mut message_buffer).await {
                    Ok(bytes_read) => bytes_read,
                    Err(err) => {
                        log::error!("read p9 streams {}", err);
                        break;
                    }
                };

                {
                    let mut vm_write_guard = vm_write_part.lock().await;

                    let channel_u8 = channel as u8;
                    let mut channel_bytes = channel_u8.to_le_bytes();
                    if let Err(err) = vm_write_guard
                        .borrow_mut()
                        .write_all(&mut channel_bytes)
                        .await
                    {
                        log::error!("Write to vm_write_part failed: {}", err);
                        break;
                    }

                    let bytes_read_u16 = bytes_read as u16;
                    let mut packet_size_bytes = bytes_read_u16.to_le_bytes();

                    if let Err(err) = vm_write_guard
                        .borrow_mut()
                        .write_all(&mut packet_size_bytes)
                        .await
                    {
                        log::error!("Write to vm_write_part failed: {}", err);
                        break;
                    }

                    if let Err(err) = vm_write_guard
                        .borrow_mut()
                        .write_all(&mut message_buffer[0..bytes_read])
                        .await
                    {
                        log::error!("Write to vm_write_part failed: {}", err);
                        break;
                    }
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

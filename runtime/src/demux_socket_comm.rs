use futures::future::{AbortHandle, Abortable};
use std::borrow::BorrowMut;
use std::convert::TryInto;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub const MAX_P9_PACKET_SIZE: usize = 0x4000 - 5; //262144
pub const MAX_DEMUX_PACKET_SIZE: usize = 0x4000; //262144

pub struct DemuxSocketHandle {
    abort_handle_reader: AbortHandle,
    abort_handle_writers: Vec<AbortHandle>,
    join_handle_reader: JoinHandle<()>,
    join_handle_writers: Vec<JoinHandle<()>>,
}

pub async fn stop_demux_communication(dsh: DemuxSocketHandle) {
    dsh.abort_handle_reader.abort();
    for abort_handle_writer in dsh.abort_handle_writers.iter() {
        abort_handle_writer.abort();
    }
    let _res = dsh.join_handle_reader.await;
    for join_handle_writer in dsh.join_handle_writers {
        let _res = join_handle_writer.await;
    }
}

pub fn start_demux_communication(
    vm_stream: tokio::net::TcpStream,
    p9_streams: Vec<DuplexStream>,
) -> anyhow::Result<DemuxSocketHandle> {
    log::debug!("start_demux_communication - start");

    let (mut vm_read_part, vm_write_part) = tokio::io::split(vm_stream);

    let mut p9_readers = vec![];
    let mut p9_writers = vec![];

    let vm_write_part = Arc::new(Mutex::new(vm_write_part));

    for p9_stream in p9_streams {
        let (vm_read_part, vm_write_part) = tokio::io::split(p9_stream);

        p9_readers.push(vm_read_part);
        p9_writers.push(vm_write_part);
    }

    let (abort_handle, abort_registration) = AbortHandle::new_pair();

    let mut benchmark_start: Option<Instant> = None;
    let mut benchmark_bytes: u64 = 0;
    log::debug!("spawning vm_to_p9_splitter...");
    let vm_to_p9_splitter = tokio::spawn(async move {
        let reader_future = Abortable::new(
            async move {
                loop {
                    let mut header_buffer = [0; 5];
                    let mut message_buffer: Vec<u8> = vec![0; MAX_DEMUX_PACKET_SIZE];

                    if let Err(err) = vm_read_part.read_exact(&mut header_buffer).await {
                        log::error!("unable to read dmux data: {}", err);
                        break;
                    }

                    let (channel_bytes, packet_size_bytes) = header_buffer.split_at(1);
                    let channel = u8::from_le_bytes(channel_bytes.try_into().unwrap()) as usize;

                    let is_benchmark_packet = channel == 249;

                    if !is_benchmark_packet && channel >= p9_writers.len() {
                        log::error!("channel exceeded number of connected p9 servers channel: {}, p9_stream.len: {}", channel, p9_writers.len());
                        break;
                    }

                    let packet_size =
                        u32::from_le_bytes(packet_size_bytes.try_into().unwrap()) as usize;

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

                    if !is_benchmark_packet {
                        //check above guarantees that index will succeeded
                        if let Err(err) = p9_writers[channel]
                            .write_all(&message_buffer[0..packet_size])
                            .await
                        {
                            log::error!(
                                "Write to p9_writer failed on channel {}: {}",
                                channel,
                                err
                            );
                            break;
                        }
                    } else {
                        if benchmark_start == None {
                            benchmark_start = Some(Instant::now());
                        }
                        benchmark_bytes += packet_size as u64;
                        if message_buffer[0] == 255 {
                            let time_sec = benchmark_start.unwrap().elapsed().as_secs_f64();
                            let benchmark_mbytes = 1.0E-6 * benchmark_bytes as f64;
                            let speed = benchmark_mbytes / time_sec;
                            println!(
                                "Benchmark finished in {}, size {:.2}MB speed: {:.2}MB/s",
                                time_sec, benchmark_mbytes, speed
                            );
                            benchmark_start = None;
                            benchmark_bytes = 0;
                        }
                    }
                }
            },
            abort_registration,
        );
        match reader_future.await {
            Ok(()) => {
                log::error!("Reader part of p9 communication ended too soon");
            }
            Err(e) => {
                log::info!("Future aborted, reason {e}");
            }
        }
    });

    let mut join_handle_writers: Vec<JoinHandle<()>> = vec![];
    let mut abort_handles: Vec<AbortHandle> = vec![];

    for (channel, mut p9_reader) in p9_readers.into_iter().enumerate() {
        let vm_write_part = vm_write_part.clone();
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        log::debug!("spawning p9_to_vm_merger channel {}...", channel);
        let p9_to_vm_merger = tokio::spawn(async move {
            let writer_future = Abortable::new(
                async move {
                    let mut message_buffer: Vec<u8> = vec![0; MAX_DEMUX_PACKET_SIZE];

                    loop {
                        let bytes_read = match p9_reader.read(&mut message_buffer).await {
                            Ok(bytes_read) => bytes_read,
                            Err(err) => {
                                log::error!("read p9 streams {}", err);
                                break;
                            }
                        };

                        {
                            let mut vm_write_guard = vm_write_part.lock().await;

                            let channel_u8 = channel as u8;
                            let channel_bytes = channel_u8.to_le_bytes();
                            if let Err(err) =
                                vm_write_guard.borrow_mut().write_all(&channel_bytes).await
                            {
                                log::error!("Write to vm_write_part failed: {}", err);
                                break;
                            }

                            let bytes_read_u32 = bytes_read as u32;
                            let packet_size_bytes = bytes_read_u32.to_le_bytes();

                            if let Err(err) = vm_write_guard
                                .borrow_mut()
                                .write_all(&packet_size_bytes)
                                .await
                            {
                                log::error!("Write to vm_write_part failed: {}", err);
                                break;
                            }

                            if let Err(err) = vm_write_guard
                                .borrow_mut()
                                .write_all(&message_buffer[0..bytes_read])
                                .await
                            {
                                log::error!("Write to vm_write_part failed: {}", err);
                                break;
                            }
                        }
                    }
                },
                abort_registration,
            );

            match writer_future.await {
                Ok(()) => {
                    log::error!(
                        "Writer part of p9 communication ended too soon. channel: {}",
                        channel
                    );
                }
                Err(_e) => {
                    log::info!("Writer aborted for channel: {}", channel);
                }
            }
        });
        join_handle_writers.push(p9_to_vm_merger);
        abort_handles.push(abort_handle);
    }

    Ok(DemuxSocketHandle {
        join_handle_reader: vm_to_p9_splitter,
        abort_handle_reader: abort_handle,
        join_handle_writers,
        abort_handle_writers: abort_handles,
    })
}

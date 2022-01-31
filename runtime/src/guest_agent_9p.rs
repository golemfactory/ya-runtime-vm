use futures::channel::mpsc;
use futures::future::{BoxFuture, FutureExt};
use futures::lock::Mutex;
use futures::{SinkExt, StreamExt};
//use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, marker::PhantomData};
#[cfg(windows)]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{split, AsyncWriteExt, ReadHalf, WriteHalf},
    spawn, time,
};
pub use crate::response_parser_9p::Notification9p;
use crate::response_parser_9p::{GuestAgentMessage9p, parse_one_response_9p, ResponseCustomP9};

#[cfg(unix)]
type PlatformStream = UnixStream;
#[cfg(windows)]
type PlatformStream = TcpStream;

#[cfg(unix)]
type PlatformAddr = Path;

/*
#[cfg(windows)]
type PlatformAddr = SocketAddr;
*/

type OutputStream = WriteHalf<PlatformStream>;
type InputStream = ReadHalf<PlatformStream>;

pub struct GuestAgent9p {
    stream: OutputStream,
    responses: mpsc::Receiver<ResponseCustomP9>,
    responses_reader_handle: Option<tokio::task::JoinHandle<io::Error>>,
}

fn reader<'f, F>(
    agent: Arc<Mutex<GuestAgent9p>>,
    mut stream: InputStream,
    mut notification_handler: F,
    mut responses: mpsc::Sender<ResponseCustomP9>,
) -> BoxFuture<'f, io::Error>
    where
        F: FnMut(Notification9p, Arc<Mutex<GuestAgent9p>>) -> BoxFuture<'static, ()> + Send + 'static,
{
    let (mut tx, rx) = mpsc::channel(8);
    spawn(async move {
        let _ = rx
            .for_each(|n| notification_handler(n, agent.clone()))
            .await;
    });
    async move {
        loop {
            match parse_one_response_9p(&mut stream).await {
                Ok(msg) => match msg {
                    GuestAgentMessage9p::Notification(notification) => {
                        let _ = tx.send(notification).await;
                    }
                    GuestAgentMessage9p::Response(resp) => {
                        responses.send(resp).await.expect("failed to send response");
                    }
                },
                Err(err) => return err,
            }
        }
    }
        .boxed()
}

impl GuestAgent9p {
    pub async fn connected<F>(
        path: &str,
        timeout: u32,
        notification_handler: F
    ) -> io::Result<Arc<Mutex<GuestAgent9p>>>
    where
        F: FnMut(Notification9p, Arc<Mutex<GuestAgent9p>>) -> BoxFuture<'static, ()> + Send + 'static,
    {
        let mut timeout_remaining = timeout;
        loop {
            match PlatformStream::connect(path).await {
                Ok(s) => {
                    let (stream_read, stream_write) = split(s);
                    let (response_send, response_receive) = mpsc::channel(10);
                    let ga = Arc::new(Mutex::new(GuestAgent9p {
                        stream: stream_write,
                        responses: response_receive,
                        responses_reader_handle: None
                    }));
                    let reader_handle = spawn(reader(
                        ga.clone(),
                        stream_read,
                        notification_handler,
                        response_send,
                    ));
                    ga.lock()
                        .await
                        .responses_reader_handle
                        .replace(reader_handle);
                    break Ok(ga);
                }
                Err(err) => match err.kind() {
                    io::ErrorKind::NotFound => {
                        log::info!("Waiting for Guest Agent socket ...");
                    }
                    _ => break Err(err),
                },
            };
        }
    }
}

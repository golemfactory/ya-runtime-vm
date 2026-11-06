//! In-memory vsock stream transport between the Tokio runtime and OpenVMM's vsock worker.
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
use virtio_vsock::{MemoryStream, PortConnector, RelaySocket};

type RegisteredListener = (u32, mpsc::Sender<LocalStream>);

static REGISTERED_LISTENERS: OnceLock<Mutex<HashMap<String, RegisteredListener>>> = OnceLock::new();

fn registered_listeners() -> &'static Mutex<HashMap<String, RegisteredListener>> {
    REGISTERED_LISTENERS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) struct LocalListener {
    id: String,
    rx: mpsc::Receiver<LocalStream>,
}

pub(crate) struct LocalStream {
    stream: MemoryStream,
}

impl LocalListener {
    pub(crate) fn bind(port: u32) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = mpsc::channel(4);
        registered_listeners().lock().insert(id.clone(), (port, tx));
        Self { id, rx }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) async fn accept(&mut self) -> io::Result<LocalStream> {
        self.rx.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "in-memory vsock listener channel closed",
            )
        })
    }
}

impl Drop for LocalListener {
    fn drop(&mut self) {
        registered_listeners().lock().remove(&self.id);
    }
}

pub(crate) fn take_registered_vsock_connector(id: &str) -> anyhow::Result<PortConnector> {
    let (expected_port, tx) = registered_listeners()
        .lock()
        .remove(id)
        .ok_or_else(|| anyhow::anyhow!("vsock listener {id} was not registered"))?;
    Ok(Arc::new(move |port| {
        if port != expected_port {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("unexpected vsock port {port}"),
            ));
        }
        let (relay_socket, stream) = RelaySocket::pair();
        tx.try_send(LocalStream { stream }).map_err(|_| {
            io::Error::new(io::ErrorKind::ConnectionRefused, "vsock listener closed")
        })?;
        Ok(relay_socket)
    }))
}

impl LocalStream {
    #[cfg(test)]
    pub(crate) fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = MemoryStream::pair();
        Ok((Self { stream: a }, Self { stream: b }))
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let slice = buf.initialize_unfilled();
        match self.stream.poll_read_slice(cx, slice) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream.poll_write_slice(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_shutdown(cx)
    }
}

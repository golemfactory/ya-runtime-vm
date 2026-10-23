//! Local relay sockets driven by OpenVMM's portable Linux/Windows I/O pool.
use pal_async::{socket::PolledSocket, DefaultDriver, DefaultPool};
use std::{
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

pub(crate) struct LocalListener {
    socket: PolledSocket<unix_socket::UnixListener>,
    driver: DefaultDriver,
}

pub(crate) struct LocalStream {
    socket: Compat<PolledSocket<unix_socket::UnixStream>>,
    // The pool thread stops once its last driver is dropped.
    _driver: DefaultDriver,
}

fn driver() -> DefaultDriver {
    DefaultPool::spawn_on_thread("guest-agent-relay").1
}

impl LocalListener {
    pub(crate) fn bind(path: &Path) -> io::Result<Self> {
        let driver = driver();
        let socket = PolledSocket::new(&driver, unix_socket::UnixListener::bind(path)?)?;
        Ok(Self { socket, driver })
    }

    pub(crate) async fn accept(&mut self) -> io::Result<LocalStream> {
        let (socket, _) = self.socket.accept().await?;
        Ok(LocalStream {
            socket: PolledSocket::new(&self.driver, socket)?.compat(),
            _driver: self.driver.clone(),
        })
    }
}

impl LocalStream {
    pub(crate) async fn connect(path: &Path) -> io::Result<Self> {
        let driver = driver();
        let socket = PolledSocket::connect_unix(&driver, path).await?.compat();
        Ok(Self {
            socket,
            _driver: driver,
        })
    }

    #[cfg(test)]
    pub(crate) fn pair() -> io::Result<(Self, Self)> {
        let driver = driver();
        let (a, b) = unix_socket::UnixStream::pair()?;
        Ok((
            Self {
                socket: PolledSocket::new(&driver, a)?.compat(),
                _driver: driver.clone(),
            },
            Self {
                socket: PolledSocket::new(&driver, b)?.compat(),
                _driver: driver,
            },
        ))
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

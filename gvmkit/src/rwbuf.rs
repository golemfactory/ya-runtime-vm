use bytes::{Buf, BytesMut};
use std::io::{Read, Result, Write};

// wrapper for BytesMut so we can implement Read/Write
pub struct RWBuffer {
    pub bytes: BytesMut,
}

impl RWBuffer {
    pub fn new() -> RWBuffer {
        RWBuffer {
            bytes: BytesMut::new(),
        }
    }
}

impl Write for RWBuffer {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for RWBuffer {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.bytes.copy_to_slice(buf);
        Ok(buf.len())
    }
}

impl From<BytesMut> for RWBuffer {
    fn from(bytes: BytesMut) -> Self {
        RWBuffer { bytes }
    }
}

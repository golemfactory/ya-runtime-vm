use bytes::{Buf, BytesMut};
use std::io::{Read, Write};

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
    /*fn slice<'a>(&'a self, x: usize, y: usize) -> &'a [u8] {
        &self.bytes[x..y]
    }*/
}

impl Write for RWBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for RWBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.bytes.copy_to_slice(buf);
        Ok(buf.len())
    }
}

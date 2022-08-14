use std::{pin::Pin, task::{Context, Poll}, net::SocketAddr};

use tokio::{net::TcpStream, io::{AsyncRead, AsyncWrite, ReadBuf, self}};


pub(crate) struct SessionStream {
    stream: TcpStream,
}

// unsafe impl Send for SessionStream {
// }

// unsafe impl Sync for SessionStream {
// }

impl SessionStream {
    pub fn new(stream: TcpStream) -> Self {
        SessionStream {
            stream
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::result::Result<(), io::Error>> {
        let stream_wrapper = Pin::into_inner(self);

        // let mut encrypted_readbuf_inner  = [0u8; 1042];
        // let mut r_buf = ReadBuf::new(&mut encrypted_readbuf_inner);

        let r = AsyncRead::poll_read(Pin::new(&mut stream_wrapper.stream), cx, buf);

        r
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_write(Pin::new(&mut stream_wrapper.stream), cx, &buf);
        r
    }

    // fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    //     let stream_wrapper = Pin::into_inner(self);
    //     let r = AsyncWrite::poll_close(Pin::new(&mut stream_wrapper.stream), cx);
    //     r
    // }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_flush(Pin::new(&mut stream_wrapper.stream), cx);
        r
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>],) -> Poll<io::Result<usize>> {
            for b in bufs {
                if !b.is_empty() {
                    return self.poll_write(cx, b);
                }
            }
            self.poll_write(cx, &[])
    }

    fn is_write_vectored(&self) -> bool {
        false
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_shutdown(Pin::new(&mut stream_wrapper.stream), cx);
        r
    }
}
use std::{pin::Pin, task::{Context, Poll}, net::SocketAddr, sync::{Arc, Mutex}};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, self};

use crate::session_stream::SessionStream;

pub(crate) struct SessionStreamWrapper {
    stream: Arc<Mutex<Box<SessionStream>>>,
}

impl SessionStreamWrapper {
    pub fn new(stream: Arc<Mutex<Box<SessionStream>>>) -> Self {
        SessionStreamWrapper {
            stream
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        //let a = self.stream.lock().unwrap().as_mut();
        self.stream.lock().unwrap().peer_addr()
    }
}

impl AsyncRead for SessionStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::result::Result<(), io::Error>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncRead::poll_read(Pin::new(&mut stream_wrapper.stream.lock().unwrap().as_mut()), cx, buf);
        r
    }
}

impl AsyncWrite for SessionStreamWrapper {
    fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_write(Pin::new(&mut stream_wrapper.stream.lock().unwrap().as_mut()), cx, &buf);
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_flush(Pin::new(&mut stream_wrapper.stream.lock().unwrap().as_mut()), cx);
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
        //TODO: change hyper conn to conn w/o shutdown!
        // let stream_wrapper = Pin::into_inner(self);
        // let r = AsyncWrite::poll_shutdown(Pin::new(&mut stream_wrapper.stream.lock().unwrap().as_mut()), cx);
        // r
        Poll::Ready(Ok(()))
    }
}
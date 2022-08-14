use std::{pin::Pin, task::{Context, Poll}, net::SocketAddr, cell::RefCell, io::{ErrorKind, Error}, cmp::min};

use aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use byteorder::{LittleEndian, ByteOrder};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use tokio::{net::TcpStream, io::{AsyncRead, AsyncWrite, ReadBuf, self}};

use crate::utils;


pub(crate) struct SessionStream {
    stream: TcpStream,
    session_decryptor: RefCell<Option<SessionDecryptor>>,
    session_encryptor: RefCell<Option<SessionEncryptor>>,
    dec_buffer: Vec<u8>,
}

// unsafe impl Send for SessionStream {
// }

// unsafe impl Sync for SessionStream {
// }

impl SessionStream {
    pub fn new(stream: TcpStream) -> Self {
        SessionStream {
            stream,
            session_decryptor: RefCell::new(None),
            session_encryptor: RefCell::new(None),
            dec_buffer: vec![],
        }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn set_shared_secret(&self, shared_secret: &[u8; 32]) {
        let decryptor = SessionDecryptor::new(compute_read_key(shared_secret).unwrap());
        self.session_decryptor.borrow_mut().replace(decryptor);
        let encryptor = SessionEncryptor::new(compute_write_key(shared_secret).unwrap());
        self.session_encryptor.borrow_mut().replace(encryptor);
    }
}

impl AsyncRead for SessionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<std::result::Result<(), io::Error>> {
        let session_stream = Pin::into_inner(self);

        let r = AsyncRead::poll_read(Pin::new(&mut session_stream.stream), cx, buf);
        if session_stream.session_decryptor.borrow().is_none() {
            return r;
        }

        let mut db = session_stream.session_decryptor.borrow_mut();
        let d = db.as_mut().unwrap();
        let dec_result = d.append_data(buf.filled());

        if dec_result.is_err() {
            return Poll::Ready(Err(Error::from(ErrorKind::InvalidData)));
        }

        let data = dec_result.ok().unwrap();
        session_stream.dec_buffer.extend(data);

        if session_stream.dec_buffer.is_empty() {
            return Poll::Pending;
        }

        let r_len = min(buf.capacity(), session_stream.dec_buffer.len());
        buf.put_slice(session_stream.dec_buffer.as_slice());
        session_stream.dec_buffer.drain(.. r_len);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let session_stream = Pin::into_inner(self);

        if session_stream.session_encryptor.borrow().is_none() {
            let r = AsyncWrite::poll_write(Pin::new(&mut session_stream.stream), cx, &buf);
            return r;
        }

        let mut db = session_stream.session_encryptor.borrow_mut();
        let d = db.as_mut().unwrap();
        let res = d.encrypt_data(buf);
        if res.is_err() {
            return Poll::Ready(Err(Error::from(ErrorKind::InvalidData)));
        }

        let e_buf = res.ok().unwrap();
        let r = AsyncWrite::poll_write(Pin::new(&mut session_stream.stream), cx, &e_buf.as_slice());
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_flush(Pin::new(&mut stream_wrapper.stream), cx);
        r
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let stream_wrapper = Pin::into_inner(self);
        let r = AsyncWrite::poll_shutdown(Pin::new(&mut stream_wrapper.stream), cx);
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
}

#[derive(PartialEq, Eq)]
enum DecState {
    WaitForHeader,
    WaitForData,
}

struct SessionDecryptor {
    read_key: [u8;32],
    rec_buffer: Vec<u8>,
    data_length: u16,
    dec_state: DecState,
    dec_count: u64, //counter of decripted pakets
}

impl SessionDecryptor {
    pub fn new(read_key: [u8;32]) -> Self {
        SessionDecryptor {
            read_key,
            rec_buffer: vec![],
            data_length: 0,
            dec_state: DecState::WaitForHeader,
            dec_count: 0,
        }
    }

    pub fn append_data(&mut self, data: &[u8]) -> Result<Vec<u8>, ()> {
        self.rec_buffer.extend_from_slice(&data);

        if self.dec_state == DecState::WaitForHeader {
            if self.rec_buffer.len() >= 2 {
                let data_length = LittleEndian::read_u16(data);
                self.data_length = data_length + 2 + 16; //adding 2 for pkt len + 16 for authTag
                self.dec_state = DecState::WaitForData;
            }
        }

        if (self.rec_buffer.len() as u16) < self.data_length {
            return Ok(vec![]);
        }

        let (pkt, _) = self.rec_buffer.split_at((self.data_length + 1).into());

        let res = self.decode_buffer(pkt);
        if res.is_err() {
            return Err(());
        }
        self.dec_count += 1;
        self.rec_buffer.drain(..self.data_length as usize);
        self.dec_state = DecState::WaitForHeader;

        Ok(res.ok().unwrap())
    }

    fn decode_buffer(&self, pkt: &[u8]) -> Result<Vec<u8>, ()> {
        let aad = &pkt[..2];
        let data_len = LittleEndian::read_u16(aad);
        let data = &pkt[2 .. data_len as usize];
        let auth_tag = &pkt[(data_len + 2) as usize .. ];

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&self.read_key));

        let mut nonce = vec![0; 4];
        let mut suffix = vec![0; 8];
        LittleEndian::write_u64(&mut suffix, self.dec_count);
        nonce.extend(suffix);


        let mut buffer = Vec::new();
        buffer.extend_from_slice(data);
        let res = aead.decrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut buffer, Tag::from_slice(&auth_tag));

        if res.is_err() {
            return Err(());
        }
        Ok(buffer)
    }
}


struct SessionEncryptor {
    write_key: [u8;32],
    enc_count: u64,
}

impl SessionEncryptor {
    pub fn new(write_key: [u8;32]) -> Self {
        SessionEncryptor {
            write_key,
            enc_count: 0,
        }
    }

    pub fn encrypt_data(&mut self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&self.write_key));

        let mut nonce = vec![0; 4];
        let mut suffix = vec![0; 8];
        LittleEndian::write_u64(&mut suffix, self.enc_count);
        nonce.extend(suffix);
        self.enc_count += 1;

        let mut aad = [0; 2];
        LittleEndian::write_u16(&mut aad, data.len() as u16);

        let mut buffer = Vec::new();
        buffer.extend_from_slice(data);
        let res = aead.encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut buffer);
        if res.is_err() {
            return Err(());
        }

        let auth_tag = res.ok().unwrap();

        let mut pkt = Vec::new();
        pkt.extend(aad);
        pkt.extend(buffer);
        pkt.extend(auth_tag);

        Ok(pkt)
    }
}

fn compute_read_key(shared_secret: &[u8; 32]) -> Result<[u8; 32], ()> {
    compute_key(shared_secret, b"Control-Write-Encryption-Key")
}

fn compute_write_key(shared_secret: &[u8; 32]) -> Result<[u8; 32], ()> {
    compute_key(shared_secret, b"Control-Read-Encryption-Key")
}

fn compute_key(shared_secret: &[u8; 32], info: &[u8]) -> Result<[u8; 32], ()> {
    utils::hkdf_extract_and_expand(b"Control-Salt", shared_secret, info)
}
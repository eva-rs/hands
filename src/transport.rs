//! The encrypted channel.
//!
//! Noise `NNpsk0` over TCP via `snow`: both sides send an ephemeral key (so the
//! session has forward secrecy), and the pre-shared key is mixed in at the very
//! start of the handshake. Without the matching PSK the first message fails to
//! authenticate, so a connection cannot be established — there is no
//! unencrypted, unauthenticated path in.
//!
//! [`EncryptedStream`] wraps the TCP stream as a plain encrypted byte pipe
//! (`AsyncRead + AsyncWrite`); the protocol frames ride on top of it unchanged.
//! Under the hood each Noise message is length-prefixed (`u16`) and carries at
//! most `MAX_PAYLOAD` plaintext bytes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, ToSocketAddrs};

const PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

/// A Noise message is at most 65535 bytes; 16 of those are the AEAD tag.
const MAX_NOISE_MSG: usize = 65535;
const MAX_PAYLOAD: usize = MAX_NOISE_MSG - 16;

fn noise_io(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

fn builder(psk: &[u8; 32]) -> io::Result<Builder<'_>> {
    let params = PARAMS
        .parse()
        .map_err(|e| io::Error::other(format!("bad noise params: {e}")))?;
    Builder::new(params).psk(0, psk).map_err(noise_io)
}

async fn write_handshake<S: AsyncWrite + Unpin>(
    inner: &mut S,
    hs: &mut HandshakeState,
    scratch: &mut [u8],
) -> io::Result<()> {
    let n = hs.write_message(&[], scratch).map_err(noise_io)?;
    inner.write_all(&(n as u16).to_be_bytes()).await?;
    inner.write_all(&scratch[..n]).await?;
    inner.flush().await
}

async fn read_handshake<S: AsyncRead + Unpin>(
    inner: &mut S,
    hs: &mut HandshakeState,
) -> io::Result<()> {
    let mut len = [0u8; 2];
    inner.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut msg = vec![0u8; n];
    inner.read_exact(&mut msg).await?;
    let mut out = vec![0u8; n];
    hs.read_message(&msg, &mut out).map_err(noise_io)?;
    Ok(())
}

/// Responder side of the handshake (the daemon). `NNpsk0` is `-> e` then
/// `<- e, ee`, so the responder reads first.
pub async fn responder_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut inner: S,
    psk: &[u8; 32],
) -> io::Result<EncryptedStream<S>> {
    let mut hs = builder(psk)?.build_responder().map_err(noise_io)?;
    let mut scratch = vec![0u8; MAX_NOISE_MSG];
    read_handshake(&mut inner, &mut hs).await?;
    write_handshake(&mut inner, &mut hs, &mut scratch).await?;
    let transport = hs.into_transport_mode().map_err(noise_io)?;
    Ok(EncryptedStream::new(inner, transport))
}

/// Initiator side of the handshake (the client).
pub async fn initiator_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut inner: S,
    psk: &[u8; 32],
) -> io::Result<EncryptedStream<S>> {
    let mut hs = builder(psk)?.build_initiator().map_err(noise_io)?;
    let mut scratch = vec![0u8; MAX_NOISE_MSG];
    write_handshake(&mut inner, &mut hs, &mut scratch).await?;
    read_handshake(&mut inner, &mut hs).await?;
    let transport = hs.into_transport_mode().map_err(noise_io)?;
    Ok(EncryptedStream::new(inner, transport))
}

/// Connect to a daemon and complete the handshake. A wrong key surfaces here as
/// an error.
pub async fn connect<A: ToSocketAddrs>(
    addr: A,
    psk: &[u8; 32],
) -> io::Result<EncryptedStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true).ok();
    initiator_handshake(tcp, psk).await
}

/// An encrypted byte stream over an inner transport.
pub struct EncryptedStream<S> {
    inner: S,
    noise: TransportState,

    // Reading: a 2-byte length, then that many ciphertext bytes, then decrypt.
    rx_len: [u8; 2],
    rx_len_got: usize,
    rx_body: Vec<u8>,
    rx_body_need: usize,
    rx_body_got: usize,
    rx_plain: Vec<u8>,
    rx_plain_pos: usize,

    // Writing: buffer plaintext until flush, then seal and drain to the inner.
    tx_plain: Vec<u8>,
    tx_enc: Vec<u8>,
    tx_enc_pos: usize,
}

impl<S> EncryptedStream<S> {
    fn new(inner: S, noise: TransportState) -> Self {
        Self {
            inner,
            noise,
            rx_len: [0u8; 2],
            rx_len_got: 0,
            rx_body: Vec::new(),
            rx_body_need: 0,
            rx_body_got: 0,
            rx_plain: Vec::new(),
            rx_plain_pos: 0,
            tx_plain: Vec::new(),
            tx_enc: Vec::new(),
            tx_enc_pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> EncryptedStream<S> {
    /// Seal any buffered plaintext and drive the encrypted bytes to the inner
    /// stream. Returns `Ready(Ok(()))` only once everything sealed so far is
    /// written.
    fn drive_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.tx_enc_pos == self.tx_enc.len() && !self.tx_plain.is_empty() {
            self.tx_enc.clear();
            self.tx_enc_pos = 0;
            for chunk in self.tx_plain.chunks(MAX_PAYLOAD) {
                let mut out = vec![0u8; chunk.len() + 16];
                let n = self
                    .noise
                    .write_message(chunk, &mut out)
                    .map_err(noise_io)?;
                self.tx_enc.extend_from_slice(&(n as u16).to_be_bytes());
                self.tx_enc.extend_from_slice(&out[..n]);
            }
            self.tx_plain.clear();
        }

        while self.tx_enc_pos < self.tx_enc.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.tx_enc[self.tx_enc_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.tx_enc_pos += n;
        }
        self.tx_enc.clear();
        self.tx_enc_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.rx_plain_pos < me.rx_plain.len() {
                let n = buf.remaining().min(me.rx_plain.len() - me.rx_plain_pos);
                buf.put_slice(&me.rx_plain[me.rx_plain_pos..me.rx_plain_pos + n]);
                me.rx_plain_pos += n;
                return Poll::Ready(Ok(()));
            }

            if me.rx_body_need == 0 {
                // Reading the 2-byte length prefix.
                while me.rx_len_got < 2 {
                    let mut tmp = ReadBuf::new(&mut me.rx_len[me.rx_len_got..2]);
                    ready!(Pin::new(&mut me.inner).poll_read(cx, &mut tmp))?;
                    let filled = tmp.filled().len();
                    if filled == 0 {
                        return if me.rx_len_got == 0 {
                            Poll::Ready(Ok(())) // clean EOF on a message boundary
                        } else {
                            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                        };
                    }
                    me.rx_len_got += filled;
                }
                let need = u16::from_be_bytes(me.rx_len) as usize;
                me.rx_len_got = 0;
                if need == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "empty noise message",
                    )));
                }
                me.rx_body_need = need;
                me.rx_body = vec![0u8; need];
                me.rx_body_got = 0;
            }

            // Reading the ciphertext body.
            while me.rx_body_got < me.rx_body_need {
                let mut tmp = ReadBuf::new(&mut me.rx_body[me.rx_body_got..me.rx_body_need]);
                ready!(Pin::new(&mut me.inner).poll_read(cx, &mut tmp))?;
                let filled = tmp.filled().len();
                if filled == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                me.rx_body_got += filled;
            }

            let mut plain = vec![0u8; me.rx_body_need];
            let n = me
                .noise
                .read_message(&me.rx_body, &mut plain)
                .map_err(noise_io)?;
            plain.truncate(n);
            me.rx_plain = plain;
            me.rx_plain_pos = 0;
            me.rx_body_need = 0;
            me.rx_body_got = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.tx_plain.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.drive_write(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.drive_write(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

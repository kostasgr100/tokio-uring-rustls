use crate::buffer::{SyncReadAdaptor, SyncWriteAdaptor};

use rustls::{ClientConfig, ClientConnection, ConnectionCommon, SideData, pki_types::ServerName};
use std::{
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio_uring::{buf::{IoBuf, IoBufMut}, BufResult};
tokio::net::TcpStream;

pub struct TlsStream<C> {
    pub(crate) io: TcpStream,
    pub(crate) session: C,
    pub(crate) rbuffer: SyncReadAdaptor,
    pub(crate) wbuffer: SyncWriteAdaptor,
}

impl<C, SD: SideData> TlsStream<C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub fn new(io: TcpStream, session: C) -> Self {
        TlsStream {
            io,
            session,
            rbuffer: SyncReadAdaptor::default(),
            wbuffer: SyncWriteAdaptor::default(),
        }
    }

    pub fn new_client(
        io: TcpStream,
        config: Arc<ClientConfig>,
        domain: ServerName<'static>,
    ) -> io::Result<TlsStream<ClientConnection>> {
        let session = ClientConnection::new(config, domain)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(TlsStream {
            io,
            session,
            rbuffer: SyncReadAdaptor::default(),
            wbuffer: SyncWriteAdaptor::default(),
        })
    }

    async fn read_io(&mut self) -> io::Result<usize> {
        let n = loop {
            match self.session.read_tls(&mut self.rbuffer) {
                Ok(n) => break n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.rbuffer.do_io(&mut self.io).await?;
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        let state = match self.session.process_new_packets() {
            Ok(state) => state,
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
        };

        if state.peer_has_closed() && self.session.is_handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls handshake alert",
            ));
        }

        Ok(n)
    }

    async fn write_io(&mut self) -> io::Result<usize> {
        let n = loop {
            match self.session.write_tls(&mut self.wbuffer) {
                Ok(n) => break n,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.wbuffer.do_io(&mut self.io).await?;
                    continue;
                }
                Err(err) => return Err(err),
            }
        };

        self.wbuffer.do_io(&mut self.io).await?;
        Ok(n)
    }

    pub async fn handshake(&mut self) -> io::Result<(usize, usize)> {
        let mut wrlen = 0;
        let mut rdlen = 0;
        let mut eof = false;

        loop {
            while self.session.wants_write() && self.session.is_handshaking() {
                wrlen += self.write_io().await?;
            }

            while !eof && self.session.wants_read() && self.session.is_handshaking() {
                let n = self.read_io().await?;
                rdlen += n;
                if n == 0 {
                    eof = true;
                }
            }

            match (eof, self.session.is_handshaking()) {
                (true, true) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls handshake eof",
                    ));
                }
                (false, true) => (),
                (_, false) => break,
            };
        }

        while self.session.wants_write() {
            wrlen += self.write_io().await?;
        }

        Ok((rdlen, wrlen))
    }

    pub async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let slice = unsafe { std::slice::from_raw_parts_mut(buf.stable_mut_ptr(), buf.bytes_total()) };

        loop {
            match self.session.reader().read(slice) {
                Ok(n) => {
                    unsafe { buf.set_init(n) };
                    return (Ok(n), buf);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => (),
                Err(e) => return (Err(e), buf),
            }

            match self.read_io().await {
                Ok(0) => {
                    return (
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "tls raw stream eof",
                        )),
                        buf,
                    );
                }
                Ok(_) => (),
                Err(e) => return (Err(e), buf),
            }
        }
    }

    pub async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let slice = unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) };

        let size = match self.session.writer().write(slice) {
            Ok(l) => l,
            Err(e) => return (Err(e), buf),
        };

        if let Err(e) = self.session.writer().flush() {
            return (Err(e), buf);
        }

        while self.session.wants_write() {
            match self.write_io().await {
                Ok(0) => break,
                Ok(_) => (),
                Err(e) => return (Err(e), buf),
            }
        }

        (Ok(size), buf)
    }

    pub async fn write_all<B: IoBuf>(&mut self, buf: B) -> BufResult<(), B> {
        let slice = unsafe { std::slice::from_raw_parts(buf.stable_ptr(), buf.bytes_init()) };

        if let Err(e) = self.session.writer().write_all(slice) {
            return (Err(e), buf);
        }

        if let Err(e) = self.session.writer().flush() {
            return (Err(e), buf);
        }

        while self.session.wants_write() {
            match self.write_io().await {
                Ok(0) => break,
                Ok(_) => (),
                Err(e) => return (Err(e), buf),
            }
        }

        (Ok(()), buf)
    }
}

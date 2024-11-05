use crate::stream::TlsStream;

use rustls::{ClientConfig, ClientConnection};
use std::{
    io::{self, Error, ErrorKind},
    sync::Arc,
};
use tokio_uring::net::TcpStream;

#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    #[inline]
    fn from(inner: Arc<ClientConfig>) -> TlsConnector {
        TlsConnector { inner }
    }
}

impl TlsConnector {
    pub async fn connect(
        &self,
        domain: rustls::ServerName,
        socket: TcpStream,
    ) -> io::Result<TlsStream<ClientConnection>> { 
        let connector = rustls::ClientConnection::new(self.inner.clone(), domain)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut stream = TlsStream::new(socket, connector);
        stream.handshake().await?;
        Ok(stream)
    }
}

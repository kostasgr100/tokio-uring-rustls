use crate::stream::TlsStream;

use rustls::{pki_types::ServerName, ClientConfig, ClientConnection};
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
        domain: ServerName<'static>,
        socket: TcpStream,
    ) -> io::Result<TlsStream<ClientConnection>> {
        let mut stream = TlsStream::<ClientConnection>::new_client(socket, self.inner.clone(), domain)?;
        stream.handshake().await?;
        Ok(stream)
    }
}

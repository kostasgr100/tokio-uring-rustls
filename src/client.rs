use std::io;
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, ServerName};
use tokio_rustls::{TlsConnector, TlsStream};
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
    ) -> io::Result<TlsStream<TcpStream, ClientConnection>> { 
        let connector = TlsConnector::from(self.inner.clone());
        connector.connect(domain, socket).await
    }
}

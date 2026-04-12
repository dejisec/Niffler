use std::net::SocketAddr;

use nfs3_client::net::Connector;
use nfs3_client::tokio::TokioIo;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// nfs3_client Connector that routes all TCP connections through a SOCKS5 proxy.
///
/// After SOCKS5 negotiation, `into_inner()` extracts the raw `TcpStream`
/// so the `Connection` associated type matches `TokioConnector` exactly.
pub struct SocksConnector {
    pub proxy_addr: SocketAddr,
}

impl Connector for SocksConnector {
    type Connection = TokioIo<TcpStream>;

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::Connection> {
        let stream = Socks5Stream::connect(self.proxy_addr, addr)
            .await
            .map_err(|e| std::io::Error::other(format!("SOCKS5 proxy: {e}")))?;
        let inner = stream.into_inner();
        super::transport::configure_stream(&inner)?;
        Ok(TokioIo::new(inner))
    }

    async fn connect_with_port(
        &self,
        addr: SocketAddr,
        _local_port: u16,
    ) -> std::io::Result<Self::Connection> {
        // SOCKS proxies don't support binding to specific local ports.
        self.connect(addr).await
    }
}

/// Connect TCP, optionally through a SOCKS5 proxy.
pub async fn tcp_connect(
    addr: SocketAddr,
    proxy: Option<SocketAddr>,
) -> std::io::Result<TcpStream> {
    if let Some(proxy_addr) = proxy {
        let stream = Socks5Stream::connect(proxy_addr, addr)
            .await
            .map_err(|e| std::io::Error::other(format!("SOCKS5 proxy: {e}")))?;
        let inner = stream.into_inner();
        super::transport::configure_stream(&inner)?;
        Ok(inner)
    } else {
        let stream = TcpStream::connect(addr).await?;
        super::transport::configure_stream(&stream)?;
        Ok(stream)
    }
}

/// Resolve a host:port string and connect, optionally through SOCKS5.
pub async fn tcp_connect_str(addr: &str, proxy: Option<SocketAddr>) -> std::io::Result<TcpStream> {
    if let Some(proxy_addr) = proxy {
        // Pass the hostname string directly to the SOCKS5 proxy for remote DNS
        // resolution. Local resolution would defeat the proxy for internal
        // hostnames only resolvable within the proxy's network.
        let stream = Socks5Stream::connect(proxy_addr, addr)
            .await
            .map_err(|e| std::io::Error::other(format!("SOCKS5 proxy: {e}")))?;
        let inner = stream.into_inner();
        super::transport::configure_stream(&inner)?;
        Ok(inner)
    } else {
        let stream = TcpStream::connect(addr).await?;
        super::transport::configure_stream(&stream)?;
        Ok(stream)
    }
}

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nfs3_client::net::Connector;
use nfs3_client::tokio::TokioIo;
use tokio::net::{TcpSocket, TcpStream};

pub struct NifflerTokioConnector;

impl Connector for NifflerTokioConnector {
    type Connection = TokioIo<TcpStream>;

    async fn connect(&self, addr: SocketAddr) -> std::io::Result<Self::Connection> {
        let stream = TcpStream::connect(addr).await?;
        configure_stream(&stream)?;
        Ok(TokioIo::new(stream))
    }

    async fn connect_with_port(
        &self,
        addr: SocketAddr,
        local_port: u16,
    ) -> std::io::Result<Self::Connection> {
        let socket = if addr.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        let bind_addr = if addr.is_ipv6() {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), local_port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)
        };
        socket.bind(bind_addr)?;
        let stream = socket.connect(addr).await?;
        configure_stream(&stream)?;
        Ok(TokioIo::new(stream))
    }
}

pub(crate) fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    configure_keepalive(stream)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        ) == -1
        {
            tracing::warn!(
                "setsockopt SO_KEEPALIVE failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let idle: libc::c_int = 30;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &idle as *const _ as *const libc::c_void,
            std::mem::size_of_val(&idle) as libc::socklen_t,
        ) == -1
        {
            tracing::warn!(
                "setsockopt TCP_KEEPIDLE failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let interval: libc::c_int = 10;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &interval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&interval) as libc::socklen_t,
        ) == -1
        {
            tracing::warn!(
                "setsockopt TCP_KEEPINTVL failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let count: libc::c_int = 3;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPCNT,
            &count as *const _ as *const libc::c_void,
            std::mem::size_of_val(&count) as libc::socklen_t,
        ) == -1
        {
            tracing::warn!(
                "setsockopt TCP_KEEPCNT failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    unsafe {
        let val: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        ) == -1
        {
            tracing::warn!(
                "setsockopt SO_KEEPALIVE failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let idle: libc::c_int = 30;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPALIVE,
            &idle as *const _ as *const libc::c_void,
            std::mem::size_of_val(&idle) as libc::socklen_t,
        ) == -1
        {
            tracing::warn!(
                "setsockopt TCP_KEEPALIVE failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn configure_keepalive(_stream: &TcpStream) -> std::io::Result<()> {
    Ok(())
}

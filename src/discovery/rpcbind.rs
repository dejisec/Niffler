use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use nfs3_client::PortmapperClient;
use nfs3_client::tokio::TokioIo;
use tokio::time::timeout;

use crate::nfs::socks::tcp_connect_str;

#[derive(Debug, Clone)]
pub struct RpcServices {
    pub nfs_versions: Vec<u8>,
    pub mount_available: bool,
}

pub async fn query_rpc_services(
    host: &str,
    proxy: Option<SocketAddr>,
    timeout_secs: u64,
) -> Result<RpcServices> {
    let stream = timeout(
        Duration::from_secs(timeout_secs),
        tcp_connect_str(&format!("{host}:111"), proxy),
    )
    .await
    .context("portmapper connect timeout")?
    .context("portmapper connect failed")?;

    let io = TokioIo::new(stream);
    let mut pm = PortmapperClient::new(io);

    let mut nfs_versions = Vec::new();

    // Check NFSv3 (program 100003, version 3)
    if pm.getport(100_003, 3).await.is_ok() {
        nfs_versions.push(3);
    }

    // Check NFSv4 (program 100003, version 4)
    if pm.getport(100_003, 4).await.is_ok() {
        nfs_versions.push(4);
    }

    // Check MOUNT service (program 100005, version 3)
    let mount_available = pm.getport(100_005, 3).await.is_ok();

    Ok(RpcServices {
        nfs_versions,
        mount_available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST"]
    async fn query_portmapper_on_real_host() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let services = query_rpc_services(&host, None, 5).await.unwrap();
        println!("RPC services on {host}: {services:?}");
        assert!(services.nfs_versions.contains(&3));
        assert!(services.mount_available);
    }
}

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use tracing::{debug, info, warn};

use crate::nfs::socks::tcp_connect_str;

use super::rpcbind::query_rpc_services;
use super::targets::TargetHost;

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub host: TargetHost,
    pub rpcbind_open: bool,
    /// NFS/MOUNT confirmed via portmapper RPC query (not just port 111 open).
    pub nfs_via_rpcbind: bool,
    pub nfs_direct_open: bool,
}

impl PortScanResult {
    #[must_use]
    pub fn has_nfs(&self) -> bool {
        self.nfs_via_rpcbind || self.nfs_direct_open
    }
}

pub async fn scan_host(
    host: &TargetHost,
    timeout_ms: u64,
    proxy: Option<SocketAddr>,
    rpc_timeout_secs: u64,
) -> PortScanResult {
    let addr = host.to_string();
    let dur = Duration::from_millis(timeout_ms);

    let rpcbind_open = match timeout(dur, tcp_connect_str(&format!("{addr}:111"), proxy)).await {
        Ok(Ok(_stream)) => {
            debug!(host = %addr, port = 111, "port open");
            true
        }
        Ok(Err(e)) => {
            debug!(host = %addr, port = 111, error = %e, "port closed");
            false
        }
        Err(_) => {
            debug!(host = %addr, port = 111, "port scan timed out");
            false
        }
    };

    // If rpcbind is open, verify NFS/MOUNT is actually registered.
    // Spawned as a subtask so that panics inside nfs3_client's RPC layer
    // (e.g. "Fragment header does not have EOF flag") are caught here
    // with host context instead of propagating as an anonymous JoinError.
    let nfs_via_rpcbind = if rpcbind_open {
        let host_for_rpc = addr.clone();
        let rpc_handle = tokio::spawn(async move {
            query_rpc_services(&host_for_rpc, proxy, rpc_timeout_secs).await
        });
        match rpc_handle.await {
            Ok(Ok(services)) => {
                let has_nfs = services.mount_available || !services.nfs_versions.is_empty();
                if has_nfs {
                    debug!(host = %addr, nfs_versions = ?services.nfs_versions, mount = services.mount_available, "NFS confirmed via portmapper");
                } else {
                    debug!(host = %addr, "rpcbind open but no NFS/MOUNT registered");
                }
                has_nfs
            }
            Ok(Err(e)) => {
                debug!(host = %addr, error = %e, "portmapper query failed");
                false
            }
            Err(join_err) => {
                warn!(host = %addr, "portmapper query panicked: {}", join_err);
                false
            }
        }
    } else {
        false
    };

    let nfs_direct_open = match timeout(dur, tcp_connect_str(&format!("{addr}:2049"), proxy)).await
    {
        Ok(Ok(_stream)) => {
            debug!(host = %addr, port = 2049, "port open");
            true
        }
        Ok(Err(e)) => {
            debug!(host = %addr, port = 2049, error = %e, "port closed");
            false
        }
        Err(_) => {
            debug!(host = %addr, port = 2049, "port scan timed out");
            false
        }
    };

    PortScanResult {
        host: host.clone(),
        rpcbind_open,
        nfs_via_rpcbind,
        nfs_direct_open,
    }
}

pub async fn scan_hosts(
    hosts: Vec<TargetHost>,
    concurrency: usize,
    timeout_ms: u64,
    proxy: Option<SocketAddr>,
    rpc_timeout_secs: u64,
) -> Vec<PortScanResult> {
    let total = hosts.len();
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set = JoinSet::new();

    for host in hosts {
        let sem = Arc::clone(&sem);
        set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            scan_host(&host, timeout_ms, proxy, rpc_timeout_secs).await
        });
    }

    let mut results = Vec::new();
    while let Some(join_result) = set.join_next().await {
        match join_result {
            Ok(result) => {
                if result.has_nfs() {
                    results.push(result);
                } else {
                    debug!(host = %result.host, "no NFS ports detected, skipping host");
                }
            }
            Err(e) => warn!("port scan task panicked: {}", e),
        }
    }
    info!(
        total_scanned = total,
        nfs_found = results.len(),
        "port scan complete"
    );
    if results.is_empty() && total > 0 {
        debug!(
            "no hosts with open NFS ports found — check network connectivity and proxy settings"
        );
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_scan_result_nfs_via_rpcbind_only() {
        let r = PortScanResult {
            host: TargetHost::Ip("10.0.0.1".parse().unwrap()),
            rpcbind_open: true,
            nfs_via_rpcbind: true,
            nfs_direct_open: false,
        };
        assert!(r.has_nfs());
    }

    #[test]
    fn port_scan_result_rpcbind_without_nfs() {
        let r = PortScanResult {
            host: TargetHost::Ip("10.0.0.1".parse().unwrap()),
            rpcbind_open: true,
            nfs_via_rpcbind: false,
            nfs_direct_open: false,
        };
        assert!(!r.has_nfs());
    }

    #[tokio::test]
    #[ignore = "network-dependent — results vary by host"]
    async fn scan_localhost_ports() {
        let host = TargetHost::Ip("127.0.0.1".parse().unwrap());
        let result = scan_host(&host, 500, None, 5).await;
        // Just verify it completes without panic
        println!("localhost scan: {result:?}");
    }
}

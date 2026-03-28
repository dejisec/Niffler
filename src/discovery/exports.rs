use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use nfs3_client::MountClient;
use nfs3_client::PortmapperClient;
use nfs3_client::tokio::TokioIo;
use tokio::time::timeout;

use crate::nfs::socks::tcp_connect_str;
use crate::nfs::types::{ExportAccessOptions, NfsExport};

pub fn parse_access_options(export: &NfsExport) -> ExportAccessOptions {
    ExportAccessOptions {
        allowed_hosts: export.allowed_hosts.clone(),
    }
}

pub async fn list_exports(
    host: &str,
    proxy: Option<SocketAddr>,
    timeout_secs: u64,
) -> Result<Vec<NfsExport>> {
    // Query portmapper for MOUNT service port
    let pm_stream = timeout(
        Duration::from_secs(timeout_secs),
        tcp_connect_str(&format!("{host}:111"), proxy),
    )
    .await
    .context("portmapper connect timeout")?
    .context("portmapper connect failed")?;

    let mut pm = PortmapperClient::new(TokioIo::new(pm_stream));
    let mount_port = pm
        .getport(100_005, 3)
        .await
        .context("MOUNT service not registered")?;

    // Connect to MOUNT service
    let mount_stream = timeout(
        Duration::from_secs(timeout_secs),
        tcp_connect_str(&format!("{host}:{mount_port}"), proxy),
    )
    .await
    .context("mount connect timeout")?
    .context("mount connect failed")?;

    let mut mc = MountClient::new(TokioIo::new(mount_stream));
    let exports = mc.export().await.context("export listing failed")?;

    let results = exports
        .0
        .into_iter()
        .map(|node| {
            let path = String::from_utf8_lossy(node.ex_dir.0.as_ref()).to_string();
            let allowed_hosts = node
                .ex_groups
                .0
                .into_iter()
                .map(|name| String::from_utf8_lossy(name.0.as_ref()).to_string())
                .collect();
            NfsExport {
                path,
                allowed_hosts,
            }
        })
        .collect();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_access_options_wildcard() {
        let export = NfsExport {
            path: "/data".into(),
            allowed_hosts: vec!["*".into()],
        };
        let opts = parse_access_options(&export);
        assert_eq!(opts.allowed_hosts, vec!["*"]);
    }

    #[test]
    fn parse_access_options_cidr_list() {
        let export = NfsExport {
            path: "/share".into(),
            allowed_hosts: vec!["10.0.0.0/24".into(), "192.168.1.0/16".into()],
        };
        let opts = parse_access_options(&export);
        assert_eq!(opts.allowed_hosts.len(), 2);
        assert_eq!(opts.allowed_hosts[0], "10.0.0.0/24");
        assert_eq!(opts.allowed_hosts[1], "192.168.1.0/16");
    }

    #[test]
    fn parse_access_options_empty() {
        let export = NfsExport {
            path: "/empty".into(),
            allowed_hosts: vec![],
        };
        let opts = parse_access_options(&export);
        assert!(opts.allowed_hosts.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires NFS server — set NFS_TEST_HOST"]
    async fn list_exports_on_real_host() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let exports = list_exports(&host, None, 5).await.unwrap();
        assert!(!exports.is_empty());
        for export in &exports {
            println!("  {} -> {:?}", export.path, export.allowed_hosts);
        }
    }
}

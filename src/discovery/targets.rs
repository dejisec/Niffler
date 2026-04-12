use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;

use anyhow::Result;
use ipnet::IpNet;

use crate::config::settings::DiscoveryConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetHost {
    Ip(IpAddr),
    Hostname(String),
}

impl std::fmt::Display for TargetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

pub fn resolve_single_target(spec: &str) -> Result<Vec<TargetHost>> {
    if let Ok(network) = spec.parse::<IpNet>() {
        let hosts: Vec<TargetHost> = network.hosts().map(TargetHost::Ip).collect();
        if hosts.is_empty() {
            // /32 (IPv4) or /128 (IPv6): hosts() may return empty, use network addr
            return Ok(vec![TargetHost::Ip(network.addr())]);
        }
        return Ok(hosts);
    }
    if let Ok(addr) = spec.parse::<IpAddr>() {
        return Ok(vec![TargetHost::Ip(addr)]);
    }
    Ok(vec![TargetHost::Hostname(spec.to_string())])
}

pub fn resolve_targets_from_list(specs: &[String]) -> Result<Vec<TargetHost>> {
    let mut targets = Vec::new();
    for spec in specs {
        targets.extend(resolve_single_target(spec)?);
    }
    Ok(targets)
}

pub fn resolve_targets_from_file(path: &str) -> Result<Vec<TargetHost>> {
    let reader: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path)?))
    };

    let mut targets = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        targets.extend(resolve_single_target(trimmed)?);
    }
    Ok(targets)
}

pub async fn resolve_targets(config: &DiscoveryConfig) -> Result<Vec<TargetHost>> {
    let mut targets = Vec::new();
    if let Some(ref specs) = config.targets {
        targets.extend(resolve_targets_from_list(specs)?);
    }
    if let Some(ref file_path) = config.target_file {
        let path = file_path.clone();
        let file_targets = tokio::task::spawn_blocking(move || resolve_targets_from_file(&path))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;
        targets.extend(file_targets);
    }

    // Deduplicate while preserving insertion order
    let mut seen = HashSet::with_capacity(targets.len());
    targets.retain(|t| seen.insert(t.clone()));

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_cidr_24_expands() {
        let result = resolve_single_target("10.0.0.0/24").unwrap();
        assert_eq!(result.len(), 254);
        assert!(result.iter().all(|t| matches!(t, TargetHost::Ip(_))));
    }

    #[test]
    fn parse_cidr_32_single_host() {
        let result = resolve_single_target("10.0.0.1/32").unwrap();
        assert_eq!(result.len(), 1, "/32 must produce exactly one host");
        assert_eq!(result[0], TargetHost::Ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_cidr_128_ipv6_single_host() {
        let result = resolve_single_target("::1/128").unwrap();
        assert_eq!(result.len(), 1, "/128 must produce exactly one host");
        assert_eq!(result[0], TargetHost::Ip("::1".parse().unwrap()));
    }

    #[test]
    fn parse_cidr_30_small_range() {
        let result = resolve_single_target("192.168.1.0/30").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], TargetHost::Ip("192.168.1.1".parse().unwrap()));
        assert_eq!(result[1], TargetHost::Ip("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_address() {
        let result = resolve_single_target("::1").unwrap();
        assert_eq!(result, vec![TargetHost::Ip("::1".parse().unwrap())]);
    }

    #[test]
    fn parse_hostname_passthrough() {
        let result = resolve_single_target("nfs-server.internal").unwrap();
        assert_eq!(
            result,
            vec![TargetHost::Hostname("nfs-server.internal".into())]
        );
    }

    #[test]
    fn parse_fqdn_passthrough() {
        let result = resolve_single_target("prod-nfs.corp.example.com").unwrap();
        assert_eq!(
            result,
            vec![TargetHost::Hostname("prod-nfs.corp.example.com".into())]
        );
    }

    #[test]
    fn resolve_list_mixed_targets() {
        let specs: Vec<String> = vec![
            "10.0.0.1".into(),
            "nfs-server".into(),
            "192.168.0.0/30".into(),
        ];
        let result = resolve_targets_from_list(&specs).unwrap();
        // 1 IP + 1 hostname + 2 CIDR hosts = 4
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn file_skips_comments() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "# comment").unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        writeln!(tmp, "# another").unwrap();
        writeln!(tmp, "10.0.0.2").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn file_skips_empty_lines() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp).unwrap();
        writeln!(tmp, "10.0.0.2").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn file_trims_whitespace() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "  10.0.0.1  ").unwrap();
        writeln!(tmp, "  nfs-server  ").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], TargetHost::Ip("10.0.0.1".parse().unwrap()));
        assert_eq!(result[1], TargetHost::Hostname("nfs-server".into()));
    }

    #[tokio::test]
    async fn resolve_targets_deduplicates_identical_ips() {
        let config = DiscoveryConfig {
            targets: Some(vec!["10.0.0.1".into(), "10.0.0.1".into()]),
            target_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        };
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result.len(), 1, "duplicate IPs should be deduplicated");
    }

    #[tokio::test]
    async fn resolve_targets_deduplicates_identical_hostnames() {
        let config = DiscoveryConfig {
            targets: Some(vec!["nfs-server".into(), "nfs-server".into()]),
            target_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        };
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(
            result.len(),
            1,
            "duplicate hostnames should be deduplicated"
        );
    }

    #[tokio::test]
    async fn resolve_targets_preserves_order_after_dedup() {
        let config = DiscoveryConfig {
            targets: Some(vec![
                "10.0.0.2".into(),
                "10.0.0.1".into(),
                "10.0.0.2".into(),
            ]),
            target_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 10,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        };
        let result = resolve_targets(&config).await.unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], TargetHost::Ip("10.0.0.2".parse().unwrap()));
        assert_eq!(result[1], TargetHost::Ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn file_mixed_content() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "10.0.0.1").unwrap();
        writeln!(tmp, "nfs-server").unwrap();
        writeln!(tmp, "192.168.1.0/30").unwrap();
        writeln!(tmp, "# skip this").unwrap();
        writeln!(tmp, "::1").unwrap();
        tmp.flush().unwrap();

        let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
        // 1 IPv4 + 1 hostname + 2 CIDR hosts + 1 IPv6 = 5
        assert_eq!(result.len(), 5);
    }
}

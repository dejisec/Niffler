pub async fn discover_v4_exports(host: &str) -> anyhow::Result<Vec<crate::nfs::types::NfsExport>> {
    use crate::nfs::auth::AuthCreds;
    use crate::nfs::connector::NfsConnector;
    use crate::nfs::types::NfsExport;
    use crate::nfs::v4::Nfs4Connector;

    let connector = Nfs4Connector::new();

    // Connect to pseudo-root with nobody credentials (least privilege)
    let mut ops = match connector.connect(host, "/", &AuthCreds::nobody()).await {
        Ok(ops) => ops,
        Err(e) => {
            tracing::debug!("NFSv4 pseudo-root connect failed for {}: {}", host, e);
            return Ok(vec![]);
        }
    };

    let root_fh = ops.root_handle().clone();
    let entries = match ops.readdirplus(&root_fh).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!("NFSv4 pseudo-root readdirplus failed for {}: {}", host, e);
            return Ok(vec![]);
        }
    };

    let exports = entries
        .into_iter()
        .filter(|e| e.attrs.is_directory())
        .map(|e| NfsExport {
            path: format!("/{}", e.name),
            allowed_hosts: vec![],
        })
        .collect();

    Ok(exports)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST"]
    async fn nfs4_pseudo_root_discovers_exports() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let exports = super::discover_v4_exports(&host)
            .await
            .expect("discover failed");
        assert!(!exports.is_empty(), "expected at least one export");
        for export in &exports {
            println!("discovered export: {}", export.path);
        }
    }
}

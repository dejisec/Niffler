use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use indicatif::MultiProgress;

use niffler::config::NifflerConfig;
use niffler::config::cli::{Cli, NifflerCommand, ScanArgs, Verbosity};
use niffler::config::settings::ExportFormat;
use niffler::nfs::{Nfs3Connector, NfsConnector};
use niffler::output::export::{export_csv, export_json, export_tsv};
use niffler::pipeline::{IndicatifWriter, StatsFormatter, run_pipeline};
use niffler::web::db::{Database, FindingsQuery};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let verbosity = cli.verbosity;

    match cli.command {
        NifflerCommand::Scan(args) => run_scan(*args, verbosity).await,
        NifflerCommand::Serve { db, port, bind } => {
            niffler::web::server::start_server(&db, port, &bind).await
        }
        NifflerCommand::Export {
            db,
            format,
            min_severity,
            host,
            rule,
            scan_id,
        } => {
            if !db.exists() {
                anyhow::bail!("database file not found: {}", db.display());
            }
            let database = Database::open(&db).await?;
            let query = FindingsQuery {
                scan_id,
                host,
                rule,
                min_triage: min_severity.map(|t| t.to_string()),
                per_page: u64::MAX,
                ..Default::default()
            };
            let findings = database.list_findings(&query).await?;
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            match format {
                ExportFormat::Json => export_json(&findings, &mut writer)?,
                ExportFormat::Csv => export_csv(&findings, &mut writer)?,
                ExportFormat::Tsv => export_tsv(&findings, &mut writer)?,
            }
            Ok(())
        }
    }
}

async fn run_scan(args: ScanArgs, verbosity: Verbosity) -> Result<()> {
    let level = match verbosity {
        Verbosity::Trace => tracing::Level::TRACE,
        Verbosity::Debug => tracing::Level::DEBUG,
        Verbosity::Info => tracing::Level::INFO,
        Verbosity::Warn => tracing::Level::WARN,
        Verbosity::Error => tracing::Level::ERROR,
    };

    let mut config = NifflerConfig::from_scan_args(args)?;

    if config.generate_config {
        let toml = toml::to_string_pretty(&config)?;
        println!("{toml}");
        return Ok(());
    }

    // Progress bars always enabled — SQLite is file-backed, progress uses stderr.
    // When --live, findings go to stdout while progress stays on stderr.
    let multi = MultiProgress::new();

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(IndicatifWriter::new(multi.clone()))
        .init();

    let multi = Some(multi);

    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(String::new, |l| {
            format!(" at {}:{}:{}", l.file(), l.line(), l.column())
        });
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown".to_string()
        };
        tracing::warn!("task panic{}: {}", location, payload);
    }));

    if config.discovery.proxy.is_some() && config.discovery.privileged_port {
        tracing::warn!("--privileged-port is incompatible with --proxy, ignoring privileged port");
        config.discovery.privileged_port = false;
    }

    let connector: Arc<dyn NfsConnector> = if config.discovery.nfs_version == Some(4) {
        Arc::new(niffler::nfs::Nfs4Connector::new())
    } else {
        match config.discovery.proxy {
            Some(proxy) => Arc::new(Nfs3Connector::with_proxy(proxy)),
            None => Arc::new(Nfs3Connector::new(config.discovery.privileged_port)),
        }
    };

    let min_severity = config.output.min_severity;
    let stats = run_pipeline(config, connector, None, multi).await?;

    eprintln!(
        "\n{}",
        StatsFormatter {
            stats: &stats,
            min_severity
        }
    );

    Ok(())
}

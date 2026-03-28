use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use indicatif::MultiProgress;

use niffler::config::cli::{Cli, Verbosity};
use niffler::config::{NifflerConfig, OutputFormat};
use niffler::nfs::{Nfs3Connector, NfsConnector};
use niffler::pipeline::{IndicatifWriter, run_pipeline};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbosity {
        Verbosity::Trace => tracing::Level::TRACE,
        Verbosity::Debug => tracing::Level::DEBUG,
        Verbosity::Info => tracing::Level::INFO,
        Verbosity::Warn => tracing::Level::WARN,
        Verbosity::Error => tracing::Level::ERROR,
    };

    let config = NifflerConfig::from_cli(cli)?;

    if config.generate_config {
        let toml = toml::to_string_pretty(&config)?;
        println!("{toml}");
        return Ok(());
    }

    let progress_enabled =
        config.output.output_file.is_none() && config.output.format == OutputFormat::Console;
    let multi = if progress_enabled {
        Some(MultiProgress::new())
    } else {
        None
    };

    if let Some(ref m) = multi {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .with_writer(IndicatifWriter::new(m.clone()))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .init();
    }

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
    }

    let connector: Arc<dyn NfsConnector> = if config.discovery.nfs_version == Some(4) {
        Arc::new(niffler::nfs::Nfs4Connector::new())
    } else {
        match config.discovery.proxy {
            Some(proxy) => Arc::new(Nfs3Connector::with_proxy(proxy)),
            None => Arc::new(Nfs3Connector::new(config.discovery.privileged_port)),
        }
    };

    let stats = run_pipeline(config, connector, None, multi).await?;

    eprintln!("\n{stats}");

    Ok(())
}

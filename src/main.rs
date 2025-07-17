use anyhow::Result;
use clap::Parser as _;
use log::info;
use std::{sync::Arc, time::Duration};
use timedmap::{TimedMap, start_cleaner};
use tokio::signal;

mod handler;

mod args;
mod server;
use args::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::init();

    let socket = tokio::net::UdpSocket::bind(args.listen).await?;
    let socket = Arc::new(socket);

    let args = Arc::new(args);

    let dns_cache = Arc::new(TimedMap::new());

    let _ = start_cleaner(dns_cache.clone(), Duration::from_secs(1));

    tokio::spawn(async move {
        server::start_server(socket, args, dns_cache).await;
    });

    match signal::ctrl_c().await {
        Ok(()) => {}
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {err}");
        }
    }

    Ok(())
}

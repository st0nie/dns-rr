use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Domains
    #[arg(short, long)]
    pub suffix: String,

    /// Http API Host
    #[arg(short, long)]
    pub api: String,

    /// LoadBalancer ID
    #[arg(short, long)]
    pub balancer: String,

    /// listen address
    #[arg(short, long, default_value = "0.0.0.0:53")]
    pub listen: SocketAddr,
}
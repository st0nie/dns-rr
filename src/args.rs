use std::net::{Ipv4Addr, SocketAddr};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Domains
    #[arg(short, long)]
    pub suffix: String,

    /// Ips
    #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ' ')]
    pub address: Vec<Ipv4Addr>,

    /// listen address
    #[arg(short, long, default_value = "0.0.0.0:53")]
    pub listen: SocketAddr,
}
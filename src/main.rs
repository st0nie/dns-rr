use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use anyhow::Result;
use lazy_static::lazy_static;
use log::{error, info};
use simple_dns::{rdata::RData, *};
use timedmap::{TimedMap, start_cleaner};
use tokio::signal;

use clap::Parser;

lazy_static! {
    static ref RR_COUNTER: AtomicUsize = AtomicUsize::new(0);
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Domains
    #[arg(short, long)]
    suffix: String,

    /// Ips
    #[arg(short, long)]
    address: Vec<Ipv4Addr>,

    /// listen address
    #[arg(short, long, default_value = "0.0.0.0:53")]
    listen: SocketAddr,
}

async fn query_handler(
    socket: Arc<tokio::net::UdpSocket>,
    buf: &[u8],
    size: usize,
    addr: std::net::SocketAddr,
    args: Arc<Args>,
    dns_cache: Arc<TimedMap<String, Vec<Ipv4Addr>>>,
) -> Result<()> {
    info!("Received {} bytes", size);
    let request = &buf[..size];
    let packet =
        Packet::parse(request).inspect_err(|e| error!("Failed to parse DNS packet: {}", e))?;

    let id = packet.id();

    let suffix = &args.suffix;
    let address = &args.address;

    let mut reply = Packet::new_reply(id);
    reply.questions.extend(packet.questions.iter().cloned());
    if packet.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

    if packet.opcode() != OPCODE::StandardQuery {
        socket.send_to(&reply.build_bytes_vec()?, addr).await?;
        return Ok(());
    }
    for question in packet.questions {
        let qname = question.qname;
        let qname_string = qname.to_string();
        let qtype = question.qtype;

        let mut should_fallback = true;

        if qtype != QTYPE::TYPE(TYPE::A) {
            continue;
        }

        if qname_string.ends_with(suffix) {
            should_fallback = false;
            let rr_count = RR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let ip = address[rr_count % address.len()];
            reply.answers.push(ResourceRecord::new(
                qname.clone(),
                CLASS::IN,
                0,
                RData::A(ip.into()),
            ));
        }

        const TTL: u32 = 300;

        if should_fallback == false {
            continue;
        }

        // 有缓存就用缓存
        if let Some(cached_addrs) = dns_cache.get_value(&qname_string) {
            let expire = cached_addrs.expires();
            let now = std::time::Instant::now();
            let remaining = expire.saturating_duration_since(now);

            for ip in cached_addrs.value() {
                reply.answers.push(ResourceRecord::new(
                    qname.clone(),
                    CLASS::IN,
                    remaining.as_secs() as u32,
                    RData::A(ip.into()),
                ));
            }
            continue;
        }

        // 没有缓存就问上游
        match tokio::net::lookup_host(format!("{}:0", qname_string)).await {
            Ok(addrs) => {
                let v4_addrs = addrs
                    .filter_map(|addr| -> Option<Ipv4Addr> {
                        if let SocketAddr::V4(addr_v4) = addr {
                            reply.answers.push(ResourceRecord::new(
                                qname.clone(),
                                CLASS::IN,
                                TTL,
                                RData::A((*addr_v4.ip()).into()),
                            ));
                            Some(*addr_v4.ip())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                dns_cache.insert(qname_string, v4_addrs, Duration::from_secs(TTL as u64));
            }
            // 如果上游也无法解析域名，记录缓存
            Err(e) => {
                // 11001 Host not found
                if e.raw_os_error() == Some(11001) {
                    dns_cache.insert(qname_string, Vec::new(), Duration::from_secs(TTL as u64));
                }
            }
        };
    }
    socket.send_to(&reply.build_bytes_vec()?, addr).await?;

    Ok(())
}

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
        let mut buf = [0; 1024];
        loop {
            let socket = Arc::clone(&socket);
            match socket.recv_from(buf.as_mut()).await {
                Ok((size, addr)) => {
                    let args = Arc::clone(&args);
                    let dns_cache = Arc::clone(&dns_cache);
                    tokio::spawn(async move {
                        let args = Arc::clone(&args);
                        query_handler(socket, &buf, size, addr, args, dns_cache)
                            .await
                            .inspect_err(|e| error!("Error handling query: {}", e))
                    });
                }
                Err(e) => {
                    error!("Failed to receive data: {}", e);
                    continue;
                }
            }
        }
    });

    match signal::ctrl_c().await {
        Ok(()) => {}
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        }
    }

    Ok(())
}

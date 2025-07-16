use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use anyhow::Result;
use lazy_static::lazy_static;
use log::{error, info};
use simple_dns::{CLASS, OPCODE, Packet, PacketFlag, QTYPE, ResourceRecord, TYPE, rdata::RData};
use timedmap::TimedMap;

use crate::Args;

lazy_static! {
    static ref RR_COUNTER: AtomicUsize = AtomicUsize::new(0);
}

async fn generate_reply<'a>(
    packet: &Packet<'a>,
    address: &Vec<Ipv4Addr>,
    suffix: &String,
    dns_cache: Arc<TimedMap<String, Vec<Ipv4Addr>>>,
) -> Result<Packet<'a>> {
    let id = packet.id();
    let mut reply = Packet::new_reply(id);
    reply.questions.extend(packet.questions.iter().cloned());
    if packet.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);

    if packet.opcode() != OPCODE::StandardQuery {
        return Ok(reply);
    }

    for question in &packet.questions {
        let qname = &question.qname;
        let qname_string = qname.to_string();
        let qtype = question.qtype;

        let mut should_fallback = true;

        if qtype != QTYPE::TYPE(TYPE::A) {
            continue;
        }

        if qname_string.ends_with(suffix) && !address.is_empty() {
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

        if !should_fallback {
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
        match tokio::net::lookup_host(format!("{qname_string}:0")).await {
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
            Err(_) => {
                dns_cache.insert(qname_string, Vec::new(), Duration::from_secs(1));
            }
        };
    }

    Ok(reply)
}

pub async fn query_handler(
    socket: Arc<tokio::net::UdpSocket>,
    buf: &[u8],
    size: usize,
    addr: std::net::SocketAddr,
    args: Arc<Args>,
    dns_cache: Arc<TimedMap<String, Vec<Ipv4Addr>>>,
) -> Result<()> {
    info!("Received {size} bytes");
    let request = &buf[..size];
    let packet =
        Packet::parse(request).inspect_err(|e| error!("Failed to parse DNS packet: {e}"))?;

    let reply = generate_reply(&packet, &args.address, &args.suffix, dns_cache)
        .await
        .unwrap_or(Packet::new_reply(packet.id()));

    socket.send_to(&reply.build_bytes_vec()?, addr).await?;

    Ok(())
}

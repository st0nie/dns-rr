use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use log::{error, info, warn};
use simple_dns::{CLASS, OPCODE, Packet, PacketFlag, QTYPE, ResourceRecord, TYPE, rdata::RData};
use std::sync::LazyLock;
use timedmap::TimedMap;

use crate::Args;
mod requests;
use requests::{LoadBalancerInfo, NextNodeRequest};

static API_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

async fn generate_reply<'a>(
    packet: &Packet<'a>,
    suffix: &str,
    lb_id: &str,
    dns_cache: Arc<TimedMap<String, Vec<Ipv4Addr>>>,
    api_host: &str,
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

        if qname_string.ends_with(suffix) {
            should_fallback = false;

            let request_body = NextNodeRequest::new(lb_id);

            let api_response = API_CLIENT
                .post(api_host)
                .json(&request_body)
                .send()
                .await
                .inspect_err(|e| error!("Unable to get response from API: {e}"))?
                .json::<LoadBalancerInfo>()
                .await
                .inspect_err(|e| error!("Unable to parse response: {e}"))?;

            let ip = api_response.ip;

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
            info!("Cache hit for {qname_string}");
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

        info!("Fallback to upstream for {qname_string}");
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
                warn!("No upstream DNS found for {qname_string}");
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
    info!("Received query from {addr}");
    let request = &buf[..size];
    let packet =
        Packet::parse(request).inspect_err(|e| error!("Failed to parse DNS packet: {e}"))?;

    let reply = generate_reply(&packet, &args.suffix, &args.balancer, dns_cache, &args.api)
        .await
        .inspect_err(|e| warn!("Failed to generate reply, use empty reply: {e}"))
        .unwrap_or(Packet::new_reply(packet.id()));

    info!("Sending reply to {addr}");
    socket.send_to(&reply.build_bytes_vec()?, addr).await?;

    Ok(())
}

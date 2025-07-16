use std::{net::Ipv4Addr, sync::Arc};

use log::error;
use timedmap::TimedMap;

use crate::{Args, handler::query_handler};

pub async fn start_server(
    socket: Arc<tokio::net::UdpSocket>,
    args: Arc<Args>,
    dns_cache: Arc<TimedMap<String, Vec<Ipv4Addr>>>,
) {
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
                        .inspect_err(|e| error!("Error handling query: {e}"))
                });
            }
            Err(e) => {
                error!("Failed to receive data: {e}");
                continue;
            }
        }
    }
}

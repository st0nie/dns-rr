use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct NextNodeRequest<'a> {
    load_balancer_id: &'a str,
}

impl<'a> NextNodeRequest<'a> {
    pub fn new(load_balancer_id: &'a str) -> Self {
        Self { load_balancer_id }
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct LoadBalancerInfo {
    load_balancer_id: String,
    pub ip: Ipv4Addr,
    port: u16,
    weight: f64,
}
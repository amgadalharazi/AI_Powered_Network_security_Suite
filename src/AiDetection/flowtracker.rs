use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // 6=TCP, 17=UDP, 1=ICMP
}

// Clone is required because we push (key.clone(), stats) into the expired Vec
// while iterating flows with retain().
#[derive(Clone)]
pub struct FlowStats {
    #[allow(dead_code)]
    pub start_time: Instant,
    pub last_seen: Instant,
    // Packet counts
    pub fwd_pkts: u64,
    pub bwd_pkts: u64,
    // Byte counts
    pub fwd_bytes: u64,
    pub bwd_bytes: u64,
    // Packet lengths (for mean/std)
    fwd_pkt_lens: Vec<u64>,
    bwd_pkt_lens: Vec<u64>,
    // IAT (inter-arrival times) in microseconds
    fwd_iat: Vec<u64>,
    bwd_iat: Vec<u64>,
    last_fwd_time: Option<Instant>,
    last_bwd_time: Option<Instant>,
}

impl FlowStats {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            last_seen: now,
            fwd_pkts: 0,
            bwd_pkts: 0,
            fwd_bytes: 0,
            bwd_bytes: 0,
            fwd_pkt_lens: Vec::new(),
            bwd_pkt_lens: Vec::new(),
            fwd_iat: Vec::new(),
            bwd_iat: Vec::new(),
            last_fwd_time: None,
            last_bwd_time: None,
        }
    }

    pub fn update(&mut self, is_forward: bool, packet_len: usize) {
        let now = Instant::now();
        self.last_seen = now;

        if is_forward {
            self.fwd_pkts += 1;
            self.fwd_bytes += packet_len as u64;
            self.fwd_pkt_lens.push(packet_len as u64);
            if let Some(prev) = self.last_fwd_time {
                let iat = (now - prev).as_micros() as u64;
                self.fwd_iat.push(iat);
            }
            self.last_fwd_time = Some(now);
        } else {
            self.bwd_pkts += 1;
            self.bwd_bytes += packet_len as u64;
            self.bwd_pkt_lens.push(packet_len as u64);
            if let Some(prev) = self.last_bwd_time {
                let iat = (now - prev).as_micros() as u64;
                self.bwd_iat.push(iat);
            }
            self.last_bwd_time = Some(now);
        }
    }

    /// Compute a feature vector of exactly 78 floats (zeros for unimplemented features).
    pub fn to_feature_vector(&self) -> Vec<f32> {
        let mut f = Vec::with_capacity(78);

        // 1-4: basic counts & bytes
        f.push(self.fwd_pkts as f32);
        f.push(self.bwd_pkts as f32);
        f.push(self.fwd_bytes as f32);
        f.push(self.bwd_bytes as f32);

        // 5-6: mean packet lengths
        let fwd_mean_len = if self.fwd_pkts > 0 {
            self.fwd_bytes as f64 / self.fwd_pkts as f64
        } else {
            0.0
        };
        let bwd_mean_len = if self.bwd_pkts > 0 {
            self.bwd_bytes as f64 / self.bwd_pkts as f64
        } else {
            0.0
        };
        f.push(fwd_mean_len as f32);
        f.push(bwd_mean_len as f32);

        // 7-10: min/max packet lengths
        let fwd_min = self.fwd_pkt_lens.iter().min().copied().unwrap_or(0) as f32;
        let fwd_max = self.fwd_pkt_lens.iter().max().copied().unwrap_or(0) as f32;
        let bwd_min = self.bwd_pkt_lens.iter().min().copied().unwrap_or(0) as f32;
        let bwd_max = self.bwd_pkt_lens.iter().max().copied().unwrap_or(0) as f32;
        f.push(fwd_min);
        f.push(fwd_max);
        f.push(bwd_min);
        f.push(bwd_max);

        // 11-12: forward IAT mean/std
        let fwd_iat_mean = if !self.fwd_iat.is_empty() {
            self.fwd_iat.iter().sum::<u64>() as f64 / self.fwd_iat.len() as f64
        } else {
            0.0
        };
        let fwd_iat_std = if self.fwd_iat.len() > 1 {
            let variance = self
                .fwd_iat
                .iter()
                .map(|&x| (x as f64 - fwd_iat_mean).powi(2))
                .sum::<f64>()
                / (self.fwd_iat.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };
        f.push(fwd_iat_mean as f32);
        f.push(fwd_iat_std as f32);

        // 13-14: backward IAT mean/std
        let bwd_iat_mean = if !self.bwd_iat.is_empty() {
            self.bwd_iat.iter().sum::<u64>() as f64 / self.bwd_iat.len() as f64
        } else {
            0.0
        };
        let bwd_iat_std = if self.bwd_iat.len() > 1 {
            let variance = self
                .bwd_iat
                .iter()
                .map(|&x| (x as f64 - bwd_iat_mean).powi(2))
                .sum::<f64>()
                / (self.bwd_iat.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };
        f.push(bwd_iat_mean as f32);
        f.push(bwd_iat_std as f32);

        // Pad remaining features with 0.0 to reach exactly 78
        while f.len() < 78 {
            f.push(0.0);
        }
        f.truncate(78);
        f
    }
}

pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowStats>,
    idle_timeout: Duration,
}

impl FlowTracker {
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            flows: HashMap::new(),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
        }
    }

    /// Process a packet, update flow stats, and return any flows that expired.
    pub fn process_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        packet_len: usize,
    ) -> Vec<(FlowKey, FlowStats)> {
        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        // We treat the initial direction as forward; bidirectional tracking
        // would require checking whether the reverse key already exists.
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.update(true, packet_len);
        } else {
            let mut new_flow = FlowStats::new();
            new_flow.update(true, packet_len);
            self.flows.insert(key.clone(), new_flow);
        }

        // Collect and remove idle flows
        let now = Instant::now();
        let mut expired = Vec::new();
        self.flows.retain(|k, v| {
            if v.last_seen + self.idle_timeout < now {
                expired.push((k.clone(), v.clone()));
                false
            } else {
                true
            }
        });
        expired
    }
}

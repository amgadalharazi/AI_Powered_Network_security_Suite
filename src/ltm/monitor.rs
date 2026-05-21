// src/ltm/monitor.rs
use std::collections::HashMap;
use std::time::Instant;

pub struct LiveTrafficMonitor {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub protocol_stats: HashMap<String, u64>,
    pub start_time: Instant,
}

impl LiveTrafficMonitor {
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            protocol_stats: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    pub fn update(&mut self, protocol: &str, packet_size: usize) {
        self.total_packets += 1;
        self.total_bytes += packet_size as u64;
        *self.protocol_stats.entry(protocol.to_string()).or_insert(0) += 1;
    }

    /// Packets per second since monitor started
    pub fn packet_rate(&self) -> f64 {
        let secs = self.start_time.elapsed().as_secs_f64();
        if secs > 0.0 {
            self.total_packets as f64 / secs
        } else {
            0.0
        }
    }

    /// Bandwidth in Megabits per second
    pub fn bandwidth_mbps(&self) -> f64 {
        let secs = self.start_time.elapsed().as_secs_f64();
        if secs > 0.0 {
            (self.total_bytes as f64 * 8.0) / (1_000_000.0 * secs)
        } else {
            0.0
        }
    }
}

// Oii the Visuals in the following directory "sniffing/visualization.rs"
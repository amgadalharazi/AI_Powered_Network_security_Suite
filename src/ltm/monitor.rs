// monitor.rs — Live traffic monitor with optional TUI rendering.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::visualizer::Visualizer;

pub struct LiveTrafficMonitor {
    total_packets: u64,
    total_bytes: u64,
    protocol_stats: HashMap<String, u64>,
    start_time: Instant,
    last_render: Instant,
    visualizer: Visualizer,
    enable_visuals: bool,
}

impl LiveTrafficMonitor {
    /// Create a new monitor. Pass `enable_visuals: false` for headless use.
    pub fn new(enable_visuals: bool) -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            protocol_stats: HashMap::new(),
            start_time: Instant::now(),
            last_render: Instant::now(),
            visualizer: Visualizer::new(),
            enable_visuals,
        }
    }

    /// Record a packet's protocol and size without triggering a render.
    pub fn update(&mut self, protocol: &str, packet_size: usize) {
        self.total_packets += 1;
        self.total_bytes += packet_size as u64;
        *self.protocol_stats.entry(protocol.to_string()).or_insert(0) += 1;
    }

    /// Record a packet and render if at least 1 second has passed.
    /// Returns `true` if a render happened.
    pub fn update_and_render(
        &mut self,
        protocol: &str,
        packet_size: usize,
        http_host: Option<String>,
    ) -> bool {
        self.update(protocol, packet_size);
        self.maybe_render_with_host(http_host)
    }

    /// Render if 1 second has passed (no packet needed — useful for idle ticks).
    pub fn maybe_render(&mut self) -> bool {
        self.maybe_render_with_host(None)
    }

    /// Force a final render on exit so the user sees up-to-date stats.
    pub fn final_render(&mut self) {
        if !self.enable_visuals {
            return;
        }
        self.visualizer.render(
            &self.protocol_stats,
            self.total_packets,
            self.start_time.elapsed(),
            self.bandwidth_mbps(),
            self.packet_rate(),
            None,
        );
    }

    /// Seconds elapsed since the monitor started.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Average packets per second since start.
    pub fn packet_rate(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 {
            self.total_packets as f64 / secs
        } else {
            0.0
        }
    }

    /// Average bandwidth in Mbit/s since start.
    pub fn bandwidth_mbps(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 {
            (self.total_bytes as f64 * 8.0) / (1_000_000.0 * secs)
        } else {
            0.0
        }
    }

    // Public getters — not used internally but kept for external callers
    // (e.g. tests or a future summary report). #[allow(dead_code)] silences
    // the compiler warning without removing the API.

    #[allow(dead_code)]
    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    #[allow(dead_code)]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[allow(dead_code)]
    pub fn protocol_stats(&self) -> &HashMap<String, u64> {
        &self.protocol_stats
    }

    /// Only render when visuals are on and the 1 Hz rate limit has elapsed.
    fn maybe_render_with_host(&mut self, http_host: Option<String>) -> bool {
        if !self.enable_visuals {
            return false;
        }
        if self.last_render.elapsed() < Duration::from_secs(1) {
            return false;
        }

        self.visualizer.render(
            &self.protocol_stats,
            self.total_packets,
            self.start_time.elapsed(),
            self.bandwidth_mbps(),
            self.packet_rate(),
            http_host,
        );

        self.last_render = Instant::now();
        true
    }
}

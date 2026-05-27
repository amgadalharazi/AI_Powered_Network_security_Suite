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
    /// Create a new monitor. If `enable_visuals` is true, it will automatically
    /// render the dashboard at 1 Hz when `update_and_render()` or `maybe_render()` is called.
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

    /// Update statistics with a new packet (no rendering).
    pub fn update(&mut self, protocol: &str, packet_size: usize) {
        self.total_packets += 1;
        self.total_bytes += packet_size as u64;
        *self.protocol_stats.entry(protocol.to_string()).or_insert(0) += 1;
    }

    /// Update stats and automatically render if visuals are enabled and at least 1 second has passed.
    /// Returns `true` if a render actually happened.
    pub fn update_and_render(&mut self, protocol: &str, packet_size: usize, http_host: Option<String>) -> bool {
        self.update(protocol, packet_size);
        self.maybe_render_with_host(http_host)
    }

    /// Render if enough time has passed (no new packet needed). Uses `None` for HTTP host.
    pub fn maybe_render(&mut self) -> bool {
        self.maybe_render_with_host(None)
    }

    /// Internal: render with optional HTTP host if time elapsed.
    fn maybe_render_with_host(&mut self, http_host: Option<String>) -> bool {
        if self.enable_visuals && self.last_render.elapsed() >= Duration::from_secs(1) {
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
        } else {
            false
        }
    }

    /// Force a final render (e.g., on exit).
    pub fn final_render(&mut self) {
        if self.enable_visuals {
            self.visualizer.render(
                &self.protocol_stats,
                self.total_packets,
                self.start_time.elapsed(),
                self.bandwidth_mbps(),
                self.packet_rate(),
                None,
            );
        }
    }

    /// Time elapsed since monitor started.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Packets per second.
    pub fn packet_rate(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 {
            self.total_packets as f64 / secs
        } else {
            0.0
        }
    }

    /// Bandwidth in Megabits per second.
    pub fn bandwidth_mbps(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 {
            (self.total_bytes as f64 * 8.0) / (1_000_000.0 * secs)
        } else {
            0.0
        }
    }

    // Getters for stats (if needed by external modules)
    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn protocol_stats(&self) -> &HashMap<String, u64> {
        &self.protocol_stats
    }
}
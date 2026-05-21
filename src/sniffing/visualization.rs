// src/sniffing/visualization.rs
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;

const RESET: &str = "\x1B[0m";
const BOLD:  &str = "\x1B[1m";
const DIM:   &str = "\x1B[2m";

const C_TCP:  &str = "\x1B[38;5;39m";
const C_UDP:  &str = "\x1B[38;5;135m";
const C_ICMP: &str = "\x1B[38;5;214m";
const C_ARP:  &str = "\x1B[38;5;42m";
const C_IPV6: &str = "\x1B[38;5;205m";
const C_OTH:  &str = "\x1B[38;5;243m";
const C_GRN:  &str = "\x1B[38;5;42m";
const C_RED:  &str = "\x1B[38;5;196m";

const PROTOCOLS: &[(&str, &str)] = &[
    ("TCP",      C_TCP),
    ("UDP",      C_UDP),
    ("ICMP",     C_ICMP),
    ("ARP",      C_ARP),
    ("IPv6",     C_IPV6),
    ("IP/Other", C_OTH),
    ("Unknown",  C_OTH),
];

const BAR_WIDTH: usize = 28;

pub struct Visualizer {
    http_hosts:      Vec<String>,
    last_line_count: Option<usize>,
}

impl Visualizer {
    pub fn new() -> Self {
        Visualizer {
            http_hosts:      Vec::new(),
            last_line_count: None,
        }
    }

    /// Renders the live dashboard including bandwidth and packet rate (from LTM)
    pub fn render(
        &mut self,
        stats:          &HashMap<String, u64>,
        total:          u64,
        elapsed:        Duration,
        bandwidth_mbps: f64,
        packet_rate:    f64,
        http_host:      Option<String>,
    ) {
        if let Some(host) = http_host {
            if !self.http_hosts.contains(&host) {
                self.http_hosts.push(host);
            }
        }

        let secs = elapsed.as_secs_f64().max(0.1);
        let arp = stats.get("ARP").copied().unwrap_or(0);
        let arp_pct = if total > 0 { arp as f64 / total as f64 * 100.0 } else { 0.0 };
        let arp_warn = arp_pct > 15.0 && arp > 10;

        let mut lines = Vec::new();

        // Header
        lines.push(format!("{BOLD}╔══════════════════════════════════════════════════╗{RESET}"));
        lines.push(format!("{BOLD}║{RESET}         Network Traffic Monitor v1.0             {BOLD}║{RESET}"));
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════╣{RESET}"));

        // Live metrics: time, total packets, bandwidth, packet rate
        lines.push(format!(
            "{BOLD}║{RESET} Time:{BOLD}{:>7.1}s{RESET}  Pkts:{BOLD}{:>7}{RESET}  BW:{BOLD}{:>6.1} Mbps{RESET}  {BOLD}║{RESET}",
            secs, total, bandwidth_mbps
        ));
        lines.push(format!(
            "{BOLD}║{RESET} Rate:{BOLD}{:>6.1} pkt/s{RESET}                                   {BOLD}║{RESET}",
            packet_rate
        ));

        // Protocol distribution bars
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════╣{RESET}"));
        lines.push(format!("{BOLD}║{RESET}  Protocol Distribution:                          {BOLD}║{RESET}"));

        for (proto, color) in PROTOCOLS {
            let count = stats.get(*proto).copied().unwrap_or(0);
            let pct = if total > 0 { count as f64 / total as f64 * 100.0 } else { 0.0 };
            let filled = (pct / 100.0 * BAR_WIDTH as f64) as usize;
            let empty = BAR_WIDTH - filled;

            lines.push(format!(
                "{BOLD}║{RESET} {color}{BOLD}{proto:<8}{RESET} {color}{}{RESET}{DIM}{}{RESET} {count:>5} {DIM}{pct:>5.1}%{RESET} {BOLD}║{RESET}",
                "█".repeat(filled),
                "░".repeat(empty),
            ));
        }

        // HTTP hosts (fixed 5 rows)
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════╣{RESET}"));
        lines.push(format!("{BOLD}║{RESET}  HTTP Hosts Detected:                            {BOLD}║{RESET}"));
        for i in 0..5 {
            if let Some(host) = self.http_hosts.iter().rev().nth(i) {
                let truncated = if host.len() > 44 {
                    format!("{}...", &host[..41])
                } else {
                    host.clone()
                };
                lines.push(format!("{BOLD}║{RESET}  {C_GRN}•{RESET} {truncated:<44}  {BOLD}║{RESET}"));
            } else {
                lines.push(format!("{BOLD}║{RESET}    {:<46}  {BOLD}║{RESET}", ""));
            }
        }

        // ARP warning
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════╣{RESET}"));
        if arp_warn {
            lines.push(format!("{BOLD}║{RESET}  {C_RED}{BOLD}⚠  ARP anomaly — possible spoofing!{RESET}             {BOLD}║{RESET}"));
        } else {
            lines.push(format!("{BOLD}║{RESET}    {:<46}  {BOLD}║{RESET}", ""));
        }

        lines.push(format!("{BOLD}╚══════════════════════════════════════════════════╝{RESET}"));
        lines.push(format!("{DIM}Press Ctrl+C to stop...{RESET}"));

        // Overwrite previous render
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        if let Some(prev) = self.last_line_count {
            write!(out, "\x1B[{}A", prev).unwrap();
        }
        for line in &lines {
            writeln!(out, "\r\x1B[K{}", line).unwrap();
        }
        out.flush().unwrap();
        self.last_line_count = Some(lines.len());
    }
}
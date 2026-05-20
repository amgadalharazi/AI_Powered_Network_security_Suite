use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::Write;
use std::time::Duration;

// ANSI color codes
const RESET:  &str = "\x1B[0m";
const BOLD:   &str = "\x1B[1m";
const DIM:    &str = "\x1B[2m";

const C_TCP:  &str = "\x1B[38;5;39m";   // blue
const C_UDP:  &str = "\x1B[38;5;135m";  // purple
const C_ICMP: &str = "\x1B[38;5;214m";  // amber
const C_ARP:  &str = "\x1B[38;5;42m";   // green
const C_IPV6: &str = "\x1B[38;5;205m";  // pink
const C_OTH:  &str = "\x1B[38;5;243m";  // gray

const C_RED:  &str = "\x1B[38;5;196m";
const C_GRN:  &str = "\x1B[38;5;42m";
const C_YEL:  &str = "\x1B[38;5;220m";
const C_BLU:  &str = "\x1B[38;5;39m";

// Fixed protocol display order so rows never shift position
const PROTO_ORDER: &[(&str, &str)] = &[
    ("TCP",      C_TCP),
    ("UDP",      C_UDP),
    ("ICMP",     C_ICMP),
    ("ARP",      C_ARP),
    ("IPv6",     C_IPV6),
    ("IP/Other", C_OTH),
    ("Unknown",  C_OTH),
];

const BAR_WIDTH:    usize = 30;
const SPARK_WIDTH:  usize = 40;
const SPARK_HISTORY:usize = 40;
const HOST_ROWS:    usize = 5;
const LOG_ROWS:     usize = 4;

pub struct Visualizer {
    http_hosts:      Vec<String>,
    log_lines:       VecDeque<String>,
    rate_history:    VecDeque<f64>,
    last_total:      u64,
    last_line_count: Option<usize>,
}

impl Visualizer {
    pub fn new() -> Self {
        Visualizer {
            http_hosts:      Vec::new(),
            log_lines:       VecDeque::new(),
            rate_history:    VecDeque::new(),
            last_total:      0,
            last_line_count: None,
        }
    }

    /// Push a log entry (call this from packet_sniffing.rs alongside render)
    pub fn push_log(&mut self, entry: String) {
        self.log_lines.push_front(entry);
        while self.log_lines.len() > LOG_ROWS * 4 {
            self.log_lines.pop_back();
        }
    }

    pub fn render(
        &mut self,
        stats:     &HashMap<String, u64>,
        total:     u64,
        elapsed:   Duration,
        http_host: Option<String>,
    ) {
        // Accumulate HTTP hosts (most recent first)
        if let Some(host) = http_host {
            if !self.http_hosts.contains(&host) {
                self.http_hosts.insert(0, host);
                if self.http_hosts.len() > 20 {
                    self.http_hosts.pop();
                }
            }
        }

        // Track per-tick rate for sparkline
        let rate = total.saturating_sub(self.last_total) as f64;
        self.last_total = total;
        self.rate_history.push_back(rate);
        if self.rate_history.len() > SPARK_HISTORY {
            self.rate_history.pop_front();
        }

        let secs      = elapsed.as_secs_f64().max(0.1);
        let pkt_rate  = total as f64 / secs;
        let max_count = stats.values().copied().max().unwrap_or(1).max(1);

        let dominant = PROTO_ORDER
            .iter()
            .max_by_key(|(k, _)| stats.get(*k).copied().unwrap_or(0))
            .map(|(k, _)| *k)
            .unwrap_or("—");

        let arp_count = stats.get("ARP").copied().unwrap_or(0);
        let arp_pct   = if total > 0 { arp_count as f64 / total as f64 * 100.0 } else { 0.0 };
        let arp_alert = arp_pct > 15.0 && arp_count > 10;
        let arp_color = if arp_alert { C_RED } else { C_GRN };

        let mut lines: Vec<String> = Vec::new();

        // ── Header ─────────────────────────────────────────────────────────
        lines.push(format!("{BOLD}╔══════════════════════════════════════════════════════════╗{RESET}"));
        lines.push(format!("{BOLD}║{RESET}  {C_BLU}{BOLD}NET_MONITOR{RESET}  {DIM}// en0{RESET}                    {C_GRN}● CAPTURING{RESET}       {BOLD}║{RESET}"));
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));

        // ── Metrics ────────────────────────────────────────────────────────
        lines.push(format!(
            "{BOLD}║{RESET}  {DIM}PACKETS{RESET} {C_BLU}{BOLD}{total:>8}{RESET}   {DIM}RATE{RESET} {BOLD}{pkt_rate:>7.1}/s{RESET}   {DIM}TIME{RESET} {BOLD}{secs:>6.0}s{RESET}   {DIM}ARP{RESET} {arp_color}{BOLD}{arp_count:>5}{RESET}  {BOLD}║{RESET}",
        ));

        // ── Protocol bars ──────────────────────────────────────────────────
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));
        lines.push(format!(
            "{BOLD}║{RESET}  {DIM}PROTOCOL DISTRIBUTION   dominant:{RESET} {C_YEL}{BOLD}{dominant:<8}{RESET}               {BOLD}║{RESET}",
        ));
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));

        for (proto, color) in PROTO_ORDER {
            let count  = stats.get(*proto).copied().unwrap_or(0);
            let filled = (count as f64 / max_count as f64 * BAR_WIDTH as f64) as usize;
            let empty  = BAR_WIDTH - filled;
            let pct    = if total > 0 { count as f64 / total as f64 * 100.0 } else { 0.0 };

            let bar = format!(
                "{color}{}{RESET}{DIM}{}{RESET}",
                "█".repeat(filled),
                "░".repeat(empty),
            );
            lines.push(format!(
                "{BOLD}║{RESET}  {color}{BOLD}{proto:<9}{RESET} {bar} {color}{BOLD}{count:>6}{RESET} {DIM}{pct:>5.1}%{RESET}  {BOLD}║{RESET}",
            ));
        }

        // ── Sparkline ──────────────────────────────────────────────────────
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));
        lines.push(format!("{BOLD}║{RESET}  {DIM}PACKET RATE  last {SPARK_WIDTH} ticks{RESET}                                 {BOLD}║{RESET}"));

        let spark = self.build_sparkline();
        lines.push(format!("{BOLD}║{RESET}  {C_BLU}{spark}{RESET}                    {BOLD}║{RESET}"));

        // ── HTTP hosts ─────────────────────────────────────────────────────
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));
        lines.push(format!(
            "{BOLD}║{RESET}  {DIM}HTTP HOSTS ({} detected){RESET}                                 {BOLD}║{RESET}",
            self.http_hosts.len(),
        ));

        for i in 0..HOST_ROWS {
            if i < self.http_hosts.len() {
                let h = &self.http_hosts[i];
                let t = if h.len() > 52 { format!("{}…", &h[..51]) } else { format!("{h:<52}") };
                lines.push(format!("{BOLD}║{RESET}  {C_GRN}•{RESET} {t}  {BOLD}║{RESET}"));
            } else {
                lines.push(format!("{BOLD}║{RESET}  {DIM}·{RESET} {:<52}  {BOLD}║{RESET}", ""));
            }
        }

        // ── Log tail ───────────────────────────────────────────────────────
        lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));
        lines.push(format!("{BOLD}║{RESET}  {DIM}PACKET LOG{RESET}                                               {BOLD}║{RESET}"));

        for i in 0..LOG_ROWS {
            if i < self.log_lines.len() {
                let entry = &self.log_lines[i];
                let vlen  = Self::visible_len(entry);
                let pad   = 56usize.saturating_sub(vlen);
                lines.push(format!("{BOLD}║{RESET}  {entry}{}  {BOLD}║{RESET}", " ".repeat(pad)));
            } else {
                lines.push(format!("{BOLD}║{RESET}  {DIM}{:<54}{RESET}  {BOLD}║{RESET}", ""));
            }
        }

        // ── ARP alert ─────────────────────────────────────────────────────
        if arp_alert {
            lines.push(format!("{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}"));
            lines.push(format!("{BOLD}║{RESET}  {C_RED}{BOLD}⚠  ARP ANOMALY — possible spoofing activity{RESET}             {BOLD}║{RESET}"));
        }

        lines.push(format!("{BOLD}╚══════════════════════════════════════════════════════════╝{RESET}"));
        lines.push(format!("{DIM}  Press Ctrl+C to stop...{RESET}"));

        // ── In-place overwrite ─────────────────────────────────────────────
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

    fn build_sparkline(&self) -> String {
        let blocks = ['▁','▂','▃','▄','▅','▆','▇','█'];
        let max    = self.rate_history.iter().cloned().fold(0.0f64, f64::max).max(1.0);

        let data: Vec<f64> = if self.rate_history.len() >= SPARK_WIDTH {
            self.rate_history.iter().rev().take(SPARK_WIDTH).rev().cloned().collect()
        } else {
            let pad = SPARK_WIDTH - self.rate_history.len();
            let mut v: Vec<f64> = vec![0.0; pad];
            v.extend(self.rate_history.iter().cloned());
            v
        };

        data.iter()
            .map(|&v| {
                let idx = ((v / max) * (blocks.len() - 1) as f64).round() as usize;
                blocks[idx.min(blocks.len() - 1)]
            })
            .collect()
    }

    /// Count printable characters, skipping ANSI escape sequences
    fn visible_len(s: &str) -> usize {
        let mut len = 0usize;
        let mut esc = false;
        for c in s.chars() {
            if c == '\x1B'     { esc = true; continue; }
            if esc             { if c == 'm' { esc = false; } continue; }
            len += 1;
        }
        len
    }
}
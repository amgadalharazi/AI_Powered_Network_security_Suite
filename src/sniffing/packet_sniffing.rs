use crate::AiDetection::{AIDetector, FlowTracker};
use crate::firewall_rule_manager::FirewallManager;
use crate::ltm::monitor::LiveTrafficMonitor;
use pcap::{Capture, Device, Error};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

pub struct SnifferConfig {
    pub device: String,
    pub verbose: bool,
    pub visualize: bool,
    pub print_devices: bool,
    pub enable_spoofing: bool,
    pub target_ip: String,
    pub gateway_ip: String,
    /// Path to the ONNX model (empty = AI detection disabled)
    pub ai_model_path: String,
    /// Path to the scaler JSON produced by main.py
    pub ai_scaler_path: String,
    /// Probability threshold above which a flow is flagged as an attack
    pub ai_threshold: f32,
    /// When true, auto-block detected attack sources via the firewall
    pub ai_auto_block: bool,
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            device: "en0".to_string(),
            verbose: false,
            visualize: false,
            print_devices: false,
            enable_spoofing: false,
            target_ip: String::new(),
            gateway_ip: String::new(),
            ai_model_path: String::new(),
            ai_scaler_path: String::new(),
            ai_threshold: 0.5,
            ai_auto_block: false,
        }
    }
}

pub fn start_sniffer(config: SnifferConfig) {
    if config.print_devices {
        if let Ok(devices) = Device::list() {
            println!("\nAvailable devices:");
            for dev in devices {
                println!("  {} - {:?}", dev.name, dev.desc.unwrap_or_default());
            }
        }
        return;
    }

    let devices = Device::list().expect("No devices found");
    let device = devices
        .iter()
        .find(|d| d.name == config.device)
        .unwrap_or_else(|| panic!("Device '{}' not found", config.device))
        .clone();

    if config.enable_spoofing {
        println!("[*] ARP poisoning enabled");
        println!("[*] Target:  {}", config.target_ip);
        println!("[*] Gateway: {}", config.gateway_ip);
    }

    // ── Optional AI detector ──────────────────────────────────────────────────
    let mut ai_detector: Option<AIDetector> = if !config.ai_model_path.is_empty() {
        match AIDetector::new(
            &config.ai_model_path,
            &config.ai_scaler_path,
            config.ai_threshold,
        ) {
            Ok(det) => {
                println!(
                    "[AI] Detector loaded (threshold={:.2})",
                    config.ai_threshold
                );
                Some(det)
            }
            Err(e) => {
                eprintln!("[AI] Failed to load detector: {} — running without AI", e);
                None
            }
        }
    } else {
        None
    };

    // Flow tracker: expire flows idle for 60 s
    let mut flow_tracker = FlowTracker::new(60);

    // Firewall manager (shared so auto_block can write rules)
    let fw_manager: Option<Arc<Mutex<FirewallManager>>> = if config.ai_auto_block {
        Some(Arc::new(Mutex::new(FirewallManager::new(
            "firewall_rules.json",
        ))))
    } else {
        None
    };

    let mut cap = Capture::from_device(device)
        .expect("Failed to create capture")
        .timeout(100)
        .open()
        .expect("Failed to open device");

    println!("[*] Live capture only – pcap saving disabled for stability");

    if config.visualize {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║         Live Packet Visualization Active         ║");
        println!("╚══════════════════════════════════════════════════╝\n");
    } else {
        println!("[*] Press Ctrl+C to stop…\n");
    }

    let mut ltm = LiveTrafficMonitor::new(config.visualize);

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let proto = guess_protocol(&packet);
                let http_host = if config.visualize || config.verbose {
                    extract_http_host(&packet)
                } else {
                    None
                };

                ltm.update_and_render(&proto, packet.len(), http_host.clone());

                // ── AI detection: feed packet into flow tracker ───────────────
                if let Some(ref mut detector) = ai_detector {
                    let (src_ip, dst_ip, src_port, dst_port, ip_proto) = extract_ip_fields(&packet);

                    let expired_flows = flow_tracker.process_packet(
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        ip_proto,
                        packet.len(),
                    );

                    for (key, stats) in expired_flows {
                        let features = stats.to_feature_vector();
                        match detector.predict(&features) {
                            Ok((true, prob)) => {
                                println!(
                                    "\x1b[91m[AI] ATTACK detected from {} → {} (proto={}, confidence={:.1}%)\x1b[0m",
                                    key.src_ip,
                                    key.dst_ip,
                                    key.protocol,
                                    prob * 100.0
                                );
                                if let Some(ref fw_arc) = fw_manager {
                                    if let Ok(mut fw) = fw_arc.lock() {
                                        fw.auto_block(&key.src_ip.to_string(), prob);
                                    }
                                }
                            }
                            Ok((false, _)) => {}
                            Err(e) => eprintln!("[AI] predict error: {}", e),
                        }
                    }
                }
                // ─────────────────────────────────────────────────────────────

                if config.verbose && !config.visualize {
                    println!(
                        "[#{}] {} bytes | Protocol: {}",
                        ltm.total_packets(),
                        packet.len(),
                        proto
                    );
                    if let Some(host) = &http_host {
                        println!("  └─ HTTP Host: {}", host);
                    }
                } else if !config.visualize && !config.verbose {
                    print!(
                        "\r[*] Packets captured: {} | Time: {:.1}s",
                        ltm.total_packets(),
                        ltm.elapsed().as_secs_f64()
                    );
                    std::io::Write::flush(&mut std::io::stdout()).unwrap();
                }
            }
            Err(Error::TimeoutExpired) => {
                if config.visualize {
                    ltm.maybe_render();
                }
            }
            Err(e) => {
                eprintln!("[!] Error capturing packet: {}", e);
                break;
            }
        }
    }

    if config.visualize {
        ltm.final_render();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn guess_protocol(packet: &pcap::Packet) -> String {
    if packet.len() < 14 {
        return "Short".to_string();
    }

    let (ethertype_offset, ip_proto_offset) = if &packet[12..14] == [0x81, 0x00] {
        (16, 27)
    } else {
        (12, 23)
    };

    if packet.len() < ethertype_offset + 2 {
        return "Short".to_string();
    }

    match &packet[ethertype_offset..ethertype_offset + 2] {
        [0x08, 0x00] => {
            if packet.len() > ip_proto_offset {
                match packet[ip_proto_offset] {
                    0x06 => "TCP".to_string(),
                    0x11 => "UDP".to_string(),
                    0x01 => "ICMP".to_string(),
                    _ => "IP/Other".to_string(),
                }
            } else {
                "IP".to_string()
            }
        }
        [0x08, 0x06] => "ARP".to_string(),
        [0x86, 0xDD] => "IPv6".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn extract_http_host(packet: &pcap::Packet) -> Option<String> {
    let data_str = String::from_utf8_lossy(&packet[..]);
    if data_str.contains("Host: ") {
        for line in data_str.lines() {
            if line.starts_with("Host: ") {
                return Some(line["Host: ".len()..].trim().to_string());
            }
        }
    }
    None
}

/// Parse an Ethernet frame and extract (src_ip, dst_ip, src_port, dst_port, ip_proto).
/// Returns zeroed-out values for non-IPv4 or short packets.
fn extract_ip_fields(packet: &pcap::Packet) -> (IpAddr, IpAddr, u16, u16, u8) {
    let data = &packet[..];

    // Need at least Ethernet (14) + IP header (20)
    if data.len() < 34 {
        return (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            0,
            0,
        );
    }

    // Only handle plain IPv4 (ethertype 0x0800); skip VLAN-tagged etc.
    if &data[12..14] != [0x08, 0x00] {
        return (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            0,
            0,
        );
    }

    let ip_proto = data[23];
    let src_ip = IpAddr::V4(Ipv4Addr::new(data[26], data[27], data[28], data[29]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(data[30], data[31], data[32], data[33]));

    // IP header length (IHL field, lower nibble of byte 14, in 32-bit words)
    let ihl = (data[14] & 0x0F) as usize * 4;
    let transport_start = 14 + ihl;

    let (src_port, dst_port) =
        if (ip_proto == 6 || ip_proto == 17) && data.len() >= transport_start + 4 {
            let sp = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
            let dp = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
            (sp, dp)
        } else {
            (0, 0)
        };

    (src_ip, dst_ip, src_port, dst_port, ip_proto)
}

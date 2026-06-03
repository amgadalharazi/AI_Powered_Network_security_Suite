extern crate pcap;

use crate::ltm::monitor::LiveTrafficMonitor;
use pcap::{Capture, Device, Error};

/// Configuration passed in from main — args are parsed once there,
/// so this function never needs to touch std::env::args() itself.
pub struct SnifferConfig {
    pub device: String,
    pub verbose: bool,
    pub visualize: bool,
    pub print_devices: bool,
    pub enable_spoofing: bool,
    pub target_ip: String,
    pub gateway_ip: String,
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

    let mut cap = Capture::from_device(device)
        .expect("Failed to create capture")
        .timeout(100) // 100 ms — keeps the loop responsive for visualize ticks
        .open()
        .expect("Failed to open device");

    std::fs::create_dir_all("./rslts").unwrap();
    let filename = if config.enable_spoofing {
        "./rslts/poisoned_traffic.pcap"
    } else {
        "./rslts/capture.pcap"
    };
    let mut file = cap.savefile(filename).expect("Failed to create pcap file");
    println!("[*] Saving packets to {}", filename);

    if config.visualize {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║         Live Packet Visualization Active         ║");
        println!("╚══════════════════════════════════════════════════╝\n");
    } else {
        println!("[*] Press Ctrl+C to stop...\n");
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

                file.write(&packet);
            }
            Err(Error::TimeoutExpired) => {
                // No packet arrived within the timeout window; tick the visualizer.
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

/// Determine the protocol of a raw Ethernet frame.
/// Handles 802.1Q VLAN-tagged frames (EtherType 0x8100) by skipping the 4-byte tag,
/// which shifts the real EtherType and IP protocol fields forward.
fn guess_protocol(packet: &pcap::Packet) -> String {
    if packet.len() < 14 {
        return "Short".to_string();
    }

    // Check for 802.1Q VLAN tag at offset 12 and adjust offsets accordingly.
    let (ethertype_offset, ip_proto_offset) = if &packet[12..14] == [0x81, 0x00] {
        (16usize, 27usize) // VLAN tag present: EtherType moves to byte 16, IP proto to 27
    } else {
        (12usize, 23usize) // Standard Ethernet
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
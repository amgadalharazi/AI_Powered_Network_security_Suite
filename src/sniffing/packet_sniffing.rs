// src/sniffing/packet_sniffing.rs
extern crate pcap;

use super::visualization::Visualizer;
use crate::ltm::monitor::LiveTrafficMonitor;
use pcap::{Capture, Device};
use std::time::{Duration, Instant};

pub fn start_sniffer(enable_spoofing: bool, target_ip: &str, gateway_ip: &str) {
    let mut print_devices = false;
    let mut requested_device_s = "en0".to_string();
    let mut verbose = false;
    let mut visualize = false;

    // Simple argument parser
    let args: Vec<String> = std::env::args().collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--visualize" | "-V" | "--viz" => visualize = true,
            "--verbose" => verbose = true,
            "-v" => {
                if i > 0 && args.get(i) == Some(&"-V".to_string()) {
                    visualize = true;
                } else {
                    verbose = true;
                }
            }
            "--print" | "-p" | "--print_devices" => print_devices = true,
            "--device" | "-d" => {
                if i + 1 < args.len() {
                    requested_device_s = args[i + 1].clone();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    if print_devices {
        if let Ok(devices) = Device::list() {
            println!("\nAvailable devices:");
            for dev in devices {
                println!("  {} - {:?}", dev.name, dev.desc);
            }
        }
        return;
    }

    let devices = Device::list().expect("No devices found");
    let device = devices
        .iter()
        .find(|d| d.name == requested_device_s)
        .unwrap_or_else(|| panic!("Device {} not found", requested_device_s))
        .clone();

    if enable_spoofing {
        println!("[*] ARP poisoning enabled");
        println!("[*] Target: {}", target_ip);
        println!("[*] Gateway: {}", gateway_ip);
    }

    let mut cap = Capture::from_device(device)
        .expect("Failed to create capture")
        .open()
        .expect("Failed to open device");

    std::fs::create_dir_all("./rslts").unwrap();
    let filename = if enable_spoofing {
        "./rslts/poisoned_traffic.pcap"
    } else {
        "./rslts/capture.pcap"
    };
    let mut file = cap.savefile(filename).expect("Failed to create pcap file");
    println!("[*] Saving packets to {}", filename);

    if visualize {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║         Live Packet Visualization Active         ║");
        println!("╚══════════════════════════════════════════════════╝\n");
    } else {
        println!("[*] Press Ctrl+C to stop...\n");
    }

    let mut ltm = LiveTrafficMonitor::new();
    let mut visualizer = Visualizer::new();
    let start_time = Instant::now();
    let mut last_update = Instant::now();

    while let Ok(packet) = cap.next_packet() {
        let proto = guess_protocol(&packet);
        ltm.update(&proto, packet.len());

        if visualize {
            let http_host = extract_http_host(&packet);
            if last_update.elapsed() >= Duration::from_secs(1) {
                visualizer.render(
                    &ltm.protocol_stats,
                    ltm.total_packets,
                    start_time.elapsed(),
                    ltm.bandwidth_mbps(),
                    ltm.packet_rate(),
                    http_host,
                );
                last_update = Instant::now();
            }
        } else if verbose {
            println!(
                "[#{}] {} bytes | Protocol: {}",
                ltm.total_packets,
                packet.len(),
                proto
            );
            if let Some(host) = extract_http_host(&packet) {
                println!("  └─ HTTP Host: {}", host);
            }
        } else {
            print!(
                "\r[*] Packets captured: {} | Time: {:.1}s",
                ltm.total_packets,
                start_time.elapsed().as_secs_f64()
            );
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }

        file.write(&packet);
    }
}

fn guess_protocol(packet: &pcap::Packet) -> String {
    if packet.len() > 14 {
        match &packet[12..14] {
            [0x08, 0x00] => {
                if packet.len() > 23 {
                    match packet[23] {
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
    } else {
        "Short".to_string()
    }
}

fn extract_http_host(packet: &pcap::Packet) -> Option<String> {
    let data_str = String::from_utf8_lossy(&packet[..]);
    if data_str.contains("Host: ") {
        for line in data_str.lines() {
            if line.starts_with("Host: ") {
                return Some(line.replace("Host: ", "").trim().to_string());
            }
        }
    }
    None
}

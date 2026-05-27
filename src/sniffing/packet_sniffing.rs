extern crate pcap;

use crate::ltm::monitor::LiveTrafficMonitor;
use pcap::{Capture, Device, Error};

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
                if i > 0 && args.get(i - 1).map(|s| s.as_str()) == Some("-V") {
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
                println!("  {} - {:?}", dev.name, dev.desc.unwrap_or_default());
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

    // Create inactive capture with timeout (milliseconds)
    let mut cap_inactive = Capture::from_device(device).expect("Failed to create capture");
    cap_inactive = cap_inactive.timeout(100); // 100 ms timeout
    let mut cap = cap_inactive.open().expect("Failed to open device");

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

    let mut ltm = LiveTrafficMonitor::new(visualize);

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let proto = guess_protocol(&packet);
                let http_host = if visualize { extract_http_host(&packet) } else { None };
                ltm.update_and_render(&proto, packet.len(), http_host.clone());

                if verbose && !visualize {
                    println!(
                        "[#{}] {} bytes | Protocol: {}",
                        ltm.total_packets(),
                        packet.len(),
                        proto
                    );
                    if let Some(host) = &http_host {
                        println!("  └─ HTTP Host: {}", host);
                    }
                } else if !visualize && !verbose {
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
                if visualize {
                    ltm.maybe_render();
                }
            }
            Err(e) => {
                eprintln!("[!] Error capturing packet: {}", e);
                break;
            }
        }
    }

    if visualize {
        ltm.final_render();
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
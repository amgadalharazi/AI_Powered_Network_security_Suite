extern crate argparse;
extern crate pcap;

//use argparse::{ArgumentParser, Store, StoreTrue};
use pcap::{Capture, Device};
use super::visualization::Visualizer;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub fn start_sniffer(enable_spoofing: bool, target_ip: &str, gateway_ip: &str) {
    let mut print_devices: bool = false;
    let mut requested_device_s: String = "en0".to_string();
    let mut verbose: bool = false;
    let mut visualize: bool = false;

    // Manual argument parsing to avoid argparse issues
    let args: Vec<String> = std::env::args().collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--visualize" | "-V" | "--viz" => visualize = true,
            "--verbose" => verbose = true,
            "-v" => {
                // Only set verbose if -V wasn't specified
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
                    i += 1; // Skip next argument
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Debug output
    println!("[*] Configuration:");
    println!("[*]   Verbose: {}", verbose);
    println!("[*]   Visualize: {}", visualize);
    println!("[*]   Device: {}", requested_device_s);
    println!();

    // Handle print devices first
    if print_devices {
        match Device::list() {
            Ok(devices) => {
                println!("\nAvailable devices:");
                println!("{:=<60}", "");
                for device in devices {
                    println!("  Device: {:?}", device.name);
                    println!("  Description: {:?}", device.desc);
                    println!("{:-<60}", "");
                }
                return;
            }
            Err(e) => {
                println!("[!] Error listing devices: {}", e);
                return;
            }
        }
    }

    // Get the requested device
    let devices = match Device::list() {
        Ok(d) => d,
        Err(_) => {
            println!("[!] No devices found...");
            return;
        }
    };

    let requested_device = match devices.iter().find(|d| d.name == requested_device_s) {
        Some(device) => {
            println!("[+] Device {} selected!", requested_device_s);
            device.clone()
        }
        None => {
            println!("[!] Device {} not found!", requested_device_s);
            println!("[*] Available devices:");
            for d in &devices {
                println!("    - {}", d.name);
            }
            return;
        }
    };

    if enable_spoofing {
        println!("[*] ARP poisoning enabled");
        println!("[*] Target: {}", target_ip);
        println!("[*] Gateway: {}", gateway_ip);
        println!("[*] Capturing poisoned traffic...\n");
    }

    let mut cap = match Capture::from_device(requested_device) {
        Ok(cap) => match cap.open() {
            Ok(c) => c,
            Err(e) => {
                println!("[!] Failed to open device: {}", e);
                return;
            }
        },
        Err(e) => {
            println!("[!] Failed to create capture: {}", e);
            return;
        }
    };

    std::fs::create_dir_all("./rslts").unwrap();
    
    let filename = if enable_spoofing {
        "./rslts/poisoned_traffic.pcap".to_string()
    } else {
        "./rslts/capture.pcap".to_string()
    };
    
    let mut file = match cap.savefile(&filename) {
        Ok(f) => f,
        Err(e) => {
            println!("[!] Failed to create pcap file: {}", e);
            return;
        }
    };

    println!("[*] Saving packets to {}", filename);
    
    if visualize {
        println!("\n╔══════════════════════════════════════════════════╗");
        println!("║         Live Packet Visualization Active         ║");
        println!("╚══════════════════════════════════════════════════╝\n");
    } else {
        println!("[*] Press Ctrl+C to stop...\n");
    }
    
    let mut packet_count: u64 = 0;
    let mut protocol_stats: HashMap<String, u64> = HashMap::new();
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    let mut visualizer = Visualizer::new();

    while let Ok(packet) = cap.next_packet() {
        packet_count += 1;
        
        if visualize {
            let proto = guess_protocol(&packet);
            *protocol_stats.entry(proto.clone()).or_insert(0) += 1;
            
            let http_host = extract_http_host(&packet);
            
            if last_print.elapsed() >= Duration::from_secs(1) {
                visualizer.render(&protocol_stats, packet_count, start_time.elapsed(), http_host);
                last_print = Instant::now();
            }
        } else if verbose {
            let proto = guess_protocol(&packet);
            println!("[#{}] {} bytes | Protocol: {}", packet_count, packet.len(), proto);
            
            if let Some(host) = extract_http_host(&packet) {
                println!("  └─ HTTP Host: {}", host);
            }
        } else {
            print!("\r[*] Packets captured: {} | Time: {:.1}s", 
                packet_count, start_time.elapsed().as_secs_f64());
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
    let data = &packet[..];
    let data_str = String::from_utf8_lossy(data);
    
    if data_str.contains("Host: ") {
        for line in data_str.lines() {
            if line.starts_with("Host: ") {
                return Some(line.replace("Host: ", "").trim().to_string());
            }
        }
    }
    None
}
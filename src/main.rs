mod sniffing;
mod ltm;

// NEW: add firewall module with explicit path because the directory starts with capital F
#[path = "Firewall_rule_manager/mod.rs"]
mod firewall_rule_manager;

use sniffing::arp_spoofing::ArpSpoofer;
use sniffing::packet_sniffing::{start_sniffer, SnifferConfig};
use pcap::Device;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// NEW: import the firewall manager
use firewall_rule_manager::{FirewallManager, FirewallRule};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    println!("╔════════════════════════════════════════╗");
    println!("║   Network Security Tool v1.0           ║");
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
            let interface = args.get(4).cloned().unwrap_or_else(|| "en0".to_string());

            let target_parsed: Ipv4Addr = target_ip.parse().expect("Invalid target IP");
            let gateway_parsed: Ipv4Addr = gateway_ip.parse().expect("Invalid gateway IP");

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
        // ────────────────── NEW FIREWALL COMMAND ──────────────────
        "firewall" => {
            handle_firewall_commands(&args[2..]);
        }
        _ => {
            println!("[!] Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

// ──────────────── NEW FIREWALL HANDLER FUNCTION ────────────────
fn handle_firewall_commands(args: &[String]) {
    if args.is_empty() {
        println!("[!] Firewall sub-command required.");
        print_firewall_usage();
        return;
    }

    // Path to save rules (can be configured)
    let storage_path = "firewall_rules.json";
    let mut fw = FirewallManager::new(storage_path);

    match args[0].as_str() {
        "list" => {
            fw.list_rules();
        }
        "add" => {
            // Usage: firewall add <name> <allow|deny> <proto> <src_ip> <dst_ip> [src_port] [dst_port]
            if args.len() < 6 {
                println!("Usage: firewall add <name> <allow|deny> <proto> <src_ip> <dst_ip> [src_port] [dst_port]");
                return;
            }
            let name = &args[1];
            let action = &args[2];
            let proto = &args[3];
            let src_ip = &args[4];
            let dst_ip = &args[5];

            let src_port = if args.len() > 6 { args[6].parse::<u16>().ok() } else { None };
            let dst_port = if args.len() > 7 { args[7].parse::<u16>().ok() } else { None };

            let rule = FirewallRule::new(name, action, proto, src_ip, dst_ip, src_port, dst_port);
            fw.add_rule(rule);
            fw.save();
        }
        "remove" => {
            if args.len() < 2 {
                println!("Usage: firewall remove <rule_name>");
                return;
            }
            fw.remove_rule(&args[1]);
            fw.save();
        }
        "enable" => {
            if args.len() < 2 {
                println!("Usage: firewall enable <rule_name>");
                return;
            }
            fw.set_rule_enabled(&args[1], true);
            fw.save();
        }
        "disable" => {
            if args.len() < 2 {
                println!("Usage: firewall disable <rule_name>");
                return;
            }
            fw.set_rule_enabled(&args[1], false);
            fw.save();
        }
        "apply" => {
            fw.apply();
        }
        _ => {
            println!("[!] Unknown firewall sub-command: {}", args[0]);
            print_firewall_usage();
        }
    }
}

// ──────────────── EXISTING FUNCTIONS (unchanged) ────────────────
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

    // ──────────────── NEW FIREWALL USAGE ────────────────
    println!("\nFirewall Commands:");
    println!("  cargo run -- firewall list                                     # List all rules");
    println!("  cargo run -- firewall add <name> <allow|deny> <proto> <src> <dst> [src_port] [dst_port]");
    println!("  cargo run -- firewall remove <name>                            # Remove a rule");
    println!("  cargo run -- firewall enable <name>                            # Enable a rule");
    println!("  cargo run -- firewall disable <name>                           # Disable a rule");
    println!("  cargo run -- firewall apply                                    # Apply rules (simulated)");
}

// ───── NEW FIREWALL USAGE HELP (separate, used by handler) ─────
fn print_firewall_usage() {
    println!("Firewall sub-commands:");
    println!("  list                                     List all rules");
    println!("  add <name> <allow|deny> <proto> <src> <dst> [src_port] [dst_port]");
    println!("  remove <name>                            Remove a rule");
    println!("  enable <name>                            Enable a rule");
    println!("  disable <name>                           Disable a rule");
    println!("  apply                                    Apply rules (simulated)");
}
#[allow(non_snake_case)]
mod AiDetection;
mod ltm;
mod sniffing;

// Explicit path because the directory name starts with a capital letter
#[path = "Firewall_rule_manager/mod.rs"]
mod firewall_rule_manager;

use pcap::Device;
use sniffing::arp_spoofing::ArpSpoofer;
use sniffing::packet_sniffing::{SnifferConfig, start_sniffer};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
            spoofer
                .discover()
                .expect("Failed to discover MAC addresses");

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
                    Err(e) => eprintln!(
                        "[!] Warning: could not enable IP forwarding ({}). Run as root.",
                        e
                    ),
                }
            }

            println!("[*] Starting MITM attack on interface {}...", interface);

            let iface_clone = interface.clone();
            thread::spawn(move || {
                let mut spoofer = ArpSpoofer::new(&iface_clone, target_parsed, gateway_parsed)
                    .expect("Failed to create ARP spoofer");
                spoofer
                    .discover()
                    .expect("Failed to discover MAC addresses");
                spoofer.start_poisoning().ok();
            });

            thread::sleep(Duration::from_secs(3));

            let config = parse_sniffer_args(&args[5..], true, &target_ip, &gateway_ip);
            start_sniffer(config);
        }
        "devices" => {
            list_devices();
        }
        "firewall" => {
            handle_firewall_commands(&args[2..]);
        }
        _ => {
            println!("[!] Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Firewall sub-command handler
// ──────────────────────────────────────────────────────────────────────────────

fn handle_firewall_commands(args: &[String]) {
    if args.is_empty() {
        println!("[!] Firewall sub-command required.");
        print_firewall_usage();
        return;
    }

    let storage_path = "firewall_rules.json";
    let mut fw = FirewallManager::new(storage_path);

    match args[0].as_str() {
        "list" => {
            fw.list_rules();
        }
        "add" => {
            // firewall add <name> <allow|deny> <proto> <src_ip> <dst_ip> [src_port] [dst_port]
            if args.len() < 6 {
                println!(
                    "Usage: firewall add <name> <allow|deny> <proto> <src_ip> <dst_ip> [src_port] [dst_port]"
                );
                return;
            }
            let name = &args[1];
            let action = &args[2];
            let proto = &args[3];
            let src_ip = &args[4];
            let dst_ip = &args[5];
            let src_port = args.get(6).and_then(|p| p.parse::<u16>().ok());
            let dst_port = args.get(7).and_then(|p| p.parse::<u16>().ok());

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

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Build a SnifferConfig from CLI flags.
/// Now also picks up AI-detection flags: --ai-model, --ai-scaler,
/// --ai-threshold, --ai-block.
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
        ai_model_path: String::new(),
        ai_scaler_path: String::new(),
        ai_threshold: 0.5,
        ai_auto_block: false,
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
            // AI detection flags
            "--ai-model" => {
                if i + 1 < extra.len() {
                    config.ai_model_path = extra[i + 1].clone();
                    i += 1;
                }
            }
            "--ai-scaler" => {
                if i + 1 < extra.len() {
                    config.ai_scaler_path = extra[i + 1].clone();
                    i += 1;
                }
            }
            "--ai-threshold" => {
                if i + 1 < extra.len() {
                    config.ai_threshold = extra[i + 1].parse::<f32>().unwrap_or(0.5);
                    i += 1;
                }
            }
            "--ai-block" => config.ai_auto_block = true,
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
    println!(
        "  sudo cargo run -- sniff -V                            # Sniffer with live visualization"
    );
    println!("  sudo cargo run -- sniff -v                            # Verbose per-packet output");
    println!("  sudo cargo run -- sniff -d <dev>                      # Use specific device");
    println!("  sudo cargo run -- arp <iface> <target> <gw>           # ARP poisoning attack");
    println!("  sudo cargo run -- mitm <target> <gw> [iface]          # MITM attack (ARP + sniff)");
    println!("  cargo run -- devices                                   # List network devices");
    println!();
    println!("Sniffer Options (with 'sniff' or 'mitm'):");
    println!("  -V, --visualize            Live TUI visualization");
    println!("  -v, --verbose              Verbose per-packet output");
    println!("  -d, --device <dev>         Network device (default: en0)");
    println!("  -p, --print                Print available devices");
    println!();
    println!("AI Detection Options (with 'sniff' or 'mitm'):");
    println!("  --ai-model   <path>        Path to models/ids_model.onnx");
    println!("  --ai-scaler  <path>        Path to models/scaler.json");
    println!("  --ai-threshold <0..1>      Attack probability threshold (default: 0.5)");
    println!("  --ai-block                 Auto-block detected attackers via firewall");
    println!();
    println!("Firewall Commands:");
    println!("  cargo run -- firewall list");
    println!(
        "  cargo run -- firewall add <name> <allow|deny> <proto> <src> <dst> [src_port] [dst_port]"
    );
    println!("  cargo run -- firewall remove <name>");
    println!("  cargo run -- firewall enable <name>");
    println!("  cargo run -- firewall disable <name>");
    println!("  cargo run -- firewall apply");
}

fn print_firewall_usage() {
    println!("Firewall sub-commands:");
    println!("  list");
    println!("  add <name> <allow|deny> <proto> <src> <dst> [src_port] [dst_port]");
    println!("  remove <name>");
    println!("  enable <name>");
    println!("  disable <name>");
    println!("  apply");
}

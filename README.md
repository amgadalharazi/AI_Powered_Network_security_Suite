# Network Security Suite

A Rust-based network analysis and security testing tool featuring ARP poisoning, packet sniffing, MITM attack capabilities, **firewall rule management**, and real-time terminal visualization.

## Current Features

- Real-time packet sniffing with protocol detection (TCP, UDP, ICMP, ARP, IPv6)
- ARP poisoning attacks for MITM scenarios
- Full MITM (ARP poison + sniff)
- Live terminal dashboard with protocol distribution charts
- HTTP host header extraction and display
- PCAP export for offline analysis with Wireshark
- Automatic ARP table restoration on exit
- ARP anomaly detection with visual warnings
- **Firewall rule manager** (add, remove, enable/disable, apply rules with JSON persistence)

## Prerequisites

- Rust 1.70 or higher
- Root/sudo privileges
- libpcap development files

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# macOS
brew install libpcap

# Arch Linux
sudo pacman -S libpcap
```

## Installation

```bash
git clone https://github.com/amgadalharazi/AI_Powered_Network_security_Suite
cd AI_Powered_Network_security_Suite
cargo build --release
```

## Commands

### Sniffing & MITM
```
sudo cargo run -- sniff
    Start basic packet sniffer on default interface (en0)

sudo cargo run -- sniff -V
    Start sniffer with live visualization dashboard

sudo cargo run -- sniff -v
    Verbose mode – print each packet with details

sudo cargo run -- sniff -d eth0
    Use specific network interface

sudo cargo run -- sniff -p
    List all available network devices

sudo cargo run -- arp en0 192.168.1.100 192.168.1.1
    Execute ARP poisoning attack between target and gateway

sudo cargo run -- mitm 192.168.1.100 192.168.1.1
    Full MITM attack – ARP poison + packet capture

cargo run -- devices
    List network devices (no root required)
```

### Firewall Rule Manager

```
cargo run -- firewall list
    List all firewall rules

cargo run -- firewall add <name> <allow|deny> <proto> <src_ip> <dst_ip> [src_port] [dst_port]
    Add a new rule (port ranges not yet supported)
    Example:
    cargo run -- firewall add "allow-ssh" allow tcp 192.168.1.0/24 any 22

cargo run -- firewall remove <name>
    Remove a rule permanently

cargo run -- firewall enable <name>
    Enable a rule

cargo run -- firewall disable <name>
    Disable a rule (keep it but don't apply)

cargo run -- firewall apply
    Apply all enabled rules (currently simulated; add platform-specific execution)
```

> Rules are saved to `firewall_rules.json` automatically after each add/remove/enable/disable.  
> Use `apply` to simulate rule enforcement or hook into your system's firewall (pfctl/iptables).

## Visualization Dashboard

When running with `-V` flag, the live dashboard displays:

```
╔══════════════════════════════════════════════════╗
║         Network Traffic Monitor v1.0             ║
╠══════════════════════════════════════════════════╣
║ Time:   45.2s  Packets:   1234  Rate:  27.3/s    ║
╠══════════════════════════════════════════════════╣
║  Protocol Distribution:                          ║
║ TCP      ████████████████░░░░░░░░    823  66.7%  ║
║ UDP      ████░░░░░░░░░░░░░░░░░░░░    156  12.6%  ║
║ ICMP     ██████░░░░░░░░░░░░░░░░░░    245  19.8%  ║
║ ARP      ██░░░░░░░░░░░░░░░░░░░░░░     10   0.8%  ║
║ IPv6     ░░░░░░░░░░░░░░░░░░░░░░░░      0   0.0%  ║
║ IP/Other ░░░░░░░░░░░░░░░░░░░░░░░░      0   0.0%  ║
╠══════════════════════════════════════════════════╣
║  HTTP Hosts Detected:                            ║
║  • api.github.com                                ║
║  • stackoverflow.com                             ║
║  • google.com                                    ║
╠══════════════════════════════════════════════════╣
║  ⚠  ARP anomaly — possible spoofing!             ║
╚══════════════════════════════════════════════════╝
Press Ctrl+C to stop...
```

The dashboard updates every second and shows:
- Elapsed time, total packets, packets per second
- Protocol distribution with colored bars
- Last 5 unique HTTP hosts detected
- ARP anomaly warning when ARP traffic exceeds 15% of total

## Output Files

All captured traffic is saved to PCAP files:

- `./rslts/capture.pcap` – Standard captures
- `./rslts/poisoned_traffic.pcap` – MITM attack captures

View with Wireshark:
```bash
wireshark ./rslts/capture.pcap
```

## Architecture

```
src/
├── main.rs                          # CLI entry point, command routing
├── sniffing/
│   ├── arp_spoofing.rs              # ARP poisoning implementation
│   ├── packet_sniffing.rs           # Packet capture and analysis
│   └── sniffers.rs                  # Sniffer helpers
├── ltm/
│   ├── monitor.rs                   # Live traffic monitor
│   └── visualizer.rs                # Terminal dashboard
└── Firewall_rule_manager/
    ├── mod.rs                       # Module root, public exports
    ├── rule.rs                      # FirewallRule struct, RuleAction enum
    ├── storage.rs                   # JSON persistence (load/save)
    ├── firewall.rs                  # Rule application (simulation placeholder)
    └── manager.rs                   # CRUD operations, apply, save
```

## Security Notes

- Educational purposes only
- Requires explicit authorization for target networks
- Unauthorized interception violates laws in most jurisdictions
- Tool automatically restores ARP tables on exit
- Manual cleanup may be required after crashes:

```bash
# Linux
sudo ip neigh flush all

# macOS
sudo arp -d -a

# Windows (Admin)
netsh interface ip delete arpcache
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Permission denied | Run with `sudo` |
| Device not found | List available devices: `cargo run -- devices` |
| No packets captured | Verify interface has traffic and is in promiscuous mode |
| ARP poisoning not working | Disable router ARP protection features; check reachability |
| Visualization glitching | Use a modern terminal that supports ANSI escape codes |
| Firewall commands not found | Make sure module files are present and deps installed |

## Planned Features

- Device discovery
- Threat detection AI
- Port scanner
- Intrusion alerts
- Log analyzer
- Dashboard analytics
- **Platform-specific firewall enforcement (iptables / pfctl)**

## Implemented Features

- Packet sniffing with real-time visualization
- ARP poisoning and MITM
- Firewall rule manager (persistent, command-line CRUD)
- Live traffic monitoring

## License

MIT License

Disclaimer: This tool is for security research and network diagnostics only. Users are solely responsible for complying with applicable laws and obtaining proper authorization. The authors assume no liability for misuse or damage.

=======
**Disclaimer:** This tool is for security research and network diagnostics only. Users are solely responsible for complying with applicable laws and obtaining proper authorization. The authors assume no liability for misuse or damage.

=======
feel free to send me a message anytime 
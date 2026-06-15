use crate::firewall_rule_manager::{
    firewall,
    rule::{FirewallRule, RuleAction},
    storage,
};

pub struct FirewallManager {
    rules: Vec<FirewallRule>,
    storage_path: String,
}

impl FirewallManager {
    pub fn new(storage_path: &str) -> Self {
        let rules = storage::load_rules(storage_path);
        Self {
            rules,
            storage_path: storage_path.to_string(),
        }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        println!("[+] Added rule '{}'", rule.name);
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, name: &str) {
        if let Some(pos) = self.rules.iter().position(|r| r.name == name) {
            self.rules.remove(pos);
            println!("[-] Removed rule '{}'", name);
        } else {
            println!("[!] Rule '{}' not found", name);
        }
    }

    pub fn set_rule_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.name == name) {
            rule.enabled = enabled;
            println!(
                "[*] Rule '{}' {}",
                name,
                if enabled { "enabled" } else { "disabled" }
            );
        } else {
            println!("[!] Rule '{}' not found", name);
        }
    }

    pub fn list_rules(&self) {
        if self.rules.is_empty() {
            println!("No rules defined.");
            return;
        }
        println!(
            "{:<20} {:<8} {:<8} {:<20} {:<20} {:<12} {:<12} {:<8}",
            "Name", "Action", "Proto", "Source", "Destination", "Src Port", "Dst Port", "Enabled"
        );
        println!("{}", "-".repeat(100));
        for rule in &self.rules {
            println!(
                "{:<20} {:<8} {:<8} {:<20} {:<20} {:<12} {:<12} {:<8}",
                rule.name,
                if rule.action == RuleAction::Allow {
                    "ALLOW"
                } else {
                    "DENY"
                },
                rule.protocol,
                rule.src_ip,
                rule.dst_ip,
                rule.src_port
                    .map_or("any".to_string(), |p: u16| p.to_string()),
                rule.dst_port
                    .map_or("any".to_string(), |p: u16| p.to_string()),
                if rule.enabled { "YES" } else { "NO" },
            );
        }
    }

    pub fn apply(&self) {
        firewall::apply_rules(&self.rules);
    }

    pub fn save(&self) {
        storage::save_rules(&self.storage_path, &self.rules);
        println!("[+] Rules saved to {}", self.storage_path);
    }
}

impl FirewallManager {
    // ... existing methods ...

    // #[allow(dead_code)] // uncomment to silence warning if not used yet
    pub fn auto_block(&mut self, src_ip: &str, confidence: f32) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let rule_name = format!("ai_block_{}_{}", src_ip.replace('.', "_"), timestamp);
        let rule = FirewallRule::new(&rule_name, "deny", "any", src_ip, "any", None, None);
        self.add_rule(rule);
        self.apply();
        self.save();
        println!(
            "\x1b[91m[AI] BLOCKED {} (confidence {:.2}%)\x1b[0m",
            src_ip,
            confidence * 100.0
        );
    }
}

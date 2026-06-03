use std::fs;
use std::path::Path;
use crate::firewall_rule_manager::rule::FirewallRule;

pub fn load_rules(path: &str) -> Vec<FirewallRule> {
    if Path::new(path).exists() {
        match fs::read_to_string(path) {
            Ok(json) => {
                serde_json::from_str(&json).unwrap_or_default()
            }
            Err(_) => vec![],
        }
    } else {
        vec![]
    }
}

pub fn save_rules(path: &str, rules: &Vec<FirewallRule>) {
    let json = serde_json::to_string_pretty(rules).unwrap();
    fs::write(path, json).expect("Failed to write rules file");
}
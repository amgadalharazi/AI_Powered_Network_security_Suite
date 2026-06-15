use crate::firewall_rule_manager::rule::FirewallRule;

pub fn apply_rules(rules: &Vec<FirewallRule>) {
    println!("[Firewall] Applying {} rule(s):", rules.len());
    for rule in rules.iter().filter(|r| r.enabled) {
        println!(
            "  - {}: {} traffic {} → {} (proto: {}, ports: {:?} → {:?})",
            rule.name,
            match rule.action {
                super::rule::RuleAction::Allow => "ALLOW",
                super::rule::RuleAction::Deny => "DENY",
            },
            rule.src_ip,
            rule.dst_ip,
            rule.protocol,
            rule.src_port,
            rule.dst_port,
        );
    }
    println!("[Firewall] (Platform‑specific application not implemented)");
}

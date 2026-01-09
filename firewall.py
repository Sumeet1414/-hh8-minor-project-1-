import random

class FirewallRule:
    def __init__(self, action, port=None, blocked_ip=None):
        self.action = action  # "ALLOW" or "DENY"
        self.port = port
        self.blocked_ip = blocked_ip

class Firewall:
    def __init__(self):
        self.rules = []
    
    def add_rule(self, rule):
        self.rules.append(rule)

    def check_packet(self, packet):
        """
        The Logic Gate: Returns TRUE (Allow) or FALSE (Deny)
        """
        print(f"Checking {packet}...")
        
        # 1. Check against Access Control List (ACL)
        for rule in self.rules:
            # Check Port Blocking
            if rule.port is not None and packet.port == rule.port:
                print(f"  -> MATCH: Rule Port {rule.port} ({rule.action})")
                return rule.action
            
            # Check IP Blocking
            if rule.blocked_ip is not None and packet.src_ip == rule.blocked_ip:
                print(f"  -> MATCH: Rule IP {rule.blocked_ip} ({rule.action})")
                return rule.action

        # 2. Simulated ML Classifier (Anomaly Detection)
        # If payload is suspiciously long (> 50 chars), we flag it.
        if len(packet.payload) > 50:
            print("  -> MATCH: ML Anomaly Detector (Payload too large)")
            return "DENY"

        # Default Policy if no rules match
        return "ALLOW"
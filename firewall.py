import random

class FirewallRule:
    def __init__(self, action, port=None, blocked_ip=None):
        self.action = action  
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
        
       
        for rule in self.rules:
           
            if rule.port is not None and packet.port == rule.port:
                print(f"  -> MATCH: Rule Port {rule.port} ({rule.action})")
                return rule.action
            
            if rule.blocked_ip is not None and packet.src_ip == rule.blocked_ip:
                print(f"  -> MATCH: Rule IP {rule.blocked_ip} ({rule.action})")
                return rule.action

        if len(packet.payload) > 50:
            print("  -> MATCH: ML Anomaly Detector (Payload too large)")
            return "DENY"

        return "ALLOW"
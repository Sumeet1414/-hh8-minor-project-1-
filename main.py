import time
from packet import Packet
from firewall import Firewall, FirewallRule

def main():
    # 1. Initialize Firewall
    fw = Firewall()

    # 2. Add Rules (The Logic)
    print("Loading Rules...")
    fw.add_rule(FirewallRule("DENY", port=22))         # Block SSH
    fw.add_rule(FirewallRule("DENY", blocked_ip="10.0.0.5")) # Block specific Hacker IP
    
    # 3. Create Packets (The Traffic)
    traffic = [
        Packet(1, "192.168.1.1", "8.8.8.8", 443, "TCP", "Secure HTTPS Request"),
        Packet(2, "10.0.0.5", "8.8.8.8", 80, "TCP", "Malicious Request from Hacker"), # Should Block (IP)
        Packet(3, "192.168.1.50", "1.1.1.1", 22, "TCP", "Attempting SSH connection"), # Should Block (Port)
        Packet(4, "192.168.1.99", "8.8.8.8", 80, "TCP", "A" * 100), # Should Block (ML/Payload too large)
    ]

    # 4. Run the Simulator
    print("\n--- STARTING TRAFFIC SIMULATION ---\n")
    
    allowed_count = 0
    denied_count = 0

    for pkt in traffic:
        decision = fw.check_packet(pkt)
        
        if decision == "ALLOW":
            print(f"RESULT: ✅ ALLOWED\n")
            allowed_count += 1
        else:
            print(f"RESULT: ❌ DENIED\n")
            denied_count += 1
            
        time.sleep(1) # Pause for effect

    # 5. Dashboard Summary
    print("-" * 30)
    print(f"Total Traffic: {len(traffic)}")
    print(f"Allowed: {allowed_count}")
    print(f"Blocked: {denied_count}")
    print("-" * 30)

if __name__ == "__main__":
    main()
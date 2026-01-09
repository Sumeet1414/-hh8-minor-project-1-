import tkinter as tk
from tkinter import ttk, scrolledtext
import random
import time
from dataclasses import dataclass

# ===========================
# 1. DATA & LOGIC LAYER
# ===========================

@dataclass
class Packet:
    id: int
    src_ip: str
    dst_ip: str
    port: int
    protocol: str
    payload: str

class FirewallEngine:
    def __init__(self):
        self.rules = []
        self.stats = {"ALLOW": 0, "DENY": 0}

    def add_rule(self, action, port=None, ip=None):
        self.rules.append({"action": action, "port": port, "ip": ip})

    def check_packet(self, packet):
        reason = "Default Policy"
        decision = "ALLOW"

        # 1. Check ACL Rules
        for rule in self.rules:
            if rule["port"] and packet.port == rule["port"]:
                decision = rule["action"]
                reason = f"Rule: Port {rule['port']}"
                break
            if rule["ip"] and packet.src_ip == rule["ip"]:
                decision = rule["action"]
                reason = f"Rule: Block IP {rule['ip']}"
                break

        # 2. ML Filter (Payload check)
        if decision == "ALLOW" and len(packet.payload) > 50:
            decision = "DENY"
            reason = "ML Filter: Payload too large"

        # Update stats
        self.stats[decision] += 1
        return decision, reason

# ===========================
# 2. GUI LAYER
# ===========================

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Rule Simulator")
        self.root.geometry("700x500")
        
        # Initialize Engine
        self.engine = FirewallEngine()
        self.setup_rules()
        self.packet_queue = []

        # --- GUI LAYOUT ---
        
        # Top Frame: Stats
        self.frame_top = tk.Frame(root, bg="#f0f0f0", pady=10)
        self.frame_top.pack(fill="x")
        
        self.lbl_allow = tk.Label(self.frame_top, text="ALLOWED: 0", font=("Arial", 14, "bold"), fg="green", bg="#f0f0f0")
        self.lbl_allow.pack(side="left", padx=20)
        
        self.lbl_deny = tk.Label(self.frame_top, text="BLOCKED: 0", font=("Arial", 14, "bold"), fg="red", bg="#f0f0f0")
        self.lbl_deny.pack(side="left", padx=20)

        # Middle Frame: Controls
        self.frame_controls = tk.Frame(root, pady=5)
        self.frame_controls.pack(fill="x")
        
        self.btn_run = tk.Button(self.frame_controls, text="▶ Run Simulation", command=self.start_simulation, bg="#007acc", fg="white", font=("Arial", 10))
        self.btn_run.pack(side="left", padx=10)
        
        self.btn_clear = tk.Button(self.frame_controls, text="Clear Logs", command=self.clear_logs)
        self.btn_clear.pack(side="left", padx=10)

        # Bottom Frame: Logs
        self.log_area = scrolledtext.ScrolledText(root, height=20, font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_area.tag_config("ALLOW", foreground="green")
        self.log_area.tag_config("DENY", foreground="red")

    def setup_rules(self):
        # Hardcoded rules for demo
        self.engine.add_rule("DENY", port=22)         # Block SSH
        self.engine.add_rule("DENY", ip="10.0.0.5")   # Block Hacker IP

    def generate_packets(self):
        # Create a batch of fake traffic
        return [
            Packet(1, "192.168.1.5", "8.8.8.8", 443, "TCP", "Normal HTTPS"),
            Packet(2, "10.0.0.5", "8.8.8.8", 80, "TCP", "Malicious IP Request"),
            Packet(3, "192.168.1.10", "1.1.1.1", 22, "TCP", "SSH Attempt"),
            Packet(4, "172.16.0.1", "8.8.8.8", 443, "TCP", "A" * 100), # Large payload
            Packet(5, "192.168.1.55", "8.8.8.8", 80, "TCP", "Normal HTTP"),
        ]

    def start_simulation(self):
        self.log_area.insert(tk.END, "\n--- STARTING TRAFFIC BATCH ---\n")
        self.packet_queue = self.generate_packets()
        self.process_next_packet()

    def process_next_packet(self):
        if not self.packet_queue:
            self.log_area.insert(tk.END, "--- BATCH COMPLETE ---\n")
            return

        packet = self.packet_queue.pop(0)
        decision, reason = self.engine.check_packet(packet)
        
        # Log to GUI
        log_msg = f"[{decision}] {packet.src_ip}:{packet.port} -> {reason}\n"
        self.log_area.insert(tk.END, log_msg, decision)
        self.log_area.see(tk.END) # Auto scroll to bottom

        # Update Stats
        self.lbl_allow.config(text=f"ALLOWED: {self.engine.stats['ALLOW']}")
        self.lbl_deny.config(text=f"BLOCKED: {self.engine.stats['DENY']}")

        # Schedule next packet processing (animation effect)
        self.root.after(800, self.process_next_packet)

    def clear_logs(self):
        self.log_area.delete('1.0', tk.END)
        self.engine.stats = {"ALLOW": 0, "DENY": 0}
        self.lbl_allow.config(text="ALLOWED: 0")
        self.lbl_deny.config(text="BLOCKED: 0")

# ===========================
# 3. MAIN ENTRY POINT
# ===========================

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
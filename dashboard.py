import tkinter as tk
from tkinter import ttk, scrolledtext
import random
import time
import threading


class Packet:
    def __init__(self, pkt_id, src_ip, dst_ip, port, protocol, payload):
        self.id = pkt_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = port
        self.protocol = protocol
        self.payload = payload

class FirewallEngine:
    def __init__(self):
        self.rules = []
        
        self.add_rule("DENY", port=22)  
        self.add_rule("DENY", ip="10.0.0.5") 

    def add_rule(self, action, port=None, ip=None):
        self.rules.append({"action": action, "port": port, "ip": ip})

    def analyze_packet(self, packet):
        reason = "Default Policy"
        decision = "ALLOW"

        
        for rule in self.rules:
            if rule["port"] is not None and packet.port == rule["port"]:
                return "DENY", f"Port {rule['port']} Blocked"
            if rule["ip"] is not None and packet.src_ip == rule["ip"]:
                return "DENY", f"IP {rule['ip']} Blacklisted"

        
        if len(packet.payload) > 80:
            return "DENY", "ML: Buffer Overflow Detected"
        if "SQL" in packet.payload:
            return "DENY", "ML: SQL Injection Pattern"

        return "ALLOW", "Traffic Normal"



class FirewallDashboard:
    def __init__(self, root):
        self.root = root

        self.root.title("🛡️ Firewall Simulator")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e") 
        self.engine = FirewallEngine()
        self.is_running = False
        self.packet_count = 0
        self.stats = {"ALLOW": 0, "DENY": 0}

        self.setup_ui()

    def setup_ui(self):
        
        header = tk.Label(self.root, text="NETWORK TRAFFIC SENTINEL", 
                         font=("Consolas", 20, "bold"), bg="#1e1e1e", fg="#00ff00")
        header.pack(pady=10)

        
        stats_frame = tk.Frame(self.root, bg="#2d2d2d", pady=10)
        stats_frame.pack(fill="x", padx=20)

        self.lbl_allowed = tk.Label(stats_frame, text="ALLOWED: 0", font=("Arial", 14, "bold"), bg="#2d2d2d", fg="#4caf50")
        self.lbl_allowed.pack(side="left", padx=40)

        self.lbl_denied = tk.Label(stats_frame, text="BLOCKED: 0", font=("Arial", 14, "bold"), bg="#2d2d2d", fg="#ff5252")
        self.lbl_denied.pack(side="right", padx=40)

        
        content_frame = tk.Frame(self.root, bg="#1e1e1e")
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        
        control_frame = tk.LabelFrame(content_frame, text="Controls & Rules", bg="#1e1e1e", fg="white", font=("Arial", 10))
        control_frame.pack(side="left", fill="y", padx=5)

        self.btn_start = tk.Button(control_frame, text="▶ START TRAFFIC", bg="#008CBA", fg="white", font=("Arial", 11, "bold"), command=self.start_simulation)
        self.btn_start.pack(pady=10, fill="x", padx=10)

        self.btn_stop = tk.Button(control_frame, text="⏹ STOP TRAFFIC", bg="#f44336", fg="white", font=("Arial", 11, "bold"), state="disabled", command=self.stop_simulation)
        self.btn_stop.pack(pady=5, fill="x", padx=10)

        tk.Label(control_frame, text="Add Blocking Rule:", bg="#1e1e1e", fg="white").pack(pady=(20,5))
        
        self.entry_port = tk.Entry(control_frame)
        self.entry_port.insert(0, "Port (e.g. 8080)")
        self.entry_port.pack(pady=5, padx=10)

        btn_add_rule = tk.Button(control_frame, text="+ Block Port", command=self.add_port_rule)
        btn_add_rule.pack(pady=5)

        log_frame = tk.LabelFrame(content_frame, text="Live Packet Inspection Log", bg="#1e1e1e", fg="white")
        log_frame.pack(side="right", fill="both", expand=True, padx=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, bg="#000000", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)

        self.log_area.tag_config("ALLOW", foreground="#00ff00") 
        self.log_area.tag_config("DENY", foreground="#ff3333")  
        self.log_area.tag_config("INFO", foreground="#00ffff")  

    def add_port_rule(self):
        try:
            port = int(self.entry_port.get())
            self.engine.add_rule("DENY", port=port)
            self.log_message(f"[SYSTEM] Added Rule: DENY Port {port}", "INFO")
        except ValueError:
            pass

    def log_message(self, message, tag):
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END) 

    def start_simulation(self):
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.log_message("--- SIMULATION STARTED ---", "INFO")
        

        threading.Thread(target=self.generate_traffic, daemon=True).start()

    def stop_simulation(self):
        self.is_running = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.log_message("--- SIMULATION PAUSED ---", "INFO")

    def generate_traffic(self):
        """Simulates incoming internet traffic endlessly"""
        ips = ["192.168.1.5", "10.0.0.5", "172.16.0.1", "45.33.22.11"]
        ports = [80, 443, 22, 21, 8080, 53]
        payloads = ["GET /index.html", "SSH-Key-Exchange", "Malicious SQL Injection", "Normal Data", "A" * 100]

        while self.is_running:
            self.packet_count += 1
            pkt = Packet(
                self.packet_count,
                random.choice(ips),
                "192.168.1.1",
                random.choice(ports),
                "TCP",
                random.choice(payloads)
            )

            decision, reason = self.engine.analyze_packet(pkt)
            
            
            self.stats[decision] += 1
            self.lbl_allowed.config(text=f"ALLOWED: {self.stats['ALLOW']}")
            self.lbl_denied.config(text=f"BLOCKED: {self.stats['DENY']}")

            
            log_text = f"[{decision}] {pkt.src_ip}:{pkt.port} -> {reason}"
            self.log_message(log_text, decision)

            time.sleep(1.5) 


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallDashboard(root)
    root.mainloop()
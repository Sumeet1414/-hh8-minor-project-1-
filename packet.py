from dataclasses import dataclass

@dataclass
class Packet:
    """
    Represents a single piece of network traffic.
    """
    id: int
    src_ip: str
    dst_ip: str
    port: int
    protocol: str  # TCP, UDP, ICMP
    payload: str
    
    def __repr__(self):
        return f"[Packet #{self.id}] {self.src_ip}:{self.port} -> {self.dst_ip} ({self.protocol})"
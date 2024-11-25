from scapy.all import *
import ifaddr

# send a forged rst packet
def send_rst(p):
    src_ip = p[IP].src
    dst_ip = p[IP].dst
    src_port = p[TCP].sport
    dst_port = p[TCP].dport

    # craft rst packet
    rst_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", seq=p[TCP].ack)

    # send rst packet
    send(rst_pkt, verbose=0)
    print(f"rst packet sent to disrupt connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")

# check if the packet matches the target
def check_packet(client_ip, server_ip, server_port):
    def f(p):
        if p.haslayer(IP) and p.haslayer(TCP):
            # extract details
            src_ip = p[IP].src
            dst_ip = p[IP].dst
            src_port = p[TCP].sport
            dst_port = p[TCP].dport

            # match packet
            if src_ip == server_ip and src_port == server_port and dst_ip == client_ip:
                print(f"packet found: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                send_rst(p)
                return True
        return None  # return none to avoid unnecessary output
    return f

if __name__ == "__main__":
    print("initializing...")
    LOCALHOST = "127.0.0.1"
    TARGET_PORT = 8554

    # find all localhost adapters
    adapters = ifaddr.get_adapters()
    local_ifaces = [adapter.nice_name for adapter in adapters if any(ip.ip == LOCALHOST for ip in adapter.ips)]

    if not local_ifaces:
        print("no localhost adapters found.")
        exit(1)
    
    iface = local_ifaces[0]
    print(f"using interface: {iface}")

    print("sniffing...")
    # sniff packets matching the target conditions
    sniff(
        iface=iface,
        prn=check_packet(LOCALHOST, LOCALHOST, TARGET_PORT),
        store=0,
        lfilter=lambda p: p.haslayer(TCP) and p[IP].dst == LOCALHOST and p[TCP].dport == TARGET_PORT
    )

from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import keyboard

def packet_handler(packet, log_file):
    src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port = "", "", "", "", "", ""

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    print(f"Packet captured - Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}")

    with open(log_file, 'a') as f:
        f.write(f"Source: {src_ip}:{src_port}, Destination: {dst_ip}:{dst_port}\n")

if __name__ == "__main__":
    protocol_filter = input("Enter protocol filter (e.g., tcp, udp, icmp, or 'all' for all protocols): ").lower()
    src_ip_filter = input("Enter source IP filter (or 'all' for any source): ")
    dst_ip_filter = input("Enter destination IP filter (or 'all' for any destination): ")
    src_port_filter = input("Enter source port filter (or 'all' for any source port): ")
    dst_port_filter = input("Enter destination port filter (or 'all' for any destination port): ")

    log_file = input("Enter the name of the log file (default is 'packet_log.txt'): ") or 'packet_log.txt'

    def filter_packets(packet):
        if protocol_filter != 'all' and packet.haslayer(protocol_filter) is False:
            return False
        if src_ip_filter != 'all' and IP in packet and packet[IP].src != src_ip_filter:
            return False
        if dst_ip_filter != 'all' and IP in packet and packet[IP].dst != dst_ip_filter:
            return False
        if src_port_filter != 'all' and (TCP in packet or UDP in packet) and packet.sport != int(src_port_filter):
            return False
        if dst_port_filter != 'all' and (TCP in packet or UDP in packet) and packet.dport != int(dst_port_filter):
            return False
        return True

    sniffing_active = True

    def sniff_packets():
        sniff(prn=lambda pkt: packet_handler(pkt, log_file) if filter_packets(pkt) else None, store=0)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.start()

    while sniffing_active:
        if keyboard.is_pressed('esc'):
            sniffing_active = False
            print("Exiting packet sniffing...")
            break

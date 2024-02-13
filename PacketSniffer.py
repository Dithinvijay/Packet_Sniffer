from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import keyboard

if __name__ == "__main__":
    protocol_filter = input("Enter protocol filter (e.g., tcp, udp, icmp, or 'all' for all protocols): ").lower()
    src_ip_filter = input("Enter source IP filter (or 'all' for any source): ")
    dst_ip_filter = input("Enter destination IP filter (or 'all' for any destination): ")
    src_port_filter = input("Enter source port filter (or 'all' for any source port): ")
    dst_port_filter = input("Enter destination port filter (or 'all' for any destination port): ")

    log_file = input("Enter the name of the log file (default is 'packet_log.txt'): ") or 'packet_log.txt'

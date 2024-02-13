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

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

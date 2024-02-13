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

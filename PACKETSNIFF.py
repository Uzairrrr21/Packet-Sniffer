from scapy.all import sniff, IP, Raw

def packet_analysis(packet):
    try:
        # Check if packet is IPv4
        if packet.haslayer(IP):
            # Get source and destination IP addresses
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            # Get protocol
            protocol = packet[IP].proto

            # Check if Raw layer exists
            if packet.haslayer(Raw):
                payload = packet[Raw].load
            else:
                payload = ""  # Set payload to an empty string if not present

            # Prepare packet information
            packet_info = (f"Source IP: {source_ip}\n"
                           f"Destination IP: {destination_ip}\n"
                           f"Protocol: {protocol}\n"
                           f"Payload: {repr(payload)}\n"
                           "--------------------------------\n")

            # Write packet information to file
            with open("packet_log.txt", "a") as log_file:
                log_file.write(packet_info)
                
    except Exception as e:
        print(f"An error occurred: {e}")

# Start sniffing
sniff(filter="ip", prn=packet_analysis)

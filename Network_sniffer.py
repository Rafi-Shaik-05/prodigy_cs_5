from scapy.all import sniff

# Function to display packet information
def packet_callback(packet):
    if packet.haslayer('IP'):
        ip_layer = packet.getlayer('IP')
        print(f'Source IP: {ip_layer.src}')
        print(f'Destination IP: {ip_layer.dst}')
        print(f'Protocol: {ip_layer.proto}')
        if packet.haslayer('Raw'):
            payload = packet.getlayer('Raw').load
            print(f'Payload: {payload}')
        print('-' * 50)

# Capture and display 10 packets
sniff(prn=packet_callback, count=10)

# Function to save packet information to a file
def packet_callback_to_file(packet):
    with open('packets.txt', 'a') as f:
        if packet.haslayer('IP'):
            ip_layer = packet.getlayer('IP')
            f.write(f'Source IP: {ip_layer.src}\n')
            f.write(f'Destination IP: {ip_layer.dst}\n')
            f.write(f'Protocol: {ip_layer.proto}\n')
            if packet.haslayer('Raw'):
                payload = packet.getlayer('Raw').load
                f.write(f'Payload: {payload}\n')
            f.write('-' * 50 + '\n')

# Capture and save 10 packets to a file
sniff(prn=packet_callback_to_file, count=10)

# Capture and display TCP packets only
sniff(filter='tcp', prn=packet_callback, count=10)

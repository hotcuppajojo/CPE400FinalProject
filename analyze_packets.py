import sys
import pandas as pd
from scapy.all import rdpcap, TCP, IP

def analyze_packets(file_name):
    try:
        # Load the pcap file
        packets = rdpcap(file_name)

        # List to store packet details
        packet_data = []
        log_data = []

        # Analyze each packet
        for packet in packets:
            if IP in packet and TCP in packet:
                try:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    payload = bytes(packet[TCP].payload)  # Keep payload as bytes

                    # Try to decode the payload in multiple ways
                    decoded = False
                    payload_text = ""
                    try:
                        # Try decoding as UTF-8 text
                        payload_text = payload.decode('utf-8')
                        decoded = True
                    except UnicodeDecodeError:
                        try:
                            # If that fails, try decoding as ASCII text
                            payload_text = payload.decode('ascii', errors='ignore')
                            decoded = True
                        except UnicodeDecodeError:
                            # If that also fails, keep the hexadecimal representation
                            payload_text = payload.hex()

                    # New Protocol Identification Logic
                    if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                        protocol = "HTTP"
                    elif src_port == 8009 or dst_port == 8009:
                        protocol = "Google Cast"  # Since port 8009 is often used for Google Cast
                    elif src_port == 32038 or dst_port == 32038:
                        protocol = "Custom Protocol"  # Label it as custom for further manual investigation
                    elif "TLS" in payload_text or "SSL" in payload_text or src_port == 443 or dst_port == 443:
                        protocol = "TLS/SSL"
                    else:
                        protocol = "Unknown"

                    # Detailed logging for each packet
                    log_entry = f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} - Protocol: {protocol}, Decoded: {decoded}"
                    log_data.append(log_entry)

                    # Store packet information if there's data in the payload
                    if payload:  # Check if the payload is non-empty
                        packet_data.append({
                            'Source IP': src_ip,
                            'Source Port': src_port,
                            'Destination IP': dst_ip,
                            'Destination Port': dst_port,
                            'Payload': payload_text,
                            'Protocol': protocol,
                            'Decoded': decoded
                        })

                except Exception as e:
                    # Log the error and continue processing
                    log_data.append(f"Error processing packet: {e}")
                    continue

        # Convert the packet data to a DataFrame for easy analysis
        df = pd.DataFrame(packet_data)

        # Save the DataFrame to a CSV file for review
        output_file = f'{file_name}_analysis.csv'
        df.to_csv(output_file, index=False)

        # Save the log to a file
        log_file = f'{file_name}_log.txt'
        with open(log_file, 'w') as log_f:
            for entry in log_data:
                log_f.write(f"{entry}\n")

        # Print a summary of the findings
        if not df.empty:
            print(f"Found {len(df)} packets with data.")
            print(df[['Source IP', 'Destination IP', 'Payload', 'Protocol', 'Decoded']].head(10))  # Display the first 10 packets
        else:
            print("No data found in the packets.")

        print(f"Analysis saved to {output_file}")
        print(f"Log saved to {log_file}")

    except Exception as e:
        print(f"Failed to analyze packets: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_packets.py <pcap_file>")
    else:
        pcap_file = sys.argv[1]
        analyze_packets(pcap_file)

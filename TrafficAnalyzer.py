from scapy.all import sniff, IP, TCP
from collections import defaultdict
class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time

            stats['last_time'] = current_time

            # print('Last time:', stats['last_time'])
            # print('Start time:', stats['start_time'])
            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        flow_duration = stats['last_time'] - stats['start_time']
        
        # Handle zero or negative flow duration to avoid division by zero
        if flow_duration <= 0:
            flow_duration = 1  # Use a small non-zero value (1 microsecond)
        
        return {
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': stats['packet_count'] / flow_duration,
            'byte_rate': stats['byte_count'] / flow_duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }
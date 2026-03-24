from scapy.all import sniff, IP, TCP, ARP
from scapy.all import IP, TCP, ARP, Ether, srp

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
        self.src_ports = defaultdict(set)

    def mac(self, ipadd):
        arp_request = ARP(pdst=ipadd)
        br = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_br = br / arp_request
        list_1 = srp(arp_req_br, timeout=5, verbose=False)[0]
        return list_1[0][1].hwsrc

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
                    
            self.src_ports[ip_src].add(port_dst)

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

        elif packet.haslayer(ARP) and packet[ARP].op == 2:
            print("ARP Spoofing detected!")
            return self.extract_for_layer2(packet)
        

    def extract_for_layer2(self, packet):
        return {
            'src_ip': 0,
            'src_port':0,
            'dst_port':0,
            'dst_ip': 0,
            'packet_size':0,
            'flow_duration': 0,
            'packet_rate': 0,
            'byte_rate':0,
            'tcp_flags': 0,
            'window_size': 0,
            'unique_ports': 0,
            'orginalmac': packet[ARP].hwsrc,
            'responsemac': packet[ARP].psrc
    }
    
    def extract_features(self, packet, stats):
        ip_src = packet[IP].src
        flow_duration = stats['last_time'] - stats['start_time']
        
        # Handle zero or negative flow duration to avoid division by zero
        if flow_duration <= 0:
            flow_duration = 1  # Use a small non-zero value (1 microsecond)
        return {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': stats['packet_count'] / flow_duration,
            'byte_rate': stats['byte_count'] / flow_duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window,
            'unique_ports': len(self.src_ports[ip_src]),
            'orginalmac': None,
            'responsemac': None
        }
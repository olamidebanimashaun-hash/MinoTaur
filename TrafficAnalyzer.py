from scapy import packet
from scapy.all import IP, TCP, ARP, UDP, Ether, srp, Raw
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
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.src_ports = defaultdict(set)

    def flush_all_flows(self):
        results = []

        for key, stats in list(self.flow_stats.items()):
            duration = stats['last_time'] - stats['start_time']

            if duration <= 0:
                duration = 1  # avoid division by zero

            avg_packet_size = stats['byte_count'] / stats['packet_count']

            avg_window = (
                sum(stats['window_size']) / len(stats['window_size'])
                if stats['window_size'] else 0
            )

            features = {
                'src_ip': stats['src_ip'],
                'dst_ip': stats['dst_ip'],
                'src_port': stats['port_src'],
                'dst_port': stats['port_dst'],
                'protocol': stats['protocol'],
                'packet_size': avg_packet_size,
                'flow_duration': duration,
                'packet_count': stats['packet_count'],
                'packet_rate': stats['packet_count'] / duration,
                'byte_rate': stats['byte_count'] / duration,
                'tcp_flags': stats['tcp_flags'],
                'window_size': avg_window,
                'unique_ports': len(self.src_ports.get(stats['src_ip'], [])),
                'info': stats['info'],
                'orginalmac': None,
                'responsemac': None
            }

            results.append(features)
            del self.flow_stats[key]

        return results
    
    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')
    
    def get_mac(ip):
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            return None
        
    def get_flow_key(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            return (
                packet[IP].src,
                packet[IP].dst,
                packet[TCP].sport,
                packet[TCP].dport
            )
        return None
    
    def analyze_packet(self, packet):
        if IP in packet and (TCP in packet or UDP in packet):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            if TCP in packet:
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport     
                tcp_flags = packet[TCP].flags

            elif UDP in packet:
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport    

            payload_text = ""
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    payload_text = payload.decode(errors="ignore")
                except:
                    payload_text = ""
                
                try:
                    payload_text = payload.decode(errors="ignore")
                except:
                    pass   
 
            self.src_ports[ip_src].add(port_dst)
            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['tcp_flags'] = tcp_flags if TCP in packet else None
            stats['port_src'] = port_src
            stats['port_dst'] = port_dst
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            stats['info'] = payload_text if packet.haslayer(Raw) else ""
            current_time = packet.time
            if not stats['start_time']:
                stats['start_time'] = current_time

            stats['last_time'] = current_time

            if stats['packet_count'] == 1:
                stats['src_ip'] = ip_src
                stats['dst_ip'] = ip_dst
                stats['protocol'] = self.get_protocol_name(packet[IP].proto)


            if TCP in packet:
                stats['window_size']  = []
                stats['window_size'].append(packet[TCP].window)

            # print('Last time:', stats['last_time'])
            # print('Start time:', stats['start_time'])
            duration = stats['last_time'] - stats['start_time']
            if current_time - stats['last_time'] > 30:
                del self.flow_stats[flow_key]

            if stats['packet_count'] >= 10 or duration > 5:
                features = self.extract_features(packet, stats)
                del self.flow_stats[flow_key]  # reset flow
                return features
            
            return None
        elif packet.haslayer(ARP) and packet[ARP].op == 2:
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
            'src_port': stats['port_src'] ,
            'dst_port': stats['port_dst'] ,
            'protocol': self.get_protocol_name(packet[IP].proto),
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_count': stats['packet_count'],
            'packet_rate': stats['packet_count'] / flow_duration,
            'byte_rate': stats['byte_count'] / flow_duration,
            'tcp_flags': stats['tcp_flags'],
            'window_size': packet[TCP].window if TCP in packet else 0,
            'unique_ports': len(self.src_ports[ip_src]),
            'info': stats['info'],
            'orginalmac': None,
            'responsemac': None
        }
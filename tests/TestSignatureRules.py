import unittest
from unittest.mock import Mock
import time
from MinoTaur import IDS

class TestSignatureRules(unittest.TestCase):
    def setUp(self):
        self.ids = IDS()
        self.detection_engine = self.ids.detection_engine
    
    def test_syn_flood_detection(self):
        features = {
            'tcp_flags': 0x02,           # SYN flag
            'packet_rate': 150,          # High rate
            'unique_ports': 2,
            'flow_duration': 1.0,
            'packet_size': 64,
            'byte_rate': 10000,
            'window_size': 65535,
            'src_ip': '10.0.0.1',
            'dst_ip': '192.168.1.2',
            'orginalmac': None,
            'responsemac': None
        }
        threats = self.detection_engine.detect_threats(features)
        
        self.assertTrue(any(t['type'] == 'signature' and t['rule'] == 'syn_flood' for t in threats),"SYN flood should be detected")

    def test_port_scan_detection(self):
        features = {
            'tcp_flags': 0x02,
            'packet_rate': 5,            # Slow scanning
            'unique_ports': 15,          # Many ports
            'flow_duration': 10.0,       # Extended period
            'packet_size': 64,
            'byte_rate': 320,
            'window_size': 65535,
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.2',
            'orginalmac': None,
            'responsemac': None
        }
        threats = self.detection_engine.detect_threats(features)

        self.assertTrue(any(t['rule'] == 'port_scan' for t in threats), "Port scan should be detected")
    
    def test_normal_traffic_no_false_positives(self):
        features = {
            'tcp_flags': 0x10,           # ACK flag (normal)
            'packet_rate': 2,
            'unique_ports': 1,
            'flow_duration': 0.5,
            'packet_size': 1500,
            'byte_rate': 3000,
            'window_size': 65535,
            'src_ip': '192.168.1.5',
            'dst_ip': '192.168.1.10',
            'orginalmac': None,
            'responsemac': None
        }
        
        threats = self.detection_engine.detect_threats(features)
        
        signature_threats = [t for t in threats if t['type'] == 'signature']
        self.assertEqual(len(signature_threats), 0, "Normal traffic should not trigger signatures")

if __name__ == '__main__':
    unittest.main()
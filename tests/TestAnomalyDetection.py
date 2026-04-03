import sys
# setting path
sys.path.append('../')
import unittest
from unittest.mock import Mock
import time
from MinoTaur import MinoTaur

class TestSignatureRules(unittest.TestCase):
    def setUp(self):
        self.ids = MinoTaur()
        self.detection_engine = self.ids.detection_engine
    
    def test_anomaly_detection(self):
        features = {
            'tcp_flags': 0x02,           # SYN flag
            'packet_rate': 150,          # High rate
            'unique_ports': 2,
            'flow_duration': 999.0,
            'packet_size': 999,
            'byte_rate': 10000,
            'window_size': 65535,
            'src_port': 1024,
            'dst_port': 80,
            'orginalmac': None,
            'responsemac': None
        }
        threats = self.detection_engine.detect_threats(features, path="../Data/xgb_model.pkl")
        
        self.assertTrue(any(t['type'] == 'anomaly' for t in threats),"Anomaly should be detected")

if __name__ == '__main__':
    unittest.main()
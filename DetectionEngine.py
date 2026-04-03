from pathlib import Path
from pyexpat import features

from sklearn.ensemble import IsolationForest
import numpy as np
import joblib
np.set_printoptions(legacy='1.25')
class DetectionEngine:
    def __init__(self):
        self.signature_rules = self.load_signature_rules()

    #add more signauture rules as learn about attack patterns, keep them basic
    def load_signature_rules(self):
        return {
            'syn_flood': {
                'description': 'Multiple SYN packets from same source to same dest',
                'condition': lambda f: (
                    (f['tcp_flags'] == 2) and  # Check SYN flag specifically
                    f['packet_rate'] > 100 and        # Tuned threshold
                    f['unique_ports'] <= 3            # Targeting few ports
                ),
                'severity': 'high',
                'confidence_base': 0.8
            },
            'slowloris':{
                'description': 'A large number of small packets over a long duration',
                'condition': lambda f: (
                    f['packet_rate'] > 50 and
                    f['byte_rate'] > 500 and     
                    f['flow_duration'] > 10          
                ),
                'severity': 'critical',
                'confidence_base': 0.95
            },
            'ddos': {
                'description': 'High volume traffic from multiple sources',
                'condition': lambda f: (
                    f['packet_rate'] > 500 and
                    f['byte_rate'] > 5000 and     
                    f['flow_duration'] > 2          
                ),
                'severity': 'critical',
                'confidence_base': 0.95
            },
            'port_scan': {
                'description': 'Sequential scans to multiple high-numbered ports',
                'condition': lambda f: (
                    f['unique_ports'] > 10 and       # Increased threshold
                    f['packet_rate'] < 10 and        # Slow scanning
                    f['flow_duration'] > 5           # Over time period
                ),
                'severity': 'medium',
                'confidence_base': 0.7
            },
            'ssh_brute_force': {
                'description': 'Rapid connections to SSH port',
                'condition': lambda f: (
                    f['dst_port'] == 22 and
                    f['packet_rate'] > 50 and
                    f['flow_duration'] < 30
                ),
                'severity': 'high',
                'confidence_base': 0.75
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threats(self, features, path="Data/xgb_model.pkl"):
        threats = []
        features.setdefault('dst_port', 0)
        features.setdefault('src_port', 0)

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': rule['confidence_base']
                })

        # Anomaly-based detection
        feature_vector = np.array([[
            features['src_port'],
            features['packet_size'],
            features['flow_duration']
        ]])
        loaded_model = joblib.load(path)

        anomaly_score = loaded_model.predict_proba(feature_vector)[0, 1]  # probability for positive class
        threshold = 0.1
        print(anomaly_score)
        #print(f"Anomaly score: {anomaly_score:.4f}")
        if anomaly_score > threshold:  # Threshold for anomaly detection tweaked for better sensitivity and try different values
            threats.append({
                'type': 'anomaly',
                'score': threshold,
                'confidence': abs(anomaly_score) / 10
            })

        return threats
import time
import random
from scapy.all import IP, TCP, Raw
from MinoTaur import MinoTaur

def run_test(test_name, packets, ids):
    print(f"\n=== Running Test: {test_name} ===")

    # Feed packets
    for packet in packets:
        ids.traffic_analyzer.analyze_packet(packet)

    features_list = ids.traffic_analyzer.flush_all_flows()

    if not features_list:
        print("No flows generated")
        return

    detections = []

    for features in features_list:
        threats = ids.detection_engine.detect_threats(features)

        if threats:
            detections.extend(threats)

    if detections:
        print(f"Detected: {detections}")
    else:
        print("No threats detected")

def generate_syn_flood():
    packets = []
    base_time = time.time()

    for i in range(50):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(
            sport=random.randint(1024, 65535),
            dport=80,
            flags="S"
        )
        p.time = base_time + i * 0.001
        packets.append(p)

    return packets

def generate_port_scan():
    packets = []
    base_time = time.time()

    for port in range(20, 100):
        p = IP(src="192.168.1.100", dst="192.168.1.2") / TCP(
            sport=4444,
            dport=port,
            flags="S"
        )
        p.time = base_time + port * 0.01
        packets.append(p)

    return packets

def generate_normal():
    return [
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S"),
        IP(src="192.168.1.2", dst="192.168.1.10") / TCP(sport=80, dport=1234, flags="SA"),
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
    ]

def generate_payload_attack():
    return [
        IP(src="192.168.1.50", dst="192.168.1.2") /
        TCP(sport=5555, dport=80, flags="PA") /
        Raw(load=b"POST /login password=admin"),

        IP(src="192.168.1.50", dst="192.168.1.2") /
        TCP(sport=5555, dport=80, flags="PA") /
        Raw(load=b"GET /?cmd=whoami"),
    ]
def test_ids():
    ids = MinoTaur()
    #run_test("Normal Traffic", generate_normal(), ids)
    run_test("SYN Flood", generate_syn_flood(), ids)
  #  run_test("Port Scan", generate_port_scan(), ids)
   # run_test("Payload Attack", generate_payload_attack(), ids)
if __name__ == "__main__":
    test_ids()
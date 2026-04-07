import random
from scapy.all import IP, TCP, ARP, UDP, Ether, srp, Raw
from scapy.sendrecv import send
from scapy.all import RandShort

from MinoTaur import MinoTaur
import time
def run_test(test_name, packets, ids):
    print(f"\n=== Running Test: {test_name} ===")

    # Feed packets
    for packet in packets:
        ids.traffic_analyzer.analyze_packet(packet)

    # Force flow completion
    features_list = ids.traffic_analyzer.flush_all_flows()

    if not features_list:
        print("❌ No flows generated")
        return

    detections = []

    for features in features_list:
        threats = ids.detection_engine.detect_threats(features)

        if threats:
            detections.extend(threats)

    if detections:
        print(f"✅ Detected: {detections}")
    else:
        print("❌ No threats detected")
def test_ids():
    # Create test packets to simulate various scenarios
    base_time = time.time()
    
    # Normal traffic
    normal_packets = [
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S"),
        IP(src="192.168.1.2", dst="192.168.1.10") / TCP(sport=80, dport=1234, flags="SA"),
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.10", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="PA") / Raw(load=b"GET / HTTP/1.1"),
    ]
    
    # SYN flood simulation - many SYNs from same source in short time
    syn_flood_packets = []
    for j in range(200):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(
            sport=random.randint(1024, 65535),
            dport=80,
            flags="S"
        )
        p.time = base_time + random.uniform(0, 0.5)
        syn_flood_packets.append(p)

    fyn_packets = []
    for j in range(100):  # Increase for flood simulation
        p = IP(src=f"10.0.0.{j % 255}", dst="192.168.1.2") / TCP(sport=(random.randrange(1,6700)), dport=80, flags="S")
        p.time = base_time + j * 0.001
        fyn_packets.append(p)

    # Port scan simulation
    port_scan_packets = []
    for port in range(20, 200):
        p = IP(src="192.168.1.100", dst="192.168.1.2") / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S"
        )
        p.time = base_time + port * 0.01
        port_scan_packets.append(p)

    vanilla_packets = []
    for j in range(100):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=j, flags="S")
        vanilla_packets.append(p)

    suspicious_payload_packets = [
        IP(src="192.168.1.100", dst="192.168.1.2") /
        TCP(sport=4321, dport=80, flags="PA") /
        Raw(load=b"POST /login password=admin123"),

        IP(src="192.168.1.100", dst="192.168.1.2") /
        TCP(sport=4321, dport=80, flags="PA") /
        Raw(load=b"GET /?cmd=whoami"),
    ]

    ddos_packets = []
    for j in range(300):
        p = IP(src=f"10.0.0.{random.randint(1,254)}", dst="192.168.1.2") / TCP(
            sport=random.randint(1024, 65535),
            dport=80,
            flags="S"
        )
        p.time = base_time + random.uniform(0, 1)
        ddos_packets.append(p)


    ids = MinoTaur()
    test_packets = normal_packets + syn_flood_packets  + port_scan_packets

    attackDitctionary = {
        'nor':   normal_packets ,
        'dsyn':   syn_flood_packets  ,
        'fsyn':   fyn_packets  ,
        'pscan': port_scan_packets,
        'all':      test_packets,
        'vanilla': vanilla_packets,
        'ddos': ddos_packets,
        'susi': suspicious_payload_packets
    }

    print('Enter the type of attack to test (nor,dsyn,pscan,all):')
    for attackType in attackDitctionary.keys():
        print(f"- {attackType}")
    attackInput = input()


    if attackInput in attackDitctionary:
        print(f"\nProcessing {attackInput} attack packets:")
        for i, packet in enumerate(attackDitctionary[attackInput], 1):
            ids.traffic_analyzer.analyze_packet(packet)

            # Force flow completion
            features_list = ids.traffic_analyzer.flush_all_flows()

            if not features_list:
                print("❌ No flows generated")
                return

            detections = []

            for features in features_list:
                threats = ids.detection_engine.detect_threats(features)

                if threats:
                    detections.extend(threats)

            if detections:
                print(f"✅ Detected: {detections}")
            else:
                print("❌ No threats detected")
        print("\nIDS Test Completed.")
    else:
        print("Invalid attack type entered.")


    
if __name__ == "__main__":
    test_ids()
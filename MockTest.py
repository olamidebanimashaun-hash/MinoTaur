import random
from scapy.all import IP, TCP, ARP, UDP, Ether, srp, Raw
from scapy.sendrecv import send
from scapy.all import RandShort

from MinoTaur import MinoTaur
import time
def test_ids():
    # Create test packets to simulate various scenarios
    base_time = time.time()
    
    # Normal traffic
    normal_packets = [
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="A"),
    ]
    
    # SYN flood simulation - many SYNs from same source in short time
    syn_packets = []
    for j in range(5):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S")
        p.time = base_time + j * 0.001  # 1ms apart
        syn_packets.append(p)

    fyn_packets = []
    for j in range(100):  # Increase for flood simulation
        p = IP(src=f"10.0.0.{j % 255}", dst="192.168.1.2") / TCP(sport=(random.randrange(1,6700)), dport=80, flags="S")
        p.time = base_time + j * 0.001
        fyn_packets.append(p)

    # Port scan simulation
    port_scan_packets = [
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]
    vanilla_packets = []
    for j in range(100):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=j, flags="S")
        vanilla_packets.append(p)

    suspicious_payload_packets = [
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=80, flags="S") / Raw(load=b"password=secret"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=443, flags="S") / Raw(load=b"login=admin"),
    ]


    ids = MinoTaur()
    test_packets = normal_packets + syn_packets  + port_scan_packets

    attackDitctionary = {
        'nor':   normal_packets ,
        'dsyn':   syn_packets  ,
        'fsyn':   fyn_packets  ,
        'pscan': port_scan_packets,
        'all':      test_packets,
        'vanilla': vanilla_packets,
        'susi': suspicious_payload_packets
    }
    print('Enter the type of attack to test (nor,dsyn,pscan,all):')
    for attackType in attackDitctionary.keys():
        print(f"- {attackType}")
    attackInput = input()

    if attackInput in attackDitctionary:
        print(f"\nProcessing {attackInput} attack packets:")
        for i, packet in enumerate(attackDitctionary[attackInput], 1):
            print(f"\nProcessing packet {i}: {packet.summary()}")

            # Analyze the packet
            features = ids.traffic_analyzer.analyze_packet(packet)
            #print(f"Extracted features: {features}")
            if features:
                # Detect threats based on features
                threats = ids.detection_engine.detect_threats(features)

                if threats:
                    print(f"Detected threats: {threats}")
                else:
                    print("No threats detected.")
            else:
                print("Packet does not contain IP/TCP layers or is ignored.")
        print("\nIDS Test Completed.")
    elif attackInput == 'everything':
        print("\nProcessing all attack packets:")
        for attackType, packets in attackDitctionary.items():
            print(f"\nProcessing {attackType} attack packets:")
            for i, packet in enumerate(packets, 1):
                print(f"\nProcessing packet {i}: {packet.summary()}")

                # Analyze the packet
                features = ids.traffic_analyzer.analyze_packet(packet)

                if features:
                    # Detect threats based on features
                    threats = ids.detection_engine.detect_threats(features)

                    if threats:
                        print(f"Detected threats: {threats}")
                    else:
                        print("No threats detected.")
                else:
                    print("Packet does not contain IP/TCP layers or is ignored.")
        print("\nIDS Test Completed.") 
    else:
        print("Invalid attack type entered.")


    
if __name__ == "__main__":
    test_ids()
import random
from scapy.all import IP, TCP, ARP, Ether, srp
from scapy.sendrecv import send
from scapy.all import RandShort

from IDS import IDS
import time
# def get_mac(ip):
#     arp_request = ARP(pdst = ip)
#     broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
#     arp_request_broadcast = broadcast / arp_request
#     answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
#     return answered_list[0][1].hwsrc

# def spoof(target_ip, spoof_ip):
#     packet = ARP(op = 2, pdst = target_ip, hwdst = get_mac(target_ip),psrc = spoof_ip)
#     return packet

# def arp_spoof_once(victim_ip, gateway_ip):
#     victim_mac = get_mac(victim_ip)
#     spoof_pkt = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip)
#     send(spoof_pkt, verbose=False)
#     return spoof_pkt

def test_ids():
    # Create test packets to simulate various scenarios
    base_time = time.time()
    
    # Normal traffic
    normal_packets = [
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),
    ]
    
    # SYN flood simulation - many SYNs from same source in short time
    syn_packets = []
    for j in range(5):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S")
        p.time = base_time + j * 0.001  # 1ms apart
        syn_packets.append(p)

    fyn_packets = []
    for j in range(100):  # Increase for flood simulation
        p = IP(src=f"10.0.0.{j % 255}", dst="192.168.1.2") / TCP(sport=(random.randrange(1,6800)), dport=80, flags="S")
        p.time = base_time + j * 0.001
        fyn_packets.append(p)

    spoof_syn = [
        Ether(dst="00:11:22:33:44:55") / ARP(op=2, pdst="192.168.1.2", hwdst="00:11:22:33:44:55", psrc="192.168.1.1"),
        Ether(dst="00:11:22:33:44:55") / ARP(op=2, pdst="192.168.1.2", hwdst="00:11:22:33:44:55", psrc="192.168.1.1"),
        Ether(dst="00:11:22:33:44:55") / ARP(op=2, pdst="192.168.1.2", hwdst="00:11:22:33:44:55", psrc="192.168.1.1")
    ]

    # Port scan simulation
    port_scan_packets = [
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]
    vanilla_packets = []
    for j in range(65,536):
        p = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=j, flags="S")
        vanilla_packets.append(p)

    ids = IDS()

    # # Simulate packet processing and threat detection
    # print("Starting IDS Test...")
    # for i, packet in enumerate(test_packets, 1):
    #     print(f"\nProcessing packet {i}: {packet.summary()}")

    #     # Analyze the packet
    #     features = ids.traffic_analyzer.analyze_packet(packet)

    #     if features:
    #         # Detect threats based on features
    #         threats = ids.detection_engine.detect_threats(features)

    #         if threats:
    #             print(f"Detected threats: {threats}")
    #         else:
    #             print("No threats detected.")
    #     else:
    #         print("Packet does not contain IP/TCP layers or is ignored.")

    # print("\nIDS Test Completed.")
    test_packets = normal_packets + syn_packets  + port_scan_packets

    attackDitctionary = {
        'nor':   normal_packets ,
        'dsyn':   syn_packets  ,
        'fsyn':   fyn_packets  ,
        'pscan': port_scan_packets,
        'all':      test_packets,
        'vanilla': vanilla_packets,
        'spoof': spoof_syn
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
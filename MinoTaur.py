from PacketCapture import PacketCapture 
from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem
from scapy.all import IP, TCP
import queue
iface = "\\Device\\NPF_Loopback"
class MinoTaur:
    def __init__(self, interface=iface):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        self.alert_system.generate_alert(threat, features)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = MinoTaur()
    ids.start()
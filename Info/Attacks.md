## SYN flood attack
A SYN flood exploits a vulnerability in the TCP/IP handshake in an attempt to disrupt a web service.

This works by

1. The client sends a SYN packet to the server in order to initiate the connection.

2. The server then repsonds to that intital packetr with a SYN/ACK packer in order to acknlowdge the communciation

3. The client returns an ACK packet to acknowledge the receipt of the packet from the server.

4. After completing this sequence of packet sending and receiving, the TCP connection is open and able to send and receive data.

Can occur in three different ways:
- Direct Attack - This is where the IP address is not spoofed. This attack does not mask their IP address at all. The hacker prevents their machine from responding to server SYN-ACK packets. This is often achieved by firewall rules that stop outgoing packets other than SYN packets or by filtering out any incoming SYN-ACK packets before they reach the malicious user's machine. This method is rarely used, as mitigation is straightforward.

- DDoS -  an attack is created using abotnet the likelihood of tracking said attack back to its source is low. The attacker may also sppof their ip address.

- Spoofed Attack - A user spoof their ip address on erach SYN packet they send in order to inhibit the mitigation efforts and make their identity more difficult to discover




## Port scan 

A port scan is a common technique hackers use to discover open doors or weak points in a network. 

- Ping scans - considred the simplest port scan technique, ping scans send a group of several ICMP request to varous servers in an attempt to get a repsonse

- At attempts to connect to all of the 65536 ports at the same time, it sends a synchronizing (SYN) flag. When it receives a SYN-ACK response or an acknowledgment of connection, it responds with an ACK flag.

- XMAS - Sends a set of flags which, when responded to, can disclose insights about the firewall and the state of the ports.

- FIN - Scans see an attacker send a FIN flag, often used to end an established session to a specific port. The system's response to it can help the attacker understand the level of activity and provide insight into the organization's firewall usage.

## Fragmentation

## Malware

## Exploits
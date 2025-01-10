import ipaddress
import logging
import json
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import random
from dataclasses import dataclass
from typing import List, Dict
from collections import Counter

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler("firewall_simulation.log"),
        logging.StreamHandler()
    ]
)

@dataclass
class NetworkPacket:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    payload: str
    
    @classmethod
    def generate_random_packet(cls):
        protocols = ['TCP', 'UDP', 'ICMP']
        packet = cls(
            source_ip=str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))),
            destination_ip=str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))),
            source_port=random.randint(1024, 65535),
            destination_port=random.randint(1, 1023),
            protocol=random.choice(protocols),
            payload=''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=20))
        )
        logging.debug(f"Generated packet: {packet}")
        return packet

class FirewallRule:
    def __init__(self, source_ip=None, destination_ip=None, 
                 source_port=None, destination_port=None, 
                 protocol=None, action='block'):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol
        self.action = action

class Firewall:
    def __init__(self, rules: List[FirewallRule]):
        self.rules = rules
        self.packet_log = []
        self.blocked_packets = []
        self.allowed_packets = []
        
    def filter_packet(self, packet):
        """Check packet against firewall rules."""
        for rule in self.rules:
            matches = [
                not rule.source_ip or rule.source_ip == packet.source_ip,
                not rule.destination_ip or rule.destination_ip == packet.destination_ip,
                not rule.source_port or rule.source_port == packet.source_port,
                not rule.destination_port or rule.destination_port == packet.destination_port,
                not rule.protocol or rule.protocol == packet.protocol
            ]
            
            if all(matches):
                if rule.action == 'block':
                    self.blocked_packets.append(packet)
                    logging.info(f"Packet blocked: {packet}")
                    return False
        
        self.allowed_packets.append(packet)
        logging.info(f"Packet allowed: {packet}")
        return True

class LogAnalyzer:
    @staticmethod
    def analyze_logs(firewall):
        """Comprehensive log analysis."""
        def protocol_breakdown(packets):
            return dict(Counter(p.protocol for p in packets))
        
        def port_breakdown(packets):
            return dict(Counter(p.destination_port for p in packets))
        
        analysis = {
            'total_packets': len(firewall.packet_log),
            'blocked_packets': len(firewall.blocked_packets),
            'allowed_packets': len(firewall.allowed_packets),
            'blocked_by_protocol': protocol_breakdown(firewall.blocked_packets),
            'allowed_by_protocol': protocol_breakdown(firewall.allowed_packets),
            'blocked_by_port': port_breakdown(firewall.blocked_packets),
            'allowed_by_port': port_breakdown(firewall.allowed_packets),
            'block_percentage': len(firewall.blocked_packets) / (len(firewall.blocked_packets) + len(firewall.allowed_packets)) * 100
        }
        logging.debug(f"Log analysis results: {analysis}")
        return analysis

class Visualizer:
    @staticmethod
    def plot_comprehensive_analysis(log_analysis):
        """Create multi-panel visualization of firewall analysis."""
        plt.figure(figsize=(16, 10))
        
        # Packet Distribution
        plt.subplot(2, 2, 1)
        plt.pie(
            [log_analysis['blocked_packets'], log_analysis['allowed_packets']], 
            labels=['Blocked', 'Allowed'], 
            autopct='%1.1f%%'
        )
        plt.title('Packet Filtering Distribution')
        
        # Protocol Breakdown
        plt.subplot(2, 2, 2)
        plt.bar(
            log_analysis['blocked_by_protocol'].keys(), 
            log_analysis['blocked_by_protocol'].values()
        )
        plt.title('Blocked Packets by Protocol')
        plt.xlabel('Protocol')
        plt.ylabel('Number of Packets')
        plt.xticks(rotation=45)
        
        # Port Distribution
        plt.subplot(2, 2, 3)
        plt.bar(
            list(map(str, log_analysis['blocked_by_port'].keys())), 
            log_analysis['blocked_by_port'].values()
        )
        plt.title('Blocked Packets by Destination Port')
        plt.xlabel('Destination Port')
        plt.ylabel('Number of Packets')
        plt.xticks(rotation=45)
        
        # Allowed vs Blocked Percentage
        plt.subplot(2, 2, 4)
        plt.text(
            0.5, 0.5, 
            f"Block Percentage:\n{log_analysis['block_percentage']:.2f}%", 
            horizontalalignment='center', 
            verticalalignment='center', 
            fontsize=15
        )
        plt.axis('off')
        plt.title('Overall Blocking Rate')
        
        plt.tight_layout()
        plt.savefig('firewall_analysis.png')
        plt.close()
        logging.info("Firewall analysis visualization saved as 'firewall_analysis.png'.")

def main():
    # Define comprehensive firewall rules
    rules = [
        FirewallRule(protocol='ICMP', action='block'),  # Block ICMP
        FirewallRule(destination_port=22, action='block'),  # Block SSH
        FirewallRule(destination_port=80, action='block'),  # Block HTTP
        FirewallRule(protocol='UDP', action='block')  # Block UDP
    ]
    
    # Create firewall
    firewall = Firewall(rules)
    logging.info("Firewall initialized with rules.")

    # Simulate extensive network traffic
    for _ in range(5000):
        packet = NetworkPacket.generate_random_packet()
        firewall.filter_packet(packet)
    
    # Analyze logs
    log_analysis = LogAnalyzer.analyze_logs(firewall)
    
    # Print detailed log analysis
    logging.info("Firewall Simulation Log Analysis:")
    logging.info(json.dumps(log_analysis, indent=2))
    
    # Visualize results
    Visualizer.plot_comprehensive_analysis(log_analysis)

if __name__ == "__main__":
    main()

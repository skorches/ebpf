#!/usr/bin/env python3
"""
eBPF Packet Feature Extractor for ML
Captures network packets and extracts time-series features for machine learning models.
"""

import struct
import socket
import time
import json
from datetime import datetime
from collections import deque
import numpy as np
from bcc import BPF
import argparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketFeatureExtractor:
    def __init__(self, interface, window_size=100, feature_output=None):
        """
        Initialize packet feature extractor.
        
        Args:
            interface: Network interface to monitor (e.g., 'eth0')
            window_size: Number of packets to aggregate for time-series features
            feature_output: File to write extracted features (optional)
        """
        self.interface = interface
        self.window_size = window_size
        self.feature_output = feature_output
        self.packet_buffer = deque(maxlen=window_size)
        self.bpf = None
        
    def load_ebpf_program(self):
        """Load and compile the eBPF program."""
        try:
            with open('ebpf_packet_feature.c', 'r') as f:
                program = f.read()
            
            self.bpf = BPF(text=program)
            logger.info("eBPF program loaded successfully")
        except FileNotFoundError:
            logger.error("ebpf_packet_feature.c not found in current directory")
            raise
        except Exception as e:
            logger.error(f"Failed to load eBPF program: {e}")
            raise
    
    def attach_to_interface(self):
        """Attach XDP program to network interface."""
        try:
            fn = self.bpf.load_func("xdp_packet_feature", BPF.XDP)
            self.bpf.attach_xdp(self.interface, fn, 0)
            logger.info(f"XDP program attached to {self.interface}")
        except Exception as e:
            logger.error(f"Failed to attach XDP program: {e}")
            logger.warning("Make sure you have root privileges and the interface exists")
            raise
    
    def parse_packet(self, data):
        """Parse packet data from eBPF ring buffer."""
        # Struct: timestamp_ns (8), packet_size (4), src_ip (4), dst_ip (4),
        #         src_port (2), dst_port (2), protocol (1), tcp_flags (1),
        #         payload_size (2)
        if len(data) < 28:
            return None
        
        unpacked = struct.unpack('QIIIHHBBH', data[:28])
        return {
            'timestamp_ns': unpacked[0],
            'timestamp_s': unpacked[0] / 1e9,
            'packet_size': unpacked[1],
            'src_ip': self._int_to_ip(unpacked[2]),
            'dst_ip': self._int_to_ip(unpacked[3]),
            'src_port': unpacked[4],
            'dst_port': unpacked[5],
            'protocol': unpacked[6],
            'tcp_flags': unpacked[7],
            'payload_size': unpacked[8],
        }
    
    @staticmethod
    def _int_to_ip(ip_int):
        """Convert integer to IP address string."""
        return socket.inet_ntoa(struct.pack('I', socket.htonl(ip_int)))
    
    def compute_time_series_features(self):
        """Compute aggregated time-series features from packet buffer."""
        if len(self.packet_buffer) == 0:
            return None
        
        packets = list(self.packet_buffer)
        
        # Extract packet sizes
        sizes = np.array([p['packet_size'] for p in packets])
        
        # Inter-arrival times (difference between consecutive timestamps)
        if len(packets) > 1:
            timestamps = np.array([p['timestamp_ns'] for p in packets])
            inter_arrivals = np.diff(timestamps) / 1e6  # Convert to milliseconds
        else:
            inter_arrivals = np.array([])
        
        # Protocol distribution
        protocols = {}
        for p in packets:
            proto = p['protocol']
            protocols[proto] = protocols.get(proto, 0) + 1
        
        # Feature extraction
        features = {
            'buffer_size': len(packets),
            'timestamp_start': packets[0]['timestamp_s'],
            'timestamp_end': packets[-1]['timestamp_s'],
            'duration_ms': (packets[-1]['timestamp_ns'] - packets[0]['timestamp_ns']) / 1e6,
            
            # Packet size statistics
            'avg_packet_size': float(np.mean(sizes)),
            'min_packet_size': float(np.min(sizes)),
            'max_packet_size': float(np.max(sizes)),
            'std_packet_size': float(np.std(sizes)),
            'median_packet_size': float(np.median(sizes)),
            
            # Inter-arrival time statistics (in milliseconds)
            'avg_inter_arrival_ms': float(np.mean(inter_arrivals)) if len(inter_arrivals) > 0 else 0,
            'min_inter_arrival_ms': float(np.min(inter_arrivals)) if len(inter_arrivals) > 0 else 0,
            'max_inter_arrival_ms': float(np.max(inter_arrivals)) if len(inter_arrivals) > 0 else 0,
            'std_inter_arrival_ms': float(np.std(inter_arrivals)) if len(inter_arrivals) > 0 else 0,
            
            # Payload statistics
            'total_payload': sum(p['payload_size'] for p in packets),
            'avg_payload': float(np.mean([p['payload_size'] for p in packets])),
            
            # Protocol distribution
            'protocol_distribution': protocols,
            
            # Port diversity
            'unique_src_ports': len(set(p['src_port'] for p in packets)),
            'unique_dst_ports': len(set(p['dst_port'] for p in packets)),
            
            # Unique IPs
            'unique_src_ips': len(set(p['src_ip'] for p in packets)),
            'unique_dst_ips': len(set(p['dst_ip'] for p in packets)),
        }
        
        return features
    
    def handle_packet(self, cpu, data, size):
        """Callback function called when packet data arrives from eBPF."""
        packet = self.parse_packet(data)
        if packet:
            self.packet_buffer.append(packet)
            
            # Print packet info
            proto_name = 'TCP' if packet['protocol'] == 6 else ('UDP' if packet['protocol'] == 17 else 'OTHER')
            logger.info(
                f"{packet['src_ip']}:{packet['src_port']} → "
                f"{packet['dst_ip']}:{packet['dst_port']} "
                f"[{proto_name}] Size: {packet['packet_size']}B"
            )
            
            # Compute and output features when buffer is full
            if len(self.packet_buffer) == self.window_size:
                features = self.compute_time_series_features()
                if features:
                    self._output_features(features)
    
    def _output_features(self, features):
        """Output extracted features."""
        logger.info(f"\n=== Time-Series Features (Window Size: {self.window_size}) ===")
        logger.info(f"Duration: {features['duration_ms']:.2f}ms")
        logger.info(f"Avg Packet Size: {features['avg_packet_size']:.2f}B")
        logger.info(f"Avg Inter-arrival: {features['avg_inter_arrival_ms']:.3f}ms")
        logger.info(f"Total Payload: {features['total_payload']}B")
        logger.info(f"Unique Src IPs: {features['unique_src_ips']}, Dst IPs: {features['unique_dst_ips']}")
        
        if self.feature_output:
            with open(self.feature_output, 'a') as f:
                f.write(json.dumps(features) + '\n')
            logger.info(f"Features saved to {self.feature_output}")
    
    def start_capture(self):
        """Start capturing packets."""
        self.load_ebpf_program()
        self.attach_to_interface()
        
        # Open ring buffer
        rb = self.bpf["packet_features"]
        rb.open_ring_buffer(self.handle_packet)
        
        logger.info(f"Capturing packets from {self.interface}...")
        logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                rb.poll()
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Stopping capture...")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Detach XDP program and cleanup."""
        if self.bpf:
            self.bpf.remove_xdp(self.interface, 0)
            logger.info(f"XDP program detached from {self.interface}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract packet features for ML using eBPF'
    )
    parser.add_argument(
        '-i', '--interface',
        required=True,
        help='Network interface to monitor (e.g., eth0, wlan0)'
    )
    parser.add_argument(
        '-w', '--window-size',
        type=int,
        default=100,
        help='Number of packets to aggregate for features (default: 100)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for features (JSON lines format, optional)'
    )
    
    args = parser.parse_args()
    
    extractor = PacketFeatureExtractor(
        interface=args.interface,
        window_size=args.window_size,
        feature_output=args.output
    )
    
    extractor.start_capture()


if __name__ == '__main__':
    main()

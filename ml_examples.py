#!/usr/bin/env python3
"""
Example ML workflows using extracted packet features
Demonstrates common use cases: anomaly detection, traffic classification, etc.
"""

import json
import numpy as np
from pathlib import Path


def load_features(features_file):
    """Load features from JSON lines file"""
    features = []
    with open(features_file, 'r') as f:
        for line in f:
            if line.strip():
                features.append(json.loads(line))
    return features


def example_stateless_anomaly_detection(features):
    """
    Simple anomaly detection: flag samples with unusual packet sizes
    """
    print("\n=== Example: Stateless Anomaly Detection ===\n")
    
    packet_sizes = np.array([f['avg_packet_size'] for f in features])
    mean_size = np.mean(packet_sizes)
    std_size = np.std(packet_sizes)
    
    print(f"Average packet size: {mean_size:.2f} bytes")
    print(f"Std deviation: {std_size:.2f} bytes\n")
    
    # Flag packets that are 2 standard deviations away from mean
    threshold = 2.0
    anomalies = []
    for i, f in enumerate(features):
        z_score = (f['avg_packet_size'] - mean_size) / (std_size + 1e-6)
        if abs(z_score) > threshold:
            anomalies.append((i, f, z_score))
    
    if anomalies:
        print(f"Found {len(anomalies)} anomalous windows:\n")
        for idx, feature, z_score in anomalies[:5]:
            print(f"Window {idx}: avg_packet_size={feature['avg_packet_size']:.2f}B "
                  f"(z_score={z_score:.2f})")
    else:
        print("No anomalies detected")


def example_traffic_pattern_analysis(features):
    """
    Analyze traffic patterns: identify communication types based on features
    """
    print("\n=== Example: Traffic Pattern Analysis ===\n")
    
    tcp_count = 0
    udp_count = 0
    small_packets = 0
    large_packets = 0
    
    for f in features:
        if 6 in f['protocol_distribution']:  # TCP
            tcp_count += f['protocol_distribution'][6]
        if 17 in f['protocol_distribution']:  # UDP
            udp_count += f['protocol_distribution'][17]
        
        if f['avg_packet_size'] < 100:
            small_packets += 1
        elif f['avg_packet_size'] > 1000:
            large_packets += 1
    
    total = tcp_count + udp_count
    
    print(f"Protocol Distribution:")
    if total > 0:
        print(f"  TCP: {tcp_count/total*100:.1f}%")
        print(f"  UDP: {udp_count/total*100:.1f}%")
    
    print(f"\nPacket Size Distribution:")
    print(f"  Small packets (<100B): {small_packets}/{len(features)} windows")
    print(f"  Large packets (>1000B): {large_packets}/{len(features)} windows")
    
    # Classify traffic pattern
    if tcp_count > udp_count and small_packets > large_packets:
        print(f"\nTraffic Pattern: Control/Command (TCP, small packets)")
    elif udp_count > tcp_count:
        print(f"\nTraffic Pattern: Streaming (UDP heavy)")
    elif large_packets > small_packets:
        print(f"\nTraffic Pattern: Bulk Transfer (large packets)")
    else:
        print(f"\nTraffic Pattern: Mixed/Normal")


def example_network_health_monitoring(features):
    """
    Monitor network health: detect latency issues, packet loss patterns
    """
    print("\n=== Example: Network Health Monitoring ===\n")
    
    avg_latencies = [f['avg_inter_arrival_ms'] for f in features]
    packet_consistency = [f['std_inter_arrival_ms'] for f in features]
    
    print(f"Average inter-arrival time: {np.mean(avg_latencies):.3f} ms")
    print(f"Latency variation: {np.mean(packet_consistency):.3f} ms (std)")
    print(f"Max latency observed: {np.max(avg_latencies):.3f} ms")
    
    # Detect latency spikes
    overall_mean = np.mean(avg_latencies)
    overall_std = np.std(avg_latencies)
    spikes = sum(1 for lat in avg_latencies if lat > overall_mean + 2*overall_std)
    
    if spikes > 0:
        print(f"\n⚠ Latency spikes detected in {spikes}/{len(features)} windows")
        print("  Possible causes: network congestion, packet loss, interference")
    else:
        print(f"\n✓ Network latency stable")


def example_feature_extraction(features):
    """
    Extract numeric features for ML model input
    """
    print("\n=== Example: Feature Matrix Extraction ===\n")
    
    X = []
    for f in features:
        # Select relevant features for model
        feature_vector = [
            f['avg_packet_size'],
            f['std_packet_size'],
            f['avg_inter_arrival_ms'],
            f['std_inter_arrival_ms'],
            f['total_payload'],
            f['unique_src_ips'],
            f['unique_dst_ips'],
            f['duration_ms'],
        ]
        X.append(feature_vector)
    
    X = np.array(X)
    
    print(f"Feature matrix shape: {X.shape}")
    print(f"({X.shape[0]} samples, {X.shape[1]} features)")
    print(f"\nFeature names:")
    names = [
        'avg_packet_size', 'std_packet_size', 'avg_inter_arrival_ms',
        'std_inter_arrival_ms', 'total_payload', 'unique_src_ips',
        'unique_dst_ips', 'duration_ms'
    ]
    for i, name in enumerate(names):
        print(f"  {i}: {name}")
    
    print(f"\nFirst sample feature vector:")
    print(f"  {X[0]}")
    
    print(f"\nFeature statistics:")
    for i, name in enumerate(names):
        col = X[:, i]
        print(f"  {name:20s}: mean={np.mean(col):10.2f}, std={np.std(col):10.2f}")
    
    return X


def example_ml_ready_dataset(features):
    """
    Prepare dataset ready for ML training
    """
    print("\n=== Example: Preparing ML-Ready Dataset ===\n")
    
    # Extract features
    X = []
    y = []  # Placeholder labels
    
    for i, f in enumerate(features):
        # Feature vector
        features_vector = [
            f['avg_packet_size'],
            f['std_packet_size'],
            f['avg_inter_arrival_ms'],
            f['std_inter_arrival_ms'],
            f['total_payload'],
            f['unique_src_ips'],
            f['unique_dst_ips'],
        ]
        X.append(features_vector)
        
        # Simple labeling (replace with your own logic)
        # For example: label based on number of unique IPs
        if f['unique_src_ips'] > 5 or f['unique_dst_ips'] > 5:
            label = 'distributed'
        elif f['avg_packet_size'] > 1000:
            label = 'bulk_transfer'
        else:
            label = 'normal'
        y.append(label)
    
    X = np.array(X)
    
    # Look at class distribution
    unique, counts = np.unique(y, return_counts=True)
    
    print(f"Dataset size: {len(X)} samples")
    print(f"Number of features: {X.shape[1]}")
    print(f"Class distribution:")
    for label, count in zip(unique, counts):
        print(f"  {label}: {count} ({count/len(X)*100:.1f}%)")
    
    print(f"\nReady for scikit-learn training:")
    print(f"```python")
    print(f"from sklearn.model_selection import train_test_split")
    print(f"from sklearn.preprocessing import LabelEncoder")
    print(f"from sklearn.ensemble import RandomForestClassifier")
    print(f"")
    print(f"# Encode labels")
    print(f"le = LabelEncoder()")
    print(f"y_encoded = le.fit_transform(y)")
    print(f"")
    print(f"# Split data")
    print(f"X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2)")
    print(f"")
    print(f"# Train model")
    print(f"model = RandomForestClassifier(n_estimators=100)")
    print(f"model.fit(X_train, y_train)")
    print(f"```")
    
    return X, y


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Example ML workflows with packet features')
    parser.add_argument('features_file', help='JSON lines file with extracted features')
    parser.add_argument('--all', action='store_true', help='Run all examples')
    parser.add_argument('--anomaly', action='store_true', help='Anomaly detection example')
    parser.add_argument('--patterns', action='store_true', help='Traffic pattern analysis')
    parser.add_argument('--health', action='store_true', help='Network health monitoring')
    parser.add_argument('--features', action='store_true', help='Feature extraction')
    parser.add_argument('--dataset', action='store_true', help='ML dataset preparation')
    
    args = parser.parse_args()
    
    # Load features
    if not Path(args.features_file).exists():
        print(f"Error: {args.features_file} not found")
        return 1
    
    features = load_features(args.features_file)
    print(f"\nLoaded {len(features)} feature windows\n")
    
    # Run examples
    run_all = args.all or (
        not any([args.anomaly, args.patterns, args.health, args.features, args.dataset])
    )
    
    if run_all or args.anomaly:
        example_stateless_anomaly_detection(features)
    
    if run_all or args.patterns:
        example_traffic_pattern_analysis(features)
    
    if run_all or args.health:
        example_network_health_monitoring(features)
    
    if run_all or args.features:
        example_feature_extraction(features)
    
    if run_all or args.dataset:
        example_ml_ready_dataset(features)
    
    return 0


if __name__ == '__main__':
    exit(main())

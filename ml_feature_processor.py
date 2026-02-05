#!/usr/bin/env python3
"""
Example: Using extracted packet features with ML models
Demonstrates how to load and prepare features for machine learning
"""

import json
import numpy as np
import argparse
from pathlib import Path
from collections import defaultdict


class MLFeatureProcessor:
    """Process eBPF packet features for ML models"""
    
    def __init__(self, features_file):
        self.features_file = features_file
        self.features = []
        self.load_features()
    
    def load_features(self):
        """Load features from JSON lines file"""
        if not Path(self.features_file).exists():
            raise FileNotFoundError(f"Features file not found: {self.features_file}")
        
        with open(self.features_file, 'r') as f:
            for line in f:
                if line.strip():
                    self.features.append(json.loads(line))
        
        print(f"Loaded {len(self.features)} feature windows")
    
    def extract_feature_matrix(self):
        """
        Extract numeric feature matrix suitable for ML models.
        Returns: numpy array of shape (n_samples, n_features)
        """
        feature_list = []
        
        for f in self.features:
            features_numeric = [
                f['avg_packet_size'],
                f['std_packet_size'],
                f['max_packet_size'],
                f['min_packet_size'],
                f['avg_inter_arrival_ms'],
                f['std_inter_arrival_ms'],
                f['max_inter_arrival_ms'],
                f['min_inter_arrival_ms'],
                f['total_payload'],
                f['avg_payload'],
                f['unique_src_ips'],
                f['unique_dst_ips'],
                f['unique_src_ports'],
                f['unique_dst_ports'],
                f['duration_ms'],
                f['buffer_size'],
            ]
            feature_list.append(features_numeric)
        
        return np.array(feature_list)
    
    def get_feature_names(self):
        """Get names of extracted features"""
        return [
            'avg_packet_size',
            'std_packet_size',
            'max_packet_size',
            'min_packet_size',
            'avg_inter_arrival_ms',
            'std_inter_arrival_ms',
            'max_inter_arrival_ms',
            'min_inter_arrival_ms',
            'total_payload',
            'avg_payload',
            'unique_src_ips',
            'unique_dst_ips',
            'unique_src_ports',
            'unique_dst_ports',
            'duration_ms',
            'buffer_size',
        ]
    
    def extract_protocol_features(self):
        """Extract protocol distribution as additional features"""
        protocol_counts = defaultdict(int)
        
        for f in self.features:
            for proto, count in f['protocol_distribution'].items():
                protocol_counts[proto] += count
        
        return protocol_counts
    
    def get_statistics(self):
        """Print statistical summary of loaded features"""
        print("\n=== Feature Statistics ===")
        
        X = self.extract_feature_matrix()
        names = self.get_feature_names()
        
        print(f"\nTotal samples: {X.shape[0]}")
        print(f"Total features: {X.shape[1]}\n")
        
        for i, name in enumerate(names):
            values = X[:, i]
            print(f"{name:25s} - Mean: {np.mean(values):10.2f}, "
                  f"Std: {np.std(values):10.2f}, "
                  f"Min: {np.min(values):10.2f}, "
                  f"Max: {np.max(values):10.2f}")
        
        # Protocol statistics
        protocols = self.extract_protocol_features()
        print(f"\nProtocol Distribution:")
        proto_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 41: 'IPv6'}
        for proto, count in sorted(protocols.items()):
            proto_name = proto_names.get(proto, f'Protocol_{proto}')
            print(f"  {proto_name}: {count}")
    
    def normalize_features(self):
        """Normalize features to [0, 1] range"""
        X = self.extract_feature_matrix()
        X_min = np.min(X, axis=0)
        X_max = np.max(X, axis=0)
        
        # Avoid division by zero
        X_normalized = np.zeros_like(X, dtype=float)
        for i in range(X.shape[1]):
            if X_max[i] > X_min[i]:
                X_normalized[:, i] = (X[:, i] - X_min[i]) / (X_max[i] - X_min[i])
        
        return X_normalized
    
    def standardize_features(self):
        """Standardize features (z-score normalization)"""
        X = self.extract_feature_matrix()
        X_mean = np.mean(X, axis=0)
        X_std = np.std(X, axis=0)
        
        # Avoid division by zero
        X_standardized = np.zeros_like(X, dtype=float)
        for i in range(X.shape[1]):
            if X_std[i] > 0:
                X_standardized[:, i] = (X[:, i] - X_mean[i]) / X_std[i]
        
        return X_standardized
    
    def export_for_sklearn(self):
        """Export features in sklearn-compatible format"""
        import pickle
        
        X = self.extract_feature_matrix()
        feature_names = self.get_feature_names()
        
        data = {
            'X': X,
            'feature_names': feature_names,
            'n_samples': X.shape[0],
            'n_features': X.shape[1],
        }
        
        with open('sklearn_features.pkl', 'wb') as f:
            pickle.dump(data, f)
        print("Exported to sklearn_features.pkl")
    
    def export_for_tensorflow(self):
        """Export features in TensorFlow-compatible format"""
        import json
        
        X = self.extract_feature_matrix()
        feature_names = self.get_feature_names()
        
        data = {
            'features': X.tolist(),
            'feature_names': feature_names,
            'shape': [X.shape[0], X.shape[1]],
        }
        
        with open('tensorflow_features.json', 'w') as f:
            json.dump(data, f, indent=2)
        print("Exported to tensorflow_features.json")


def example_training():
    """Example: Train a simple anomaly detection model"""
    print("\n=== Example: Anomaly Detection Training ===")
    
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        print("sklearn not installed. Install with: pip install scikit-learn")
        return
    
    # This is a placeholder example
    print("""
    Example code to train anomaly detection:
    
    processor = MLFeatureProcessor('features.jsonl')
    X = processor.standardize_features()
    
    # Train Isolation Forest for anomaly detection
    model = IsolationForest(contamination=0.1, random_state=42)
    predictions = model.fit_predict(X)
    
    # Get anomaly scores
    scores = model.score_samples(X)
    
    # Label normal (1) and anomalies (-1)
    normal_samples = X[predictions == 1]
    anomalies = X[predictions == -1]
    """)


def main():
    parser = argparse.ArgumentParser(
        description='Process eBPF packet features for ML'
    )
    parser.add_argument(
        'features_file',
        help='JSON lines file with extracted features'
    )
    parser.add_argument(
        '--normalize',
        action='store_true',
        help='Print normalized features'
    )
    parser.add_argument(
        '--standardize',
        action='store_true',
        help='Print standardized features'
    )
    parser.add_argument(
        '--export-sklearn',
        action='store_true',
        help='Export for scikit-learn'
    )
    parser.add_argument(
        '--export-tensorflow',
        action='store_true',
        help='Export for TensorFlow'
    )
    
    args = parser.parse_args()
    
    try:
        processor = MLFeatureProcessor(args.features_file)
        
        # Print statistics
        processor.get_statistics()
        
        # Handle normalization
        if args.normalize:
            print("\n=== Normalized Features (0-1) ===")
            X_norm = processor.normalize_features()
            print(f"Shape: {X_norm.shape}")
            print(f"Sample: {X_norm[0]}")
        
        # Handle standardization
        if args.standardize:
            print("\n=== Standardized Features (z-score) ===")
            X_std = processor.standardize_features()
            print(f"Shape: {X_std.shape}")
            print(f"Mean: {np.mean(X_std, axis=0)}")
            print(f"Std: {np.std(X_std, axis=0)}")
        
        # Handle exports
        if args.export_sklearn:
            processor.export_for_sklearn()
        
        if args.export_tensorflow:
            processor.export_for_tensorflow()
        
        # Show example
        example_training()
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())

# Quick Start Guide

Get started with the eBPF Packet Feature Extractor in 5 minutes.

## Prerequisites Check

```bash
python3 verify_setup.py
```

This script checks if your system has all required dependencies.

## Installation (One-time)

### Option 1: Automatic Setup
```bash
make install-deps
make
```

### Option 2: Manual Setup

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install llvm clang libelf-dev libpcap-dev linux-headers-$(uname -r) python3-pip
pip3 install -r requirements.txt
make
```

**Fedora/RHEL:**
```bash
sudo dnf install llvm clang elfutils-libelf-devel libpcap-devel kernel-devel python3-pip
pip3 install -r requirements.txt
make
```

## Find Your Network Interface

```bash
ip link show
# or
ifconfig
```

Example output - interface names are: `eth0`, `wlan0`, `docker0`, etc.

## Run Packet Capture

### Basic: Monitor all traffic
```bash
sudo python3 extract_features.py -i eth0
```

### Aggregate every 100 packets
```bash
sudo python3 extract_features.py -i eth0 -w 100
```

### Save features to file (for ML analysis)
```bash
sudo python3 extract_features.py -i eth0 -w 100 -o features.jsonl
```

### Let it run for 30 seconds, then stop (Ctrl+C)
```bash
timeout 30 sudo python3 extract_features.py -i eth0 -w 50 -o features.jsonl
```

## Analyze Extracted Features

```bash
# View statistics
python3 ml_feature_processor.py features.jsonl

# Run ML examples
python3 ml_examples.py features.jsonl
```

## Complete Example Workflow

```bash
# Step 1: Verify setup
python3 verify_setup.py

# Step 2: Compile eBPF program
make

# Step 3: Capture packets for 1 minute
timeout 60 sudo python3 extract_features.py -i eth0 -w 100 -o my_features.jsonl

# Step 4: Analyze results
python3 ml_examples.py my_features.jsonl --all
```

## Troubleshooting

**Error: Permission denied**
```bash
# Use sudo (tool requires root to attach to network interface)
sudo python3 extract_features.py -i eth0
```

**Error: Interface not found**
```bash
# List your interfaces first
ip link show
# Then use the correct name
sudo python3 extract_features.py -i eth0  # Replace eth0 with your interface
```

**Error: Module 'bcc' not found**
```bash
pip3 install bcc numpy
# or
make install-deps
```

**Error: Permission denied /sys/kernel/debug/tracing**
```bash
# Some systems restrict tracing permissions
sudo python3 extract_features.py -i eth0
```

## Output Examples

### Real-time Console Output
```
INFO:root:127.0.0.1:54321 → 192.168.1.1:443 [TCP] Size: 512B
INFO:root:127.0.0.1:54322 → 192.168.1.1:443 [TCP] Size: 256B
...

=== Time-Series Features (Window Size: 100) ===
Duration: 2333.00ms
Avg Packet Size: 512.30B
Avg Inter-arrival: 23.33ms
Total Payload: 40230B
Unique Src IPs: 3, Dst IPs: 5
```

### Saved JSON Features File (features.jsonl)
```json
{"buffer_size": 100, "avg_packet_size": 512.3, "avg_inter_arrival_ms": 23.33, ...}
{"buffer_size": 100, "avg_packet_size": 487.2, "avg_inter_arrival_ms": 25.12, ...}
```

## Next Steps

1. **Read Full Documentation**: See `README.md`
2. **ML Integration**: Use `ml_feature_processor.py` for data preprocessing
3. **Run Examples**: See `ml_examples.py` for common use cases
4. **Customize**: Edit `ebpf_packet_feature.c` to capture additional packet properties

## File Structure

```
ebpf/
├── ebpf_packet_feature.c       # eBPF kernel program
├── extract_features.py         # Userspace packet capture & feature extraction
├── ml_feature_processor.py    # ML feature preprocessing & export
├── ml_examples.py             # Example ML workflows
├── verify_setup.py            # Setup verification script
├── Makefile                    # Build configuration
├── requirements.txt           # Python dependencies
├── README.md                  # Full documentation
├── QUICKSTART.md              # This file
└── features.jsonl             # Output file (created after running)
```

## Performance Tips

- **Larger Window Size**: More statistical precision, higher latency
  - Small (10-50): Real-time, less stable features
  - Medium (100-500): Good balance
  - Large (1000+): Very stable, higher latency

- **High-Traffic Networks**: May need to adjust ring buffer size in source code

- **Resource Usage**: Minimal CPU overhead (<1%), good for production systems

## Common Commands Reference

```bash
# Get help
python3 extract_features.py --help
python3 ml_examples.py --help

# List network interfaces
ip link show

# Check kernel version
uname -r

# See BPF programs attached
sudo bpftool prog list

# Remove all BPF programs
sudo bpftool prog detach

# Monitor in real-time
watch -n 1 'sudo bpftool prog list'
```

## Need Help?

1. Check `verify_setup.py` output for missing dependencies
2. Review `README.md` for detailed documentation
3. Check kernel version: `uname -r` (need 5.8+)
4. Verify network interface: `ip link show`
5. Try verbose Python output: Add `logging.basicConfig(level=logging.DEBUG)`

---

**Good luck! Happy packet capturing! 🚀**

CLANG ?= clang
LLC ?= llc
STRIP ?= llvm-strip
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

# Get architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# BPF object file
OUTPUT := .ebpf
VMLINUX_BTF := /sys/kernel/btf/vmlinux

# Compilation flags
INCLUDES := -I/usr/include -I/usr/include/bpf -I.
CFLAGS := -g -O2 -target bpf -D__KERNEL__ -D__BPF_TRACING__ $(INCLUDES)

.PHONY: all clean install-deps

all: $(OUTPUT)

$(OUTPUT):
	@mkdir -p $(OUTPUT)
	$(CLANG) $(CFLAGS) -c ebpf_packet_feature.c -o $(OUTPUT)/ebpf_packet_feature.o
	$(LLVM_STRIP) -g $(OUTPUT)/ebpf_packet_feature.o
	@echo "eBPF program compiled successfully"

install-deps:
	@echo "Installing dependencies..."
	pip3 install -r requirements.txt
	@echo "Checking for kernel development headers..."
	@if ! command -v clang &> /dev/null; then \
		echo "Error: clang not found. Please install LLVM:"; \
		echo "  Ubuntu/Debian: sudo apt-get install llvm clang libelf-dev libpcap-dev"; \
		echo "  Fedora: sudo dnf install llvm clang elfutils-libelf-devel libpcap-devel"; \
		exit 1; \
	fi
	@if [ ! -f "$(VMLINUX_BTF)" ]; then \
		echo "Warning: Kernel BTF not found at $(VMLINUX_BTF)"; \
		echo "Please ensure your kernel supports BPF (5.8+)"; \
	fi

clean:
	rm -rf $(OUTPUT)
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

help:
	@echo "Available targets:"
	@echo "  all              - Compile eBPF program"
	@echo "  install-deps     - Install Python and system dependencies"
	@echo "  clean            - Remove build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  make             - Compile eBPF kernel program"
	@echo "  make install-deps - Install all requirements"
	@echo ""
	@echo "Running the tool:"
	@echo "  sudo python3 extract_features.py -i <interface> -w <window_size> [-o <output_file>]"
	@echo ""
	@echo "Example:"
	@echo "  sudo python3 extract_features.py -i eth0 -w 100 -o features.jsonl"

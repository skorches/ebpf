#!/usr/bin/env python3
"""
Setup verification script for eBPF Packet Feature Extractor
Checks all requirements and provides setup guidance
"""

import subprocess
import sys
import os
import json
from pathlib import Path


class SetupVerifier:
    def __init__(self):
        self.checks = {
            'kernel': self.check_kernel,
            'clang': self.check_clang,
            'llvm_strip': self.check_llvm_strip,
            'llvm_objdump': self.check_llvm_objdump,
            'libelf': self.check_libelf,
            'libpcap': self.check_libpcap,
            'python': self.check_python,
            'bcc': self.check_bcc,
            'numpy': self.check_numpy,
            'headers': self.check_kernel_headers,
            'xdp_support': self.check_xdp_support,
        }
        self.results = {}
    
    def run_command(self, cmd):
        """Run command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            return False, str(e)
    
    def check_kernel(self):
        """Check kernel version (need 5.8+)"""
        success, output = self.run_command("uname -r")
        if not success:
            return False, "Could not determine kernel version"
        
        # Parse version
        version_str = output.split('-')[0]  # Remove release suffix
        parts = version_str.split('.')
        
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            
            if major > 5 or (major == 5 and minor >= 8):
                return True, f"✓ Kernel {output} (5.8+ required)"
            else:
                return False, f"✗ Kernel {output} (need 5.8+)"
        except:
            return True, f"✓ Kernel {output} (assuming 5.8+)"
    
    def check_clang(self):
        """Check for clang compiler"""
        success, output = self.run_command("clang --version | head -1")
        if success:
            return True, f"✓ {output}"
        return False, "✗ clang not found (install llvm package)"
    
    def check_llvm_strip(self):
        """Check for llvm-strip"""
        success, output = self.run_command("which llvm-strip")
        if success:
            return True, f"✓ llvm-strip found"
        return False, "✗ llvm-strip not found (install llvm package)"
    
    def check_llvm_objdump(self):
        """Check for llvm-objdump"""
        success, output = self.run_command("which llvm-objdump")
        if success:
            return True, f"✓ llvm-objdump found"
        return False, "✗ llvm-objdump not found (install llvm package)"
    
    def check_libelf(self):
        """Check for libelf development files"""
        success, _ = self.run_command("dpkg -l | grep libelf-dev 2>/dev/null || rpm -qa | grep elfutils-libelf-devel 2>/dev/null")
        if success:
            return True, "✓ libelf-dev found"
        return False, "✗ libelf-dev not found (install libelf-dev or elfutils-libelf-devel)"
    
    def check_libpcap(self):
        """Check for libpcap development files"""
        success, _ = self.run_command("dpkg -l | grep libpcap-dev 2>/dev/null || rpm -qa | grep libpcap-devel 2>/dev/null")
        if success:
            return True, "✓ libpcap-dev found"
        return False, "✗ libpcap-dev not found (install libpcap-dev or libpcap-devel)"
    
    def check_python(self):
        """Check Python version"""
        success, output = self.run_command("python3 --version")
        if success and "3." in output:
            return True, f"✓ {output}"
        return False, "✗ Python 3 not found"
    
    def check_bcc(self):
        """Check for BCC Python module"""
        try:
            import bcc
            return True, f"✓ bcc {bcc.__version__ if hasattr(bcc, '__version__') else 'found'}"
        except ImportError:
            return False, "✗ bcc module not found (run: pip install bcc)"
    
    def check_numpy(self):
        """Check for NumPy"""
        try:
            import numpy as np
            return True, f"✓ numpy {np.__version__}"
        except ImportError:
            return False, "✗ numpy not found (run: pip install numpy)"
    
    def check_kernel_headers(self):
        """Check for kernel headers"""
        success, _ = self.run_command("test -f /sys/kernel/btf/vmlinux && echo found")
        if success:
            return True, "✓ Kernel BTF found"
        
        # Check headers directory
        success, _ = self.run_command("test -d /usr/src/linux-headers-$(uname -r) && echo found")
        if success:
            return True, "✓ Kernel headers found"
        
        return False, "✗ Kernel headers/BTF not found (install linux-headers)"
    
    def check_xdp_support(self):
        """Check if any interface supports XDP"""
        cmd = "for i in $(ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'); do ethtool -i $i 2>/dev/null | grep -q xdp_prog && echo $i; done"
        success, output = self.run_command(cmd)
        
        if success and output:
            interfaces = output.split('\n')
            return True, f"✓ XDP supported on: {', '.join(interfaces)}"
        
        return False, "✗ No interfaces with XDP support found (check with: ethtool -i <interface>)"
    
    def verify_all(self):
        """Run all checks"""
        print("=" * 60)
        print("eBPF Packet Feature Extractor - Setup Verification")
        print("=" * 60)
        
        for check_name, check_func in self.checks.items():
            try:
                success, message = check_func()
                self.results[check_name] = (success, message)
                status = "PASS" if success else "FAIL"
                print(f"\n[{status}] {check_name.upper()}")
                print(f"      {message}")
            except Exception as e:
                self.results[check_name] = (False, str(e))
                print(f"\n[ERROR] {check_name.upper()}")
                print(f"      {e}")
        
        print("\n" + "=" * 60)
        return self.print_summary()
    
    def print_summary(self):
        """Print summary and recommendations"""
        total = len(self.results)
        passed = sum(1 for success, _ in self.results.values() if success)
        
        print(f"\nSummary: {passed}/{total} checks passed")
        
        failed = [(name, msg) for name, (success, msg) in self.results.items() if not success]
        
        if not failed:
            print("\n✓ All checks passed! Ready to use.")
            print("\nNext steps:")
            print("  1. Compile eBPF program:")
            print("     make")
            print("  2. Run packet capture:")
            print("     sudo python3 extract_features.py -i <interface>")
            print("\nFind your network interface:")
            print("  ip link show")
            return 0
        else:
            print(f"\n✗ {len(failed)} check(s) failed:\n")
            for name, msg in failed:
                print(f"  • {name}: {msg}")
            
            print("\nRecommended fixes:")
            print("\nUbuntu/Debian:")
            print("  sudo apt-get update")
            print("  sudo apt-get install llvm clang libelf-dev libpcap-dev linux-headers-$(uname -r)")
            print("  pip3 install -r requirements.txt")
            
            print("\nFedora/RHEL:")
            print("  sudo dnf install llvm clang elfutils-libelf-devel libpcap-devel kernel-devel")
            print("  pip3 install -r requirements.txt")
            
            return 1


def main():
    verifier = SetupVerifier()
    return verifier.verify_all()


if __name__ == '__main__':
    sys.exit(main())

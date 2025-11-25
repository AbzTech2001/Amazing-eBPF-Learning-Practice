#!/bin/bash

# Level 02: BCC and bpftrace Installation Script
# This script installs BCC and bpftrace with all dependencies

set -e

echo "========================================="
echo "BCC and bpftrace Setup"
echo "========================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

echo "Detected OS: $OS $VER"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install based on distribution
case "$OS" in
    ubuntu|debian)
        echo "Installing BCC and bpftrace for Ubuntu/Debian..."
        apt-get update

        # Install BCC
        echo ""
        echo "=== Installing BCC ==="
        apt-get install -y \
            bpfcc-tools \
            python3-bpfcc \
            libbpfcc-dev

        # Install bpftrace
        echo ""
        echo "=== Installing bpftrace ==="
        apt-get install -y bpftrace

        # Additional useful tools
        apt-get install -y \
            linux-headers-$(uname -r) \
            linux-tools-common \
            linux-tools-generic \
            linux-tools-$(uname -r)

        echo "Ubuntu/Debian packages installed successfully!"
        ;;

    fedora|rhel|centos)
        echo "Installing BCC and bpftrace for Fedora/RHEL/CentOS..."

        # Install BCC
        echo ""
        echo "=== Installing BCC ==="
        dnf install -y \
            bcc-tools \
            python3-bcc \
            bcc-devel

        # Install bpftrace
        echo ""
        echo "=== Installing bpftrace ==="
        dnf install -y bpftrace

        # Additional tools
        dnf install -y \
            kernel-devel \
            kernel-headers

        echo "Fedora/RHEL packages installed successfully!"
        ;;

    arch)
        echo "Installing BCC and bpftrace for Arch Linux..."

        # Install BCC
        echo ""
        echo "=== Installing BCC ==="
        pacman -Syu --noconfirm \
            bcc \
            bcc-tools \
            python-bcc

        # Install bpftrace
        echo ""
        echo "=== Installing bpftrace ==="
        pacman -Syu --noconfirm bpftrace

        # Additional tools
        pacman -Syu --noconfirm linux-headers

        echo "Arch Linux packages installed successfully!"
        ;;

    *)
        echo "Unsupported OS: $OS"
        echo ""
        echo "To install manually:"
        echo ""
        echo "BCC:"
        echo "  https://github.com/iovisor/bcc/blob/master/INSTALL.md"
        echo ""
        echo "bpftrace:"
        echo "  https://github.com/iovisor/bpftrace/blob/master/INSTALL.md"
        exit 1
        ;;
esac

echo ""
echo "========================================="
echo "Verifying Installation"
echo "========================================="
echo ""

# Verify BCC
echo "Checking BCC..."
if python3 -c "from bcc import BPF" 2>/dev/null; then
    echo "✓ BCC Python module installed"
    python3 -c "from bcc import BPF; print(f'  Version: {BPF.VERSION if hasattr(BPF, \"VERSION\") else \"unknown\"}')"
else
    echo "✗ BCC Python module not found"
fi

echo ""
echo "Checking BCC tools..."
if [ -d /usr/share/bcc/tools ]; then
    TOOL_COUNT=$(ls /usr/share/bcc/tools/*.py 2>/dev/null | wc -l)
    echo "✓ BCC tools directory found"
    echo "  Location: /usr/share/bcc/tools/"
    echo "  Tools available: $TOOL_COUNT"
else
    echo "✗ BCC tools directory not found"
    echo "  Expected location: /usr/share/bcc/tools/"
fi

# Verify bpftrace
echo ""
echo "Checking bpftrace..."
if command -v bpftrace &> /dev/null; then
    echo "✓ bpftrace installed"
    bpftrace --version
else
    echo "✗ bpftrace not found"
fi

echo ""
echo "========================================="
echo "Testing BCC"
echo "========================================="
echo ""

echo "Running simple BCC test..."
cat > /tmp/bcc_test.py << 'EOF'
#!/usr/bin/env python3
from bcc import BPF

prog = """
int hello(void *ctx) {
    bpf_trace_printk("BCC test successful!\\n");
    return 0;
}
"""

try:
    b = BPF(text=prog)
    b.attach_kprobe(event="sys_clone", fn_name="hello")
    print("✓ BCC can compile and load programs")
    b.cleanup()
except Exception as e:
    print(f"✗ BCC test failed: {e}")
EOF

python3 /tmp/bcc_test.py
rm /tmp/bcc_test.py

echo ""
echo "========================================="
echo "Testing bpftrace"
echo "========================================="
echo ""

echo "Running simple bpftrace test..."
if sudo bpftrace -e 'BEGIN { printf("bpftrace test successful!\n"); exit(); }' 2>&1 | grep -q "successful"; then
    echo "✓ bpftrace can run programs"
else
    echo "✗ bpftrace test failed"
fi

echo ""
echo "========================================="
echo "Listing Available Tools"
echo "========================================="
echo ""

echo "=== BCC Tools (sample) ==="
ls /usr/share/bcc/tools/*.py 2>/dev/null | head -20 | while read tool; do
    echo "  $(basename $tool)"
done
echo "  ... (see /usr/share/bcc/tools/ for full list)"

echo ""
echo "=== bpftrace Capabilities ==="
sudo bpftrace -l 'tracepoint:syscalls:*' 2>/dev/null | head -10
echo "  ... (run 'sudo bpftrace -l' for full list)"

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Quick start:"
echo ""
echo "BCC:"
echo "  # List tools"
echo "  ls /usr/share/bcc/tools/"
echo ""
echo "  # Trace process execution"
echo "  sudo /usr/share/bcc/tools/execsnoop"
echo ""
echo "  # Trace file opens"
echo "  sudo /usr/share/bcc/tools/opensnoop"
echo ""
echo "bpftrace:"
echo "  # List available probes"
echo "  sudo bpftrace -l 'kprobe:*'"
echo ""
echo "  # Count syscalls by process"
echo "  sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'"
echo ""
echo "  # Trace TCP connections"
echo "  sudo bpftrace examples/bpftrace/tcp_connect.bt"
echo ""
echo "Next steps:"
echo "  1. Read README.md for tasks and challenges"
echo "  2. Try the example scripts in examples/"
echo "  3. Explore BCC tools in /usr/share/bcc/tools/"
echo ""

#!/bin/bash
# Level 04: Setup Networking & Observability Environment

set -e

echo "========================================="
echo "Level 04: Networking & Observability Setup"
echo "========================================="
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

echo "Detected OS: $OS"
echo ""

echo "=== Installing Core Dependencies ==="
case "$OS" in
    ubuntu|debian)
        apt-get update
        apt-get install -y \
            libbpf-dev \
            clang \
            llvm \
            gcc \
            make \
            linux-tools-common \
            linux-tools-generic \
            iproute2 \
            iputils-ping \
            net-tools \
            tcpdump \
            iperf3 \
            curl \
            wget
        ;;
    fedora|rhel|centos)
        dnf install -y \
            libbpf-devel \
            clang \
            llvm \
            gcc \
            make \
            bpftool \
            iproute \
            iputils \
            net-tools \
            tcpdump \
            iperf3 \
            curl \
            wget
        ;;
    *)
        echo "Unsupported OS. Please install manually."
        exit 1
        ;;
esac
echo "✓ Core dependencies installed"
echo ""

echo "=== Checking Kernel Features ==="
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Check XDP support
echo -n "XDP support... "
if [ -f /sys/kernel/btf/vmlinux ]; then
    echo "✓ Available"
else
    echo "⚠ BTF not available (limited XDP features)"
fi

# Check TC support
echo -n "TC (Traffic Control) support... "
if command -v tc &> /dev/null; then
    echo "✓ Available"
else
    echo "✗ NOT FOUND"
fi

# Check LSM BPF
echo -n "LSM BPF support... "
if [ -f /sys/kernel/security/lsm ]; then
    LSM_MODULES=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_MODULES" | grep -q "bpf"; then
        echo "✓ Enabled (LSM: $LSM_MODULES)"
    else
        echo "⚠ BPF not in LSM list. Current: $LSM_MODULES"
        echo "   To enable, add 'lsm=...,bpf' to kernel cmdline"
    fi
else
    echo "⚠ Cannot determine LSM status"
fi
echo ""

echo "=== Optional: Prometheus/Grafana ==="
read -p "Install Prometheus exporters? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    case "$OS" in
        ubuntu|debian)
            apt-get install -y prometheus-node-exporter
            ;;
        fedora|rhel|centos)
            dnf install -y golang
            echo "Note: You may need to build exporters from source"
            ;;
    esac
    echo "✓ Prometheus tools installed"
fi
echo ""

echo "=== Optional: Docker (for testing) ==="
read -p "Install Docker? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if ! command -v docker &> /dev/null; then
        case "$OS" in
            ubuntu|debian)
                apt-get install -y docker.io
                systemctl enable docker
                systemctl start docker
                ;;
            fedora|rhel|centos)
                dnf install -y docker
                systemctl enable docker
                systemctl start docker
                ;;
        esac
        echo "✓ Docker installed"
    else
        echo "✓ Docker already installed"
    fi
fi
echo ""

echo "========================================="
echo "✓ Level 04 Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Run verify-networking.sh to verify setup"
echo "  2. Try XDP examples in examples/xdp/"
echo "  3. Try TC examples in examples/tc/"
echo "  4. Explore LSM examples in examples/lsm/"
echo ""

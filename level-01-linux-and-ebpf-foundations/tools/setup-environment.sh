#!/bin/bash

# Level 01: eBPF Environment Setup Script
# This script installs all necessary tools for eBPF development

set -e  # Exit on error

echo "========================================="
echo "eBPF Environment Setup"
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
        echo "Installing packages for Ubuntu/Debian..."
        apt-get update

        # Core eBPF tools
        apt-get install -y \
            linux-tools-common \
            linux-tools-generic \
            linux-tools-$(uname -r) \
            clang \
            llvm \
            gcc \
            make \
            libbpf-dev \
            linux-headers-$(uname -r)

        # Additional useful tools
        apt-get install -y \
            bpfcc-tools \
            python3-bpfcc \
            libbpfcc-dev \
            strace \
            git

        echo "Ubuntu/Debian packages installed successfully!"
        ;;

    fedora|rhel|centos)
        echo "Installing packages for Fedora/RHEL/CentOS..."
        dnf install -y \
            bpftool \
            clang \
            llvm \
            gcc \
            make \
            libbpf-devel \
            kernel-devel \
            kernel-headers

        dnf install -y \
            bcc-tools \
            python3-bcc \
            strace \
            git

        echo "Fedora/RHEL packages installed successfully!"
        ;;

    arch)
        echo "Installing packages for Arch Linux..."
        pacman -Syu --noconfirm \
            bpf \
            clang \
            llvm \
            gcc \
            make \
            linux-headers \
            bcc \
            bcc-tools \
            strace \
            git

        echo "Arch Linux packages installed successfully!"
        ;;

    *)
        echo "Unsupported OS: $OS"
        echo "Please install the following manually:"
        echo "  - bpftool"
        echo "  - clang/llvm"
        echo "  - libbpf"
        echo "  - linux-headers"
        exit 1
        ;;
esac

echo ""
echo "========================================="
echo "Verifying Installation"
echo "========================================="
echo ""

# Verify installations
echo "Checking bpftool..."
if command -v bpftool &> /dev/null; then
    bpftool version
else
    echo "WARNING: bpftool not found in PATH"
    echo "Trying alternative location..."
    if [ -f /usr/sbin/bpftool ]; then
        echo "Found at /usr/sbin/bpftool"
        ln -sf /usr/sbin/bpftool /usr/local/bin/bpftool || true
    fi
fi

echo ""
echo "Checking clang..."
clang --version | head -n 1

echo ""
echo "Checking llvm..."
llc --version | head -n 1

echo ""
echo "Checking libbpf..."
if [ -f /usr/include/bpf/bpf.h ]; then
    echo "libbpf headers found"
else
    echo "WARNING: libbpf headers not found at /usr/include/bpf/"
fi

echo ""
echo "Checking kernel headers..."
if [ -d /usr/src/linux-headers-$(uname -r) ] || [ -d /usr/src/kernels/$(uname -r) ]; then
    echo "Kernel headers found"
else
    echo "WARNING: Kernel headers not found"
fi

echo ""
echo "========================================="
echo "Setting up BPF filesystem"
echo "========================================="

# Mount BPF filesystem if not already mounted
if ! mount | grep -q "type bpf"; then
    echo "Mounting BPF filesystem..."
    mkdir -p /sys/fs/bpf
    mount -t bpf none /sys/fs/bpf
    echo "BPF filesystem mounted at /sys/fs/bpf"
else
    echo "BPF filesystem already mounted"
fi

# Make it persistent
if ! grep -q "bpf" /etc/fstab 2>/dev/null; then
    echo "Adding BPF filesystem to /etc/fstab for persistence..."
    echo "none /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
fi

echo ""
echo "========================================="
echo "Enabling JIT Compiler"
echo "========================================="

# Enable BPF JIT compiler
if [ -f /proc/sys/net/core/bpf_jit_enable ]; then
    current_jit=$(cat /proc/sys/net/core/bpf_jit_enable)
    echo "Current BPF JIT setting: $current_jit"

    if [ "$current_jit" != "1" ]; then
        echo "Enabling BPF JIT compiler..."
        echo 1 > /proc/sys/net/core/bpf_jit_enable

        # Make it persistent
        if [ ! -f /etc/sysctl.d/99-bpf.conf ]; then
            echo "net.core.bpf_jit_enable = 1" > /etc/sysctl.d/99-bpf.conf
            echo "JIT setting made persistent in /etc/sysctl.d/99-bpf.conf"
        fi
    else
        echo "BPF JIT already enabled"
    fi
fi

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Run './tools/verify-setup.sh' to verify everything is working"
echo "  2. Check kernel support with './lab/01-check-kernel-support.sh'"
echo "  3. Read the README.md for learning tasks"
echo ""

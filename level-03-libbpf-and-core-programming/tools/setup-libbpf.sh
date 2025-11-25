#!/bin/bash
# Level 03: libbpf Development Environment Setup

set -e

echo "========================================="
echo "libbpf Development Environment Setup"
echo "========================================="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

case "$OS" in
    ubuntu|debian)
        echo "Installing libbpf development tools..."
        apt-get update
        apt-get install -y \
            libbpf-dev \
            linux-headers-$(uname -r) \
            clang \
            llvm \
            gcc \
            make \
            pkg-config \
            libelf-dev \
            zlib1g-dev \
            linux-tools-common \
            linux-tools-generic
        ;;
    fedora|rhel|centos)
        dnf install -y \
            libbpf-devel \
            kernel-devel \
            clang \
            llvm \
            gcc \
            make \
            pkgconfig \
            elfutils-libelf-devel \
            zlib-devel \
            bpftool
        ;;
    *)
        echo "Unsupported OS. Please install manually."
        exit 1
        ;;
esac

echo ""
echo "✓ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Generate vmlinux.h: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
echo "  2. Try examples in examples/"
echo ""

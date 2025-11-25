#!/bin/bash
# XDP Helper Script - Quick attach/detach XDP programs

usage() {
    echo "Usage: $0 <attach|detach|status> [interface] [bpf_object] [section]"
    echo ""
    echo "Commands:"
    echo "  attach <iface> <obj> [sec]  - Attach XDP program"
    echo "  detach <iface>              - Detach XDP program"
    echo "  status [iface]              - Show XDP status"
    echo ""
    echo "Examples:"
    echo "  $0 attach eth0 xdp_drop.bpf.o xdp"
    echo "  $0 detach eth0"
    echo "  $0 status"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        exit 1
    fi
}

attach_xdp() {
    local iface=$1
    local obj=$2
    local sec=${3:-xdp}

    if [ -z "$iface" ] || [ -z "$obj" ]; then
        echo "Error: Interface and BPF object required"
        usage
    fi

    if [ ! -f "$obj" ]; then
        echo "Error: BPF object '$obj' not found"
        exit 1
    fi

    echo "Attaching XDP program to $iface..."
    echo "  Object: $obj"
    echo "  Section: $sec"

    # Try native mode first, fallback to generic
    if ip link set dev $iface xdpdrv obj $obj sec $sec 2>/dev/null; then
        echo "✓ Attached in native (driver) mode"
    elif ip link set dev $iface xdpgeneric obj $obj sec $sec 2>/dev/null; then
        echo "✓ Attached in generic (SKB) mode"
        echo "  Note: Generic mode has lower performance"
    else
        echo "✗ Failed to attach XDP program"
        exit 1
    fi

    echo ""
    echo "Verify with: ip link show dev $iface"
}

detach_xdp() {
    local iface=$1

    if [ -z "$iface" ]; then
        echo "Error: Interface required"
        usage
    fi

    echo "Detaching XDP program from $iface..."

    # Try both modes
    ip link set dev $iface xdpdrv off 2>/dev/null
    ip link set dev $iface xdpgeneric off 2>/dev/null

    echo "✓ XDP program detached"
    echo ""
    echo "Verify with: ip link show dev $iface"
}

show_status() {
    local iface=$1

    echo "XDP Status:"
    echo ""

    if [ -n "$iface" ]; then
        # Show specific interface
        ip link show dev $iface | grep -A 5 "xdp" || echo "  No XDP program attached to $iface"
    else
        # Show all interfaces with XDP
        echo "Interfaces with XDP programs:"
        ip link show | grep -B 1 "xdp" || echo "  No XDP programs attached"
    fi

    echo ""
    echo "All loaded XDP programs:"
    bpftool prog show type xdp 2>/dev/null || echo "  No XDP programs loaded"
}

# Main
case "$1" in
    attach)
        check_root
        attach_xdp "$2" "$3" "$4"
        ;;
    detach)
        check_root
        detach_xdp "$2"
        ;;
    status)
        show_status "$2"
        ;;
    *)
        usage
        ;;
esac

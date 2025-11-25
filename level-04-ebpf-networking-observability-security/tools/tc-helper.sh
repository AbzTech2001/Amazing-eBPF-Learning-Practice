#!/bin/bash
# TC Helper Script - Quick attach/detach TC BPF programs

usage() {
    echo "Usage: $0 <attach|detach|status> [interface] [direction] [bpf_object] [section]"
    echo ""
    echo "Commands:"
    echo "  attach <iface> <ingress|egress> <obj> [sec]  - Attach TC program"
    echo "  detach <iface> [ingress|egress]              - Detach TC program"
    echo "  status [iface]                               - Show TC status"
    echo ""
    echo "Examples:"
    echo "  $0 attach eth0 ingress tc_filter.bpf.o tc"
    echo "  $0 detach eth0 ingress"
    echo "  $0 status eth0"
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This command requires root privileges"
        exit 1
    fi
}

attach_tc() {
    local iface=$1
    local direction=$2
    local obj=$3
    local sec=${4:-tc}

    if [ -z "$iface" ] || [ -z "$direction" ] || [ -z "$obj" ]; then
        echo "Error: Interface, direction, and BPF object required"
        usage
    fi

    if [ "$direction" != "ingress" ] && [ "$direction" != "egress" ]; then
        echo "Error: Direction must be 'ingress' or 'egress'"
        exit 1
    fi

    if [ ! -f "$obj" ]; then
        echo "Error: BPF object '$obj' not found"
        exit 1
    fi

    echo "Attaching TC program to $iface ($direction)..."
    echo "  Object: $obj"
    echo "  Section: $sec"

    # Create clsact qdisc if it doesn't exist
    tc qdisc add dev $iface clsact 2>/dev/null || true

    # Attach filter
    if tc filter add dev $iface $direction bpf da obj $obj sec $sec; then
        echo "✓ TC program attached"
    else
        echo "✗ Failed to attach TC program"
        exit 1
    fi

    echo ""
    echo "Verify with: tc filter show dev $iface $direction"
}

detach_tc() {
    local iface=$1
    local direction=$2

    if [ -z "$iface" ]; then
        echo "Error: Interface required"
        usage
    fi

    echo "Detaching TC program from $iface..."

    if [ -n "$direction" ]; then
        if [ "$direction" != "ingress" ] && [ "$direction" != "egress" ]; then
            echo "Error: Direction must be 'ingress' or 'egress'"
            exit 1
        fi
        # Delete specific direction
        tc filter del dev $iface $direction 2>/dev/null || true
        echo "✓ TC $direction program detached from $iface"
    else
        # Delete both directions and qdisc
        tc qdisc del dev $iface clsact 2>/dev/null || true
        echo "✓ All TC programs detached from $iface"
    fi

    echo ""
    echo "Verify with: tc filter show dev $iface ingress"
}

show_status() {
    local iface=$1

    echo "TC Status:"
    echo ""

    if [ -n "$iface" ]; then
        echo "=== $iface ==="
        echo "Ingress:"
        tc filter show dev $iface ingress 2>/dev/null || echo "  No filters"
        echo ""
        echo "Egress:"
        tc filter show dev $iface egress 2>/dev/null || echo "  No filters"
    else
        echo "Interfaces with TC filters:"
        for dev in $(ip link show | grep -oP '^\d+: \K[^:]+' | grep -v lo); do
            INGRESS=$(tc filter show dev $dev ingress 2>/dev/null)
            EGRESS=$(tc filter show dev $dev egress 2>/dev/null)
            if [ -n "$INGRESS" ] || [ -n "$EGRESS" ]; then
                echo ""
                echo "=== $dev ==="
                [ -n "$INGRESS" ] && echo "Ingress: $INGRESS"
                [ -n "$EGRESS" ] && echo "Egress: $EGRESS"
            fi
        done
    fi

    echo ""
    echo "All loaded TC BPF programs:"
    bpftool prog show type sched_cls 2>/dev/null || echo "  No TC programs loaded"
}

# Main
case "$1" in
    attach)
        check_root
        attach_tc "$2" "$3" "$4" "$5"
        ;;
    detach)
        check_root
        detach_tc "$2" "$3"
        ;;
    status)
        show_status "$2"
        ;;
    *)
        usage
        ;;
esac

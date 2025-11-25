#!/bin/bash

# Lab 02: Inspect eBPF with bpftool
# Learn to use bpftool to examine running eBPF programs and maps

echo "========================================"
echo "Exploring eBPF with bpftool"
echo "========================================"
echo ""

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool not found"
    echo "Install it with: sudo apt install linux-tools-generic"
    exit 1
fi

echo "bpftool version:"
bpftool version
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script needs root privileges to inspect eBPF programs"
    echo "Re-running with sudo..."
    sudo "$0" "$@"
    exit $?
fi

echo "=== 1. List All Loaded BPF Programs ==="
echo ""
echo "Command: bpftool prog list"
echo ""

PROG_COUNT=$(bpftool prog list 2>/dev/null | grep -c "^[0-9]")

if [ $PROG_COUNT -eq 0 ]; then
    echo "No BPF programs currently loaded."
    echo "This is normal on a fresh system."
else
    echo "Found $PROG_COUNT loaded BPF program(s):"
    echo ""
    bpftool prog list
fi

echo ""
echo "=== 2. Show Detailed Program Information ==="
echo ""

if [ $PROG_COUNT -gt 0 ]; then
    # Get first program ID
    FIRST_PROG_ID=$(bpftool prog list 2>/dev/null | grep "^[0-9]" | head -1 | cut -d: -f1)

    echo "Showing details for program ID $FIRST_PROG_ID:"
    echo "Command: bpftool prog show id $FIRST_PROG_ID"
    echo ""
    bpftool prog show id $FIRST_PROG_ID

    echo ""
    echo "=== 3. Dump Program Instructions (Bytecode) ==="
    echo ""
    echo "Command: bpftool prog dump xlated id $FIRST_PROG_ID"
    echo ""
    echo "First 20 instructions:"
    bpftool prog dump xlated id $FIRST_PROG_ID 2>/dev/null | head -20
    echo "..."
    echo ""
    echo "(Use 'bpftool prog dump xlated id $FIRST_PROG_ID' to see full program)"

    echo ""
    echo "=== 4. Dump JIT-Compiled Code ==="
    echo ""
    echo "Command: bpftool prog dump jited id $FIRST_PROG_ID"
    echo ""

    if bpftool prog dump jited id $FIRST_PROG_ID &> /dev/null; then
        echo "First 20 lines of native assembly:"
        bpftool prog dump jited id $FIRST_PROG_ID 2>/dev/null | head -20
        echo "..."
    else
        echo "JIT dump not available (may need CONFIG_BPF_JIT_ALWAYS_ON=y)"
    fi
else
    echo "No programs loaded to inspect."
    echo ""
    echo "TIP: Some systems load BPF programs automatically (systemd, Docker)."
    echo "     You can load a simple program with the examples in ../src/"
fi

echo ""
echo "=== 5. List All BPF Maps ==="
echo ""
echo "Command: bpftool map list"
echo ""

MAP_COUNT=$(bpftool map list 2>/dev/null | grep -c "^[0-9]")

if [ $MAP_COUNT -eq 0 ]; then
    echo "No BPF maps currently exist."
else
    echo "Found $MAP_COUNT BPF map(s):"
    echo ""
    bpftool map list
fi

echo ""
echo "=== 6. Inspect a Map ==="
echo ""

if [ $MAP_COUNT -gt 0 ]; then
    # Get first map ID
    FIRST_MAP_ID=$(bpftool map list 2>/dev/null | grep "^[0-9]" | head -1 | cut -d: -f1)

    echo "Showing details for map ID $FIRST_MAP_ID:"
    echo "Command: bpftool map show id $FIRST_MAP_ID"
    echo ""
    bpftool map show id $FIRST_MAP_ID

    echo ""
    echo "Dumping map contents:"
    echo "Command: bpftool map dump id $FIRST_MAP_ID"
    echo ""

    MAP_ENTRIES=$(bpftool map dump id $FIRST_MAP_ID 2>/dev/null | grep -c "key:")

    if [ $MAP_ENTRIES -eq 0 ]; then
        echo "Map is empty (no entries)"
    else
        echo "Map has $MAP_ENTRIES entries. First 5:"
        echo ""
        bpftool map dump id $FIRST_MAP_ID 2>/dev/null | head -15
        if [ $MAP_ENTRIES -gt 5 ]; then
            echo "..."
            echo "(Use 'bpftool map dump id $FIRST_MAP_ID' to see all entries)"
        fi
    fi
else
    echo "No maps loaded to inspect."
fi

echo ""
echo "=== 7. List Pinned BPF Objects ==="
echo ""
echo "Pinned objects allow BPF programs/maps to persist across process restarts."
echo "Location: /sys/fs/bpf/"
echo ""

if [ -d /sys/fs/bpf ]; then
    PINNED_COUNT=$(find /sys/fs/bpf -type f 2>/dev/null | wc -l)

    if [ $PINNED_COUNT -eq 0 ]; then
        echo "No pinned objects found."
        echo ""
        echo "Objects can be pinned with:"
        echo "  bpftool prog pin id <ID> /sys/fs/bpf/my_program"
    else
        echo "Found $PINNED_COUNT pinned object(s):"
        echo ""
        find /sys/fs/bpf -type f 2>/dev/null | while read obj; do
            echo "  $obj"
            file "$obj" 2>/dev/null | sed 's/^/    /'
        done
    fi
else
    echo "BPF filesystem not mounted at /sys/fs/bpf"
    echo "Mount it with: mount -t bpf none /sys/fs/bpf"
fi

echo ""
echo "=== 8. Probe Kernel Features ==="
echo ""
echo "Command: bpftool feature probe kernel"
echo ""
echo "This shows all eBPF features available on your kernel."
echo "Output is verbose, showing sample:"
echo ""

bpftool feature probe kernel 2>/dev/null | head -30
echo "..."
echo ""
echo "(Run 'bpftool feature probe kernel' for full output)"

echo ""
echo "=== 9. Show BPF Statistics ==="
echo ""

if [ -f /proc/sys/kernel/bpf_stats_enabled ]; then
    STATS_ENABLED=$(cat /proc/sys/kernel/bpf_stats_enabled)

    if [ "$STATS_ENABLED" = "1" ]; then
        echo "✓ BPF statistics are enabled"
        echo ""
        if [ $PROG_COUNT -gt 0 ]; then
            echo "Program statistics:"
            bpftool prog show 2>/dev/null | grep -E "id|run_time_ns|run_cnt"
        fi
    else
        echo "⚠ BPF statistics are disabled"
        echo ""
        echo "To enable:"
        echo "  sudo sysctl kernel.bpf_stats_enabled=1"
        echo ""
        echo "This will show run_time_ns and run_cnt for each program"
    fi
else
    echo "⚠ Kernel doesn't support BPF statistics (need 5.1+)"
fi

echo ""
echo "=== 10. Useful bpftool Commands Summary ==="
echo ""

cat << 'EOF'
Core Commands:
  bpftool prog list                    # List all loaded programs
  bpftool prog show id <ID>            # Show program details
  bpftool prog dump xlated id <ID>     # Dump eBPF bytecode
  bpftool prog dump jited id <ID>      # Dump JIT-compiled assembly
  bpftool prog pin id <ID> <path>      # Pin program to filesystem

  bpftool map list                     # List all maps
  bpftool map show id <ID>             # Show map details
  bpftool map dump id <ID>             # Dump map contents
  bpftool map lookup id <ID> key <KEY> # Lookup specific key
  bpftool map update id <ID> key <K> value <V>  # Update map entry

  bpftool btf list                     # List BTF objects
  bpftool btf dump id <ID>             # Dump BTF info

  bpftool feature probe                # Probe kernel features

Output Formats:
  bpftool -j prog list                 # JSON output
  bpftool -p prog list                 # Pretty JSON output

Advanced:
  bpftool prog load <obj> <path>       # Load program from object file
  bpftool prog attach <prog> <type> <target>  # Attach to cgroup/etc
  bpftool net list                     # List network-attached programs
  bpftool cgroup tree                  # Show cgroup BPF attachments
EOF

echo ""
echo "========================================"
echo "Exploration Complete!"
echo "========================================"
echo ""
echo "Try these tasks:"
echo "  1. Pick a program and examine its bytecode"
echo "  2. Find a map and understand its key/value structure"
echo "  3. Check if any programs are attached to network hooks: bpftool net list"
echo "  4. Explore BTF: ../lab/04-btf-exploration.sh"
echo ""

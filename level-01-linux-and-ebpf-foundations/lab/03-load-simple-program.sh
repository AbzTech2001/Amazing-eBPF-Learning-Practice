#!/bin/bash

# Lab 03: Load a Simple eBPF Program
# This demonstrates loading a minimal tracepoint program

echo "========================================"
echo "Loading a Simple eBPF Program"
echo "========================================"
echo ""

# Check prerequisites
if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool not found"
    echo "Install: sudo apt install linux-tools-generic"
    exit 1
fi

# Check if the minimal program is built
PROG_DIR="../src"
PROG_OBJ="$PROG_DIR/minimal.bpf.o"
PROG_LOADER="$PROG_DIR/minimal_loader"

if [ ! -f "$PROG_OBJ" ]; then
    echo "eBPF program not built yet."
    echo "Building..."
    echo ""

    cd "$PROG_DIR" || exit 1

    if [ -f "Makefile" ]; then
        make
        BUILD_STATUS=$?
        cd - > /dev/null

        if [ $BUILD_STATUS -ne 0 ]; then
            echo ""
            echo "✗ Build failed!"
            echo ""
            echo "Common issues:"
            echo "  1. Missing clang: sudo apt install clang"
            echo "  2. Missing libbpf: sudo apt install libbpf-dev"
            echo "  3. Missing kernel headers: sudo apt install linux-headers-\$(uname -r)"
            echo ""
            echo "Run '../tools/setup-environment.sh' to install all dependencies"
            exit 1
        fi
    else
        echo "✗ Makefile not found in $PROG_DIR"
        exit 1
    fi
fi

echo "✓ Program is built: $PROG_OBJ"
echo ""

# Inspect the compiled object
echo "=== Inspecting Compiled eBPF Object ==="
echo ""
echo "File: $PROG_OBJ"
file "$PROG_OBJ"
echo ""

echo "Size: $(stat -c%s "$PROG_OBJ") bytes"
echo ""

# Show sections in the object
if command -v llvm-objdump &> /dev/null; then
    echo "Sections in the ELF object:"
    llvm-objdump -h "$PROG_OBJ" 2>/dev/null | grep -E "tracepoint|maps|\.text|BTF"
    echo ""
elif command -v readelf &> /dev/null; then
    echo "Sections in the ELF object:"
    readelf -S "$PROG_OBJ" 2>/dev/null | grep -E "tracepoint|maps|\.text|BTF"
    echo ""
fi

# Dump program bytecode from object file
echo "=== eBPF Bytecode (from object file) ==="
echo ""
echo "First 15 instructions:"
llvm-objdump -d "$PROG_OBJ" 2>/dev/null | head -25 || echo "(llvm-objdump not available)"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Loading eBPF programs requires root privileges."
    echo "Re-running with sudo..."
    echo ""
    sudo "$0" "$@"
    exit $?
fi

echo "=== Loading the Program ==="
echo ""

if [ -f "$PROG_LOADER" ]; then
    echo "Using custom loader: $PROG_LOADER"
    echo ""
    echo "The loader will:"
    echo "  1. Read the compiled eBPF object"
    echo "  2. Load it into the kernel via bpf() syscall"
    echo "  3. Attach to a tracepoint"
    echo "  4. Print events"
    echo ""
    echo "Running loader (press Ctrl+C to stop)..."
    echo ""

    $PROG_LOADER
else
    echo "Custom loader not found."
    echo ""
    echo "Alternative: Loading with bpftool..."
    echo ""

    # Pin location
    PIN_PATH="/sys/fs/bpf/minimal_prog"

    # Ensure bpf filesystem is mounted
    if ! mount | grep -q "type bpf"; then
        echo "Mounting BPF filesystem..."
        mount -t bpf none /sys/fs/bpf
    fi

    # Load program
    echo "Command: bpftool prog load $PROG_OBJ $PIN_PATH"
    bpftool prog load "$PROG_OBJ" "$PIN_PATH" 2>&1

    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Program loaded successfully!"
        echo ""

        # Show the loaded program
        echo "=== Inspecting Loaded Program ==="
        echo ""

        PROG_ID=$(bpftool prog show pinned "$PIN_PATH" | head -1 | cut -d: -f1)

        if [ -n "$PROG_ID" ]; then
            echo "Program ID: $PROG_ID"
            echo ""
            bpftool prog show id "$PROG_ID"
            echo ""

            # Try to attach to tracepoint
            echo "=== Attaching to Tracepoint ==="
            echo ""
            echo "Tracepoint programs are automatically attached when loaded with proper sections."
            echo "Check attachment:"
            echo ""
            bpftool prog tracelog 2>/dev/null &
            TRACELOG_PID=$!

            sleep 2

            echo "Triggering events (running 'ls' command)..."
            ls /tmp > /dev/null

            sleep 2

            kill $TRACELOG_PID 2>/dev/null || true

            echo ""
            echo "=== Cleanup ==="
            echo ""
            echo "Unloading program..."
            rm "$PIN_PATH" 2>/dev/null || true

            echo "✓ Cleaned up"
        else
            echo "Could not determine program ID"
        fi
    else
        echo ""
        echo "✗ Failed to load program"
        echo ""
        echo "Common errors:"
        echo "  1. Verifier rejection: Program doesn't meet safety requirements"
        echo "  2. Invalid tracepoint: The tracepoint doesn't exist"
        echo "  3. Missing BTF: Program requires BTF but kernel doesn't have it"
        echo ""
        echo "To debug, check dmesg for verifier logs:"
        echo "  sudo dmesg | tail -50"
    fi
fi

echo ""
echo "========================================"
echo "Program Lifecycle Summary"
echo "========================================"
echo ""
cat << 'EOF'
The journey of an eBPF program:

1. WRITE: Create minimal.bpf.c (source code)
   ├─ Define program type (tracepoint, kprobe, etc.)
   ├─ Write the logic
   └─ Use proper section names (e.g., SEC("tracepoint/..."))

2. COMPILE: clang → eBPF bytecode (minimal.bpf.o)
   ├─ clang -target bpf -O2 -c minimal.bpf.c
   ├─ Generates ELF object with eBPF bytecode
   └─ Includes BTF information

3. LOAD: User-space loader → kernel
   ├─ Open compiled object
   ├─ Call bpf() syscall with BPF_PROG_LOAD
   ├─ Kernel verifier checks safety
   ├─ JIT compiles to native code
   └─ Returns file descriptor

4. ATTACH: Connect to hook point
   ├─ Tracepoint: automatically attached via section name
   ├─ Kprobe: attach to kernel function
   ├─ XDP: attach to network interface
   └─ Other: various attachment methods

5. RUN: Execute when events occur
   ├─ Kernel event fires (syscall, packet, etc.)
   ├─ eBPF program runs
   ├─ Can write to maps
   └─ Can output to ring buffer

6. UNLOAD: Cleanup
   ├─ Close file descriptor
   ├─ Remove pinned objects
   └─ Kernel garbage collects program
EOF

echo ""
echo "Next steps:"
echo "  1. Read ../src/minimal.bpf.c to understand the code"
echo "  2. Modify it to trace different tracepoints"
echo "  3. Check available tracepoints: ls /sys/kernel/debug/tracing/events/"
echo "  4. Learn more about program types in Level 02"
echo ""

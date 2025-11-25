#!/bin/bash

# Lab 04: BTF (BPF Type Format) Exploration
# Learn about BTF and why it's critical for CO-RE (Compile Once, Run Everywhere)

echo "========================================"
echo "BTF (BPF Type Format) Exploration"
echo "========================================"
echo ""

# Check if BTF is available
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: BTF is not available on this kernel"
    echo ""
    echo "BTF requires kernel compiled with CONFIG_DEBUG_INFO_BTF=y"
    echo "Your kernel: $(uname -r)"
    echo ""
    echo "Without BTF, you cannot:"
    echo "  - Use CO-RE (Compile Once, Run Everywhere)"
    echo "  - Auto-generate vmlinux.h with kernel types"
    echo "  - Write portable eBPF programs"
    echo ""
    echo "Workarounds:"
    echo "  1. Upgrade to a kernel with BTF support (most modern distros)"
    echo "  2. Use non-CO-RE approach with manual struct definitions"
    echo "  3. Compile programs specifically for your kernel version"
    exit 1
fi

echo "✓ BTF is available!"
echo ""

# BTF file information
echo "=== BTF File Information ==="
echo ""
echo "Location: /sys/kernel/btf/vmlinux"

BTF_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux)
BTF_SIZE_KB=$(echo "scale=2; $BTF_SIZE / 1024" | bc 2>/dev/null)
BTF_SIZE_MB=$(echo "scale=2; $BTF_SIZE / 1024 / 1024" | bc 2>/dev/null)

echo "Size: $BTF_SIZE bytes ($BTF_SIZE_KB KB / $BTF_SIZE_MB MB)"
echo ""

# Check if bpftool is available
if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool not found"
    echo "Install it to explore BTF: sudo apt install linux-tools-generic"
    exit 1
fi

# Check for sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script needs root privileges to inspect BTF"
    echo "Re-running with sudo..."
    sudo "$0" "$@"
    exit $?
fi

echo "=== What is BTF? ==="
echo ""
cat << 'EOF'
BTF (BPF Type Format) is a compact metadata format that describes:
  1. Data types (structs, unions, enums, typedefs)
  2. Function signatures
  3. Global variables

Why BTF matters:
  - CO-RE: Write once, run on any kernel version
  - No manual struct definitions needed
  - vmlinux.h: Auto-generated header with all kernel types
  - Better debugging and introspection

Traditional approach (without BTF):
  struct task_struct {
    // Manually define fields...
    // Breaks when kernel version changes!
  };

CO-RE approach (with BTF):
  #include "vmlinux.h"  // Auto-generated from BTF
  // struct task_struct is automatically available
  // Field offsets auto-adjusted for your kernel
EOF

echo ""
echo ""
echo "=== Exploring BTF Contents ==="
echo ""

echo "1. Counting types in BTF..."
echo ""

STRUCT_COUNT=$(bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -c "^struct ")
UNION_COUNT=$(bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -c "^union ")
ENUM_COUNT=$(bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -c "^enum ")
TYPEDEF_COUNT=$(bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -c "^typedef ")

echo "  Structs:  $STRUCT_COUNT"
echo "  Unions:   $UNION_COUNT"
echo "  Enums:    $ENUM_COUNT"
echo "  Typedefs: $TYPEDEF_COUNT"
echo ""

echo "2. Example: Looking up 'struct task_struct'"
echo ""
echo "This is the kernel's process descriptor - the most important struct for tracing!"
echo ""

bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -A 30 "^struct task_struct {"
echo "  ... (many more fields)"
echo ""

echo "3. Example: Looking up 'struct file'"
echo ""
echo "This represents open files in the kernel:"
echo ""

bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -A 20 "^struct file {"
echo "  ... (more fields)"
echo ""

echo "4. Example: Looking up 'struct sk_buff'"
echo ""
echo "This is the socket buffer - used for network packet processing:"
echo ""

bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep -A 25 "^struct sk_buff {"
echo "  ... (more fields)"
echo ""

echo "=== Generating vmlinux.h ==="
echo ""
echo "vmlinux.h is a header file containing ALL kernel types."
echo "You include it in eBPF programs instead of individual kernel headers."
echo ""
echo "Generating vmlinux.h (this may take 10-30 seconds)..."
echo ""

OUTPUT_DIR="../src"
mkdir -p "$OUTPUT_DIR"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUTPUT_DIR/vmlinux.h"

if [ -f "$OUTPUT_DIR/vmlinux.h" ]; then
    LINES=$(wc -l < "$OUTPUT_DIR/vmlinux.h")
    SIZE=$(stat -c%s "$OUTPUT_DIR/vmlinux.h")
    SIZE_MB=$(echo "scale=2; $SIZE / 1024 / 1024" | bc 2>/dev/null)

    echo "✓ Generated: $OUTPUT_DIR/vmlinux.h"
    echo "  Lines: $LINES"
    echo "  Size: $SIZE bytes ($SIZE_MB MB)"
    echo ""
    echo "First 30 lines:"
    head -30 "$OUTPUT_DIR/vmlinux.h"
    echo "  ..."
    echo ""
    echo "You can now use this in your eBPF programs:"
    echo '  #include "vmlinux.h"'
    echo ""
else
    echo "✗ Failed to generate vmlinux.h"
fi

echo "=== CO-RE Example ==="
echo ""
cat << 'EOF'
Without CO-RE (manual struct definition):

  struct task_struct {
      unsigned long state;     // Offset might change!
      pid_t pid;               // Offset might change!
      // ... manual definition, breaks across kernels
  };

  int prog(struct pt_regs *ctx) {
      struct task_struct *task = (void *)bpf_get_current_task();
      pid_t pid = task->pid;  // WRONG if offset changed!
      return 0;
  }

With CO-RE (portable):

  #include "vmlinux.h"
  #include <bpf/bpf_core_read.h>

  int prog(struct pt_regs *ctx) {
      struct task_struct *task = (void *)bpf_get_current_task();
      pid_t pid = BPF_CORE_READ(task, pid);  // Correct across kernels!
      return 0;
  }

The BPF_CORE_READ macro uses BTF to find the correct offset at load time,
making your program portable across kernel versions!
EOF

echo ""
echo ""
echo "=== BTF for Loaded Programs ==="
echo ""
echo "Loaded BPF programs can also have BTF info:"
echo ""

bpftool btf list 2>/dev/null | head -20

BTF_OBJ_COUNT=$(bpftool btf list 2>/dev/null | grep -c "^[0-9]")

if [ $BTF_OBJ_COUNT -eq 0 ]; then
    echo "No BTF objects from loaded programs"
else
    echo ""
    echo "Found $BTF_OBJ_COUNT BTF object(s)"
fi

echo ""
echo "=== Searching BTF for Specific Types ==="
echo ""
echo "You can search for types related to your tracing needs:"
echo ""

echo "Example: Find all network-related structs:"
bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep "^struct " | grep -E "sock|tcp|udp|net" | head -15
echo "  ... (many more)"
echo ""

echo "Example: Find all file-related structs:"
bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null | grep "^struct " | grep -E "file|inode|dentry" | head -10
echo "  ... (more)"
echo ""

echo "=== Checking BTF for Specific Kernel Versions ==="
echo ""
echo "BTF can also be extracted from kernel modules:"
echo ""

if [ -d /sys/kernel/btf ]; then
    MODULE_BTF_COUNT=$(find /sys/kernel/btf -type f ! -name vmlinux 2>/dev/null | wc -l)

    if [ $MODULE_BTF_COUNT -gt 0 ]; then
        echo "Found BTF for $MODULE_BTF_COUNT kernel module(s):"
        echo ""
        find /sys/kernel/btf -type f ! -name vmlinux 2>/dev/null | head -10 | while read btf_file; do
            MODULE_NAME=$(basename "$btf_file")
            echo "  - $MODULE_NAME"
        done

        if [ $MODULE_BTF_COUNT -gt 10 ]; then
            echo "  ... (and $((MODULE_BTF_COUNT - 10)) more)"
        fi
    else
        echo "No module BTF files found (modules not loaded or no BTF)"
    fi
fi

echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo ""
echo "BTF provides:"
echo "  ✓ Type information for all kernel structs/unions/enums"
echo "  ✓ Enables CO-RE (portable eBPF programs)"
echo "  ✓ Auto-generated vmlinux.h (no manual struct definitions)"
echo "  ✓ Better debugging and introspection"
echo ""
echo "Key files created:"
echo "  - $OUTPUT_DIR/vmlinux.h (use in your eBPF programs)"
echo ""
echo "Next steps:"
echo "  1. Examine vmlinux.h to see available kernel types"
echo "  2. Search for structs you want to trace:"
echo "     grep 'struct task_struct' $OUTPUT_DIR/vmlinux.h"
echo "  3. Level 03 will cover using CO-RE in practice"
echo ""
echo "Useful commands:"
echo "  bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep 'struct <name>'"
echo "  bpftool btf dump file /sys/kernel/btf/vmlinux > vmlinux.h"
echo ""

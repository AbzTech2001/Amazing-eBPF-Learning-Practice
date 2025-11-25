# Makefile for Level 01 - Minimal eBPF Program
#
# This Makefile compiles:
# 1. minimal.bpf.c → minimal.bpf.o (eBPF bytecode)
# 2. minimal_loader.c → minimal_loader (user-space executable)

# Compiler and flags
CLANG ?= clang
LLC ?= llc
CC ?= gcc

# Architecture
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
LIBBPF_DIR ?= /usr/include
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)

# BPF compilation flags
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I$(LIBBPF_DIR)
BPF_CFLAGS += -I$(KERNEL_HEADERS)/include
BPF_CFLAGS += -I$(KERNEL_HEADERS)/include/uapi
BPF_CFLAGS += -I$(KERNEL_HEADERS)/arch/$(ARCH)/include
BPF_CFLAGS += -Wall -Werror

# User-space compilation flags
USER_CFLAGS := -g -O2 -Wall -Werror
USER_LDFLAGS := -lbpf -lelf -lz

# Targets
BPF_OBJ := minimal.bpf.o
LOADER := minimal_loader

.PHONY: all clean check help

all: $(BPF_OBJ) $(LOADER)

# Compile eBPF program
$(BPF_OBJ): minimal.bpf.c
	@echo "Compiling eBPF program: $< → $@"
	@echo "  Compiler: $(CLANG)"
	@echo "  Target: BPF bytecode"
	@echo "  Architecture: $(ARCH)"
	@echo ""
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✓ eBPF bytecode generated: $@"
	@echo ""
	@echo "Inspecting object file:"
	@file $@
	@echo ""
	@if command -v llvm-objdump >/dev/null 2>&1; then \
		echo "Sections:"; \
		llvm-objdump -h $@ | grep -E "Name|tracepoint|maps|\.text|BTF"; \
	fi
	@echo ""

# Compile user-space loader
$(LOADER): minimal_loader.c $(BPF_OBJ)
	@echo "Compiling user-space loader: $< → $@"
	@echo "  Compiler: $(CC)"
	@echo "  Linking with: libbpf, libelf, libz"
	@echo ""
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)
	@echo "✓ Loader compiled: $@"
	@echo ""

# Check prerequisites
check:
	@echo "========================================="
	@echo "Checking build prerequisites"
	@echo "========================================="
	@echo ""
	@command -v $(CLANG) >/dev/null 2>&1 && echo "✓ clang found: $$($(CLANG) --version | head -1)" || echo "✗ clang not found"
	@command -v $(CC) >/dev/null 2>&1 && echo "✓ gcc found: $$($(CC) --version | head -1)" || echo "✗ gcc not found"
	@test -f $(LIBBPF_DIR)/bpf/bpf.h && echo "✓ libbpf headers found" || echo "✗ libbpf headers not found"
	@test -d $(KERNEL_HEADERS) && echo "✓ kernel headers found: $(KERNEL_HEADERS)" || echo "✗ kernel headers not found"
	@command -v bpftool >/dev/null 2>&1 && echo "✓ bpftool found: $$(bpftool version 2>&1 | head -1)" || echo "✗ bpftool not found"
	@echo ""
	@echo "If any checks failed, run: ../tools/setup-environment.sh"
	@echo ""

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BPF_OBJ) $(LOADER)
	rm -f *.o *.ll
	@echo "✓ Clean complete"

# Help
help:
	@echo "Makefile for Level 01 - Minimal eBPF Program"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build eBPF program and loader (default)"
	@echo "  check   - Check if all build tools are available"
	@echo "  clean   - Remove build artifacts"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make           # Build everything"
	@echo "  make check     # Verify prerequisites"
	@echo "  make clean     # Clean up"
	@echo ""
	@echo "After building:"
	@echo "  sudo ./$(LOADER)    # Run the loader"
	@echo ""
	@echo "To see program output:"
	@echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
	@echo ""

# Advanced: Generate LLVM IR (for learning)
%.ll: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -S -emit-llvm $< -o $@
	@echo "Generated LLVM IR: $@"
	@echo "This shows the intermediate representation before BPF bytecode"

# Advanced: Disassemble BPF bytecode
disasm: $(BPF_OBJ)
	@echo "========================================="
	@echo "Disassembling BPF bytecode"
	@echo "========================================="
	@echo ""
	@if command -v llvm-objdump >/dev/null 2>&1; then \
		llvm-objdump -d $(BPF_OBJ); \
	else \
		echo "llvm-objdump not found. Install with: sudo apt install llvm"; \
	fi

# Advanced: Dump BTF information
btf: $(BPF_OBJ)
	@echo "========================================="
	@echo "BTF Information in $(BPF_OBJ)"
	@echo "========================================="
	@echo ""
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file $(BPF_OBJ); \
	else \
		echo "bpftool not found. Install with: sudo apt install linux-tools-generic"; \
	fi

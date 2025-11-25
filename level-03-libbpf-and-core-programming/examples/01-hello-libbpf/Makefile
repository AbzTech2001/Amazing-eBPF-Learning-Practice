# Makefile for hello-libbpf example
#
# Build process:
# 1. Compile eBPF program to bytecode (hello.bpf.o)
# 2. Generate skeleton header (hello.skel.h)
# 3. Compile user-space loader (hello)

# Tools
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= gcc

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Directories
OUTPUT := .output
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

# Compiler flags
INCLUDES := -I$(OUTPUT) -I../../include -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS := -g -Wall -O2
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

# Libraries
LDFLAGS := -lelf -lz

.PHONY: all clean

all: hello

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Step 1: Compile eBPF program
$(OUTPUT)/hello.bpf.o: hello.bpf.c | $(OUTPUT)
	@echo "=== Compiling eBPF program ==="
	@echo "Input:  hello.bpf.c"
	@echo "Output: $(OUTPUT)/hello.bpf.o"
	@echo ""
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "✓ eBPF bytecode generated"
	@echo ""

# Step 2: Generate skeleton
$(OUTPUT)/hello.skel.h: $(OUTPUT)/hello.bpf.o
	@echo "=== Generating BPF skeleton ==="
	@echo "Input:  $(OUTPUT)/hello.bpf.o"
	@echo "Output: $(OUTPUT)/hello.skel.h"
	@echo ""
	$(BPFTOOL) gen skeleton $< > $@
	@echo "✓ Skeleton header generated"
	@echo "  The skeleton provides type-safe access to:"
	@echo "    - hello_bpf__open()"
	@echo "    - hello_bpf__load()"
	@echo "    - hello_bpf__attach()"
	@echo "    - hello_bpf__destroy()"
	@echo ""

# Step 3: Compile user-space loader
hello: hello.c $(OUTPUT)/hello.skel.h
	@echo "=== Compiling user-space loader ==="
	@echo "Input:  hello.c"
	@echo "Output: hello (executable)"
	@echo ""
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< -lbpf $(LDFLAGS)
	@echo "✓ User-space loader compiled"
	@echo ""
	@echo "=== Build Complete! ==="
	@echo ""
	@echo "To run:"
	@echo "  $$ sudo ./hello"
	@echo ""
	@echo "To see kernel output:"
	@echo "  $$ sudo cat /sys/kernel/debug/tracing/trace_pipe"
	@echo ""

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT) hello
	@echo "✓ Clean complete"

# Help
help:
	@echo "Makefile for hello-libbpf example"
	@echo ""
	@echo "Targets:"
	@echo "  all (default) - Build the complete program"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Build process:"
	@echo "  1. Compile eBPF C code to BPF bytecode"
	@echo "  2. Generate skeleton header with bpftool"
	@echo "  3. Compile user-space loader with skeleton"
	@echo ""
	@echo "Requirements:"
	@echo "  - clang (for eBPF compilation)"
	@echo "  - llvm-strip (for stripping debug info)"
	@echo "  - bpftool (for skeleton generation)"
	@echo "  - gcc (for user-space compilation)"
	@echo "  - libbpf-dev (headers and libraries)"
	@echo ""

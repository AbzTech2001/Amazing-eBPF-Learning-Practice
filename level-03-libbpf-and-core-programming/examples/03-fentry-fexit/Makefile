# Makefile for fentry/fexit function latency tracer

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LDFLAGS := $(shell pkg-config --libs libbpf)

TARGET = function_latency
BPF_OBJ = function_latency.bpf.o
SKEL = function_latency.skel.h

.PHONY: all clean vmlinux

all: $(TARGET)

# Generate vmlinux.h from kernel BTF
vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

# Compile eBPF program
$(BPF_OBJ): function_latency.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		$(LIBBPF_CFLAGS) \
		-c function_latency.bpf.c -o $(BPF_OBJ)

# Generate BPF skeleton
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

# Compile user-space program
$(TARGET): function_latency.c $(SKEL)
	gcc -g -Wall -o $(TARGET) function_latency.c \
		$(LIBBPF_CFLAGS) $(LIBBPF_LDFLAGS) -lelf -lz

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) vmlinux.h

run: $(TARGET)
	sudo ./$(TARGET)

# Show BPF program info
info: $(BPF_OBJ)
	$(BPFTOOL) prog show
	$(BPFTOOL) map show

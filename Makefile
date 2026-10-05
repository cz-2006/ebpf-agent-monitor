# libbpf CO-RE 构建链：生成 vmlinux.h -> 编译 BPF 对象 -> 生成 skeleton
# -> 编译并链接用户态监控器。build/ 全部是可再生文件，不应手工修改。
BUILD_DIR := build
INCLUDE_DIR := include
SRC_DIR := src

CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
BPF_ARCH ?= x86

VMLINUX := $(BUILD_DIR)/vmlinux.h
BPF_OBJ := $(BUILD_DIR)/monitor.bpf.o
SKEL := $(BUILD_DIR)/monitor.skel.h
MONITOR := $(BUILD_DIR)/monitor

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-I$(BUILD_DIR) -I$(INCLUDE_DIR) -Wall -Werror \
	-Wno-missing-declarations
USER_CFLAGS := -g -O2 -I$(BUILD_DIR) -I$(INCLUDE_DIR) \
	-Wall -Wextra -Werror
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)

.PHONY: all clean

all: $(MONITOR)

$(BUILD_DIR):
	mkdir -p $@

# 从当前内核 BTF 生成 CO-RE 类型定义。
$(VMLINUX): | $(BUILD_DIR)
	@tmp=$@.tmp; \
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $$tmp && \
	mv $$tmp $@

# 编译运行在内核中的 eBPF 程序。
$(BPF_OBJ): $(SRC_DIR)/monitor.bpf.c $(INCLUDE_DIR)/events.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 生成供用户态加载 BPF 对象的 skeleton 头文件。
$(SKEL): $(BPF_OBJ)
	@tmp=$@.tmp; \
	$(BPFTOOL) gen skeleton $< > $$tmp && \
	mv $$tmp $@

# 编译并链接用户态监控程序。
$(MONITOR): $(SRC_DIR)/monitor.c $(SRC_DIR)/detector.c \
	$(SRC_DIR)/resource_sampler.c $(INCLUDE_DIR)/events.h \
	$(INCLUDE_DIR)/detector.h $(INCLUDE_DIR)/resource_sampler.h $(SKEL)
	$(CC) $(USER_CFLAGS) $(LIBBPF_CFLAGS) \
		$(SRC_DIR)/monitor.c $(SRC_DIR)/detector.c \
		$(SRC_DIR)/resource_sampler.c -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf $(BUILD_DIR)

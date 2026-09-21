# eBPF 多智能体异常监测项目：环境与后续计划

> 记录时间：2026-09-14  
> 用途：赛题 32「基于 eBPF 的系统级多智能体异常监测框架与方法」

## 1. 当前开发环境

当前整体架构：

```text
Windows 宿主机
├── VS Code
├── 浏览器 / ChatGPT
└── SSH: localhost:2222
        ↓
Ubuntu 24.04.3 VirtualBox 虚拟机
├── Linux Kernel 7.0.0-31-generic
├── SSH Server
├── Codex CLI 0.154.0
├── clang / LLVM
├── libbpf
├── bpftool
├── bpftrace
├── BCC
└── eBPF 项目代码
```

赛题要求：

```text
Linux Kernel >= 5.15
```

当前内核：

```text
7.0.0-31-generic
```

满足要求。

---

## 2. VirtualBox 配置

```text
系统：Ubuntu 24.04.3 Desktop AMD64
内存：6 GB
CPU：4 vCPU
虚拟硬盘：60 GB，动态分配
EFI：关闭
虚拟机目录：D:\VirtualBox VMs\
ISO：D:\ubuntu-24.04.3-desktop-amd64.iso
网络：NAT
```

SSH 端口转发：

```text
Host IP: 127.0.0.1
Host Port: 2222
Guest Port: 22
Protocol: TCP
```

Windows SSH 配置：

```ssh
Host ubuntu-vm
    HostName 127.0.0.1
    User felix
    Port 2222
```

连接：

```powershell
ssh ubuntu-vm
```

---

## 3. eBPF 开发工具链

核心开发包：

```text
build-essential
clang
llvm
libbpf-dev
libelf-dev
zlib1g-dev
pkg-config
cmake
ninja-build
git
bpftrace
bpfcc-tools
python3-bpfcc
libbpf-tools
linux-tools-common
linux-tools-$(uname -r)
linux-headers-$(uname -r)
python3-venv
python3-pip
jq
curl
strace
```

关键工具：

```text
clang / LLVM
libbpf
bpftool
bpftrace
BCC
Linux headers
BTF
```

已可运行：

```bash
sudo bpftool feature probe
```

后续建议采用：

```text
libbpf + CO-RE
```

作为正式实现方案，`bpftrace` 和 BCC 主要用于快速实验与验证。

---

## 4. VS Code 与 Codex

推荐工作方式：

```text
Windows VS Code
    ↓ Remote SSH
Ubuntu VM
    ↓
/home/felix/projects/ebpf-agent-monitor
```

源码、编译、测试、eBPF 运行环境全部放在 Ubuntu 中。

Codex CLI 已安装：

```text
Codex CLI 0.154.0
```

正式项目中建议：

```bash
mkdir -p ~/projects/ebpf-agent-monitor
cd ~/projects/ebpf-agent-monitor
codex
```

恢复最近一次 Codex 会话：

```bash
codex resume --last
```

建议在项目根目录维护：

```text
AGENTS.md
```

用于记录项目背景、架构、约束、开发规范和当前进度，作为 Codex 的项目级长期上下文。

---

## 5. 推荐系统架构

```text
eBPF C
    ↓
clang / LLVM
    ↓
libbpf + CO-RE
    ↓
BPF Ring Buffer
    ↓
Userspace Collector
    ↓
Correlation Engine
    ↓
Anomaly Detector
    ↓
Alert / Attribution
```

核心思路：

```text
内核态负责轻量采集
用户态负责关联、检测与归因
```

---

## 6. 第一阶段需要实现的观测能力

### 进程

```text
execve
fork / clone
exit
```

### 文件

```text
openat
unlink
unlinkat
rename
```

### 网络

```text
connect
destination IP
destination port
```

统一事件建议至少包含：

```text
timestamp
pid
tid
ppid
uid
comm
event_type
target
```

---

## 7. 第一阶段异常检测目标

优先完成赛题基础项：

```text
Unexpected Shell Launch
Sensitive File Access
Out-of-workspace Delete
High-frequency API / Network Calls
Repeated Process / File Activity
```

重点不是单纯捕获大量 syscall，而是建立：

```text
Agent
→ Prompt / Interaction
→ Process Tree
→ System Call
→ Resource / File / Network Operation
→ Alert
```

这样的跨层关联链路。

---

## 8. 后续重点方向

### Agent 归属

建立：

```text
PID / PPID / process tree / cgroup
→ agent_id
```

用于多智能体并发场景下区分不同 Agent。

### 跨层语义关联

目标是把：

```text
Prompt
→ Agent
→ Model Response
→ Shell / Child Process
→ File / Network Operation
```

串成因果链。

### HTTPS 明文捕获

后期研究：

```text
uprobes
OpenSSL
SSL_read / SSL_write
```

但需要根据具体 Agent 的 TLS 实现决定实际 Hook 点。

### 多智能体场景

后期可引入：

```text
Docker
cgroup
namespace
```

帮助模拟和区分多个 Agent。

---

## 9. 性能与最终评测

VirtualBox 适合：

```text
开发
功能验证
调试
原型测试
```

但赛题要求：

```text
数据捕获性能损耗 <= 5%
```

正式性能评测应尽量在：

```text
真实 Linux 机器
实验室服务器
比赛指定环境
```

中完成，避免 VirtualBox 带来的虚拟化噪声。

---

## 10. 下一步任务

近期按以下顺序推进：

```text
1. 创建 ~/projects/ebpf-agent-monitor
2. 创建 AGENTS.md
3. 验证 bpftrace execve 监控
4. 编写第一个 libbpf CO-RE execve collector
5. 加入 fork / openat / unlink / connect
6. 设计统一事件结构
7. 实现用户态 Collector
8. 建立 PID / PPID → agent_id 映射
9. 实现基础异常规则
10. 增加告警日志与归因信息
11. 再研究 uprobes 与 Prompt / Response 关联
12. 最后进行性能测试与优化
```

---

## 11. 重要限制

VirtualBox 内的 eBPF 只能观测 Ubuntu 虚拟机内部的进程和系统调用。

因此需要被监控的 Agent 应运行在 Ubuntu VM 中，而不是 Windows 宿主机中。

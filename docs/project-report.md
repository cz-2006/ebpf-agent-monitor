# 基于 eBPF 的系统级多智能体异常监测框架项目报告

更新时间：2026-10-06

## 摘要

本项目面向同一 Linux 设备中多个 AI Agent 并发运行时的系统行为监测问题，设计并
实现了一个基于 eBPF 的系统级异常监测原型。系统不修改 Linux 内核源码，也不修改
被监控 Agent，而是通过受控启动将每个 Agent 放入独立的 cgroup v2，以 cgroup ID
作为稳定的归属依据。内核态 eBPF 程序利用 tracepoint 和 BPF LSM 采集进程、文件与
网络事件，通过 Ring Buffer 传递给用户态；用户态负责生命周期管理、事件解析、资源
采样、规则匹配和告警输出。

当前系统能够同时管理最多 16 个 Agent，采集 "execve"、"fork"、进程退出、文件打开、
文件删除尝试、失败 "openat"、IPv4/IPv6 "connect" 等行为，并检测非预期 Shell、敏感
文件读取、工作区外删除、重复失败文件打开以及“重复失败打开 + 高 CPU”联合异常。
确定性双 Agent 验收的 11 项检查已全部通过，真实 Codex/Qwen Agent 的文件、网络、
Shell、敏感读取和工作区外删除行为也完成了受控验证。项目尚未实现 HTTPS 明文捕获、
Prompt/Response 精确因果关联和多 Agent 协作/竞争异常识别，性能也尚未达到赛题提出
的 5% 参考指标。

## 1. 项目总体实现

### 1.1 总体架构

系统采用“内核态轻量采集、用户态关联分析”的分层架构：

```text
用户配置与受控启动
        ↓
每个 Agent 独立 cgroup v2
        ↓
cgroup_id → agent_id BPF map
        ↓
tracepoint / BPF LSM 采集进程、文件、网络事件
        ↓
统一事件结构 → BPF Ring Buffer
        ↓
用户态 Collector → Detector ← cgroup cpu.stat 采样
        ↓
活动证据 / 安全告警 / 资源与逻辑联合异常
```

内核态只完成 Agent 过滤、系统调用入口与返回配对、真实路径解析和事件提交。复杂的
路径策略、时间窗口、跨事件状态以及 CPU 联合判断放在用户态完成。这种划分降低了
eBPF verifier 验证难度，也使检测规则可以在不重新设计内核采集协议的情况下扩展。

项目各核心模块如下：

| 模块 | 文件 | 作用 |
| --- | --- | --- |
| 共享事件协议 | "include/events.h" | 定义公共事件头和七类事件载荷 |
| eBPF 数据面 | "src/monitor.bpf.c" | 挂载观测点、过滤 cgroup、生成事件 |
| 用户态控制面 | "src/monitor.c" | 启动 Agent、管理 cgroup、加载 BPF、消费事件 |
| 异常检测器 | "src/detector.c" | 保存每个 Agent 的策略和检测状态，输出告警 |
| 资源采样器 | "src/resource_sampler.c" | 读取 cgroup "cpu.stat" 并计算 CPU 使用率 |
| 构建系统 | "Makefile" | 完成 libbpf CO-RE 构建链 |
| 验证与评测 | "experiments/" | 工作负载、真实 Agent 演示和性能测量 |

### 1.2 一条事件的处理过程

以 Agent 读取文件为例：Agent 内的 "cat" 进程打开文件后，BPF LSM 的 "file_open"
钩子被触发；eBPF 程序读取当前 cgroup ID，在 "agent_by_cgroup" map 中找到对应的
"agent_id"，再使用 "bpf_d_path" 获得内核解析后的真实路径。事件与时间戳、PID、TID、
PPID、UID、进程名和 cgroup ID 一起写入 Ring Buffer。用户态 Collector 校验事件长度
并交给 Detector。如果路径位于该 Agent 配置的敏感目录内，Detector 输出
"sensitive_file_access" 高危告警。

## 2. 各项任务的具体实现

### 2.1 多 Agent 受控启动与行为归属

多 Agent 监测首先要解决“一个系统事件属于哪个 Agent”的问题。项目没有把 PID 树
作为唯一归属依据，因为进程可能重父化，PID 也可能复用。系统为每个 "--agent ID"
创建独立 cgroup v2，并在目标进程开始执行业务代码前，将
"cgroup_id → agent_id" 写入 BPF map。线程和子进程会自然继承所属 cgroup，因此即使
Agent 创建工具子进程，或者根进程先退出、后代被 PID 1 接管，事件仍能保持正确归属。

启动过程使用两阶段门控：子进程先在原 cgroup 中完成 "initgroups"；父进程收到准备
完成信号后，将子进程迁入 Agent cgroup、核验迁移结果、登记 BPF map，再放行子进程；
子进程随后执行 "setresgid"、"setresuid" 并 "exec" 目标命令。这样既保证第一条业务
"execve" 发生前归属映射已经建立，也避免把 root 身份下的用户组和 NSS 准备访问误记
为 Agent 行为。

根进程退出后，监控器不会立刻注销 Agent。它继续读取 "cgroup.events" 中的
"populated" 状态，直到 cgroup 内所有后代退出，才输出 "agent_cgroup_drained" 和最终
"agent_exit ... basis=cgroup_empty"，然后删除 BPF map 中的映射。

### 2.2 进程管理行为采集

进程任务使用三个 tracepoint：

- "sys_enter_execve" 产生 "EXEC_ATTEMPT"，记录目标程序路径。该事件只表示执行尝试，
  不宣称执行一定成功。
- "sched_process_fork" 产生 "PROCESS_FORK"，记录父 PID、子 PID 和子进程名。
- "sched_process_exit" 产生 "PROCESS_EXIT"，记录当前任务和内核原始退出状态。

每个探针首先读取当前 cgroup ID，只有已经登记的 Agent cgroup 才提交事件，从源头
过滤 VS Code、终端和系统服务等无关进程。PID/TID/PPID 用于回溯进程关系，cgroup ID
和 agent ID 用于业务归属。

### 2.3 文件打开与真实路径采集

文件任务同时使用 BPF LSM 和 syscall tracepoint，因为两者解决的问题不同。

对于成功到达文件对象层的打开操作，"lsm/file_open" 可以获得可信的 "struct file"，
系统使用 "bpf_d_path" 解析内核中的真实路径，同时记录打开 flags。这满足了赛题对真实
文件路径的要求。"FILE_OPEN" 还支持每 N 次采样一次，用于降低高频文件事件的开销；
敏感目录规则启用时仍需谨慎使用抽样，以免漏掉关键访问。

不存在的文件不会形成 "struct file"，因此不会触发可供路径解析的 "file_open"。
系统另外在 "sys_enter_openat" 保存 "dirfd" 和用户传入路径，在 "sys_exit_openat"
读取返回值，并只为失败调用提交 "FILE_OPEN_RESULT"。入口状态以完整 "pid_tgid" 为 key
保存在 "pending_openats" map 中，避免多线程互相覆盖。失败事件中的路径明确标记为
“还原尝试路径”，不冒充内核规范路径。

### 2.4 文件删除行为采集

删除任务使用 BPF LSM "path_unlink"。该钩子提供可信父目录 path 和目标 dentry，eBPF
分别读取父目录真实路径与文件名，用户态再组合为完整目标路径，生成
"FILE_UNLINK_ATTEMPT"。

这个钩子发生在删除操作执行前，因此事件语义是“删除尝试”，不能单凭该事件证明删除
最终成功。实验中通过工作负载返回值和目标文件是否仍存在辅助验证结果。当前正式原型
尚未覆盖 "unlinkat"、"rename" 和 "openat2" 的完整语义。

### 2.5 网络连接 IP 与端口采集

网络任务在 "sys_enter_connect" 和 "sys_exit_connect" 之间配对。入口处读取 socket fd
和用户态 "sockaddr"，解析 IPv4 或 IPv6 地址及网络字节序端口，并把数据写入
"pending_connects" map；返回点取得系统调用返回值，组合为 "CONNECT_RESULT" 后提交。

这种设计既能记录成功连接，也能记录 "ECONNREFUSED" 等失败连接。真实 Codex Agent
常使用非阻塞网络，"ret=-115" 表示 "EINPROGRESS"，只说明连接正在建立，不能当作最终
成功。系统记录的是 TCP 连接目标，也不会把每条连接直接等同于一次模型 API 请求。

### 2.6 非预期 Shell 检测

Detector 从 "EXEC_ATTEMPT" 中提取可执行文件 basename，并精确匹配 "sh"、"bash"、
"dash"、"zsh"、"ksh" 和 "fish"，避免仅按字符串包含关系造成误报。每个 Agent 可配置：

- "deny"：输出 high 级别 "unexpected_shell" 安全告警；
- "audit"：输出 "shell_execution" 活动证据；
- "allow"：不输出 Shell 规则结果；
- 未配置：关闭该规则。

真实 Codex 框架自身会正常使用 Bash，因此三态策略比“看到 Shell 就报警”更符合真实
运行环境。该原型当前负责观测和告警，不实际阻止 Shell 执行。

### 2.7 敏感文件读取检测

用户通过 "--sensitive-path DIR" 为每个 Agent 配置敏感目录。Detector 处理
"FILE_OPEN" 时检查目标是否位于该目录边界内，并根据 "O_ACCMODE" 排除纯写打开，根据
"O_DIRECTORY" 排除目录遍历。满足条件时输出 high 级别
"sensitive_file_access" 告警。

策略目录会被规范化为绝对路径并以目录边界匹配，避免把 "/tmp/secrets-old" 错误视为
"/tmp/secrets/" 的子目录。规则表达的是部署者给出的策略，而不是系统自动理解业务
权限。

### 2.8 工作区外删除检测

用户通过 "--workspace DIR" 指定 Agent 可操作的业务工作区，通过可重复的
"--runtime-path DIR" 指定 Codex、Bubblewrap 等框架需要清理的运行目录。Detector 对
每条 "FILE_UNLINK_ATTEMPT" 进行三级判断：

- workspace 内删除：视为允许的业务行为，不输出；
- runtime path 内删除：输出 "runtime_file_delete" 审计证据；
- 其他位置删除：输出 high 级别 "outside_workspace_delete" 告警。

实现依据目标真实路径和显式策略判断，没有按进程名硬编码放行。真实 Agent 测试中，
指定工作区外的测试文件触发了唯一高危告警，而 Codex/Bubblewrap 的正常运行时清理
被降级为审计证据。

### 2.9 重复失败文件活动检测

Detector 对失败的 "FILE_OPEN_RESULT" 进行用户态关联，按“同一 agent ID、同一目标
路径、同一时间窗口”保存状态。默认实验条件是在 2 秒内对同一路径连续 5 次返回
"ENOENT"。达到阈值时输出 medium 级别 "repeated_failed_open"，并携带次数、阈值、
窗口和路径还原依据。

该规则代表一种重复、无意义的底层文件活动证据。它本身不等同于逻辑死循环，所以
系统没有仅凭五次失败打开就输出资源/逻辑高危异常。

### 2.10 CPU 资源采样与联合异常检测

用户态资源采样器周期读取每个 Agent cgroup 的 "cpu.stat"，提取 "usage_usec"。相邻
样本的 CPU 时间增量除以单调墙钟时间增量，得到以单逻辑 CPU 为 100% 的使用率。

Detector 只有在同一个 Agent、同一个时间窗口内同时发现以下两类证据时，才输出 high
级别 "resource_logic_anomaly"：

1. 同一路径达到重复失败打开阈值；
2. cgroup CPU 使用率超过配置阈值。

三 Agent 对照实验分别安排“只有重复失败”“只有高 CPU”和“两者同时存在”，只有第
三组触发联合异常，验证了证据没有跨 Agent 串组。该规则只是资源浪费的一种受控模型，
尚未覆盖高频 API、重复 Prompt 或通用逻辑死循环。

### 2.11 告警输出与归因定位

内核态和用户态共享 "monitor_event_header"。所有事件包含单调时间戳、事件长度、类型、
PID、TID、PPID、UID、进程名、cgroup ID 和 agent ID；各事件再附加目标路径、程序名、
网络地址或返回值等专属载荷。用户态在解析前同时校验 Ring Buffer 实际长度和头部
声明长度，防止协议不一致导致错误读取。

检测结果分为三类：

- "activity_evidence"：单项活动证据或审计信息；
- "security_alert"：Shell、敏感读取、工作区外删除等安全告警；
- "anomaly_alert"：多维证据联合形成的资源/逻辑异常。

每条告警均携带时间、PID/TID、agent ID、cgroup ID、操作对象、策略和 evidence 字段，
可以回溯到具体 Agent 和底层行为。当前尚不能将特定 Prompt/Response 与某次系统调用
建立精确因果关系。

### 2.12 构建、兼容和工程实现

项目使用 libbpf CO-RE。"Makefile" 首先从本机 BTF 生成 "vmlinux.h"，再用 Clang 编译
eBPF 对象，通过 bpftool 生成 skeleton，最后把用户态程序与 libbpf 链接为
"build/monitor"。共享协议由内核态和用户态共同包含，减少手工解析偏差。

目标内核要求为 Linux 5.15 及以上。当前开发环境为 Ubuntu VirtualBox，内核已启用
BPF LSM。源码在 "-Wall -Wextra -Werror" 下构建通过，但尚未在 Linux 5.15 实机完成
兼容性复测。

## 3. 已有演示文件的代码与输出解说

项目提供三类主要演示：不调用模型的确定性验收、调用一个真实 Agent 的简单演示、
调用两个真实 Agent 的全面演示。此外还有两组性能演示。所有脚本都应在项目根目录
以普通用户运行，脚本需要加载 eBPF 时会自行调用 "sudo"。

### 3.1 确定性双 Agent 验收演示

入口文件是 "experiments/run_acceptance_demo.sh"，工作负载实现位于
"experiments/acceptance_demo_agent.py"。运行命令为：

```bash
./experiments/run_acceptance_demo.sh
```

脚本先在 "/tmp" 下创建独立测试目录和三个无害文件，再用一条 monitor 命令启动两个
Agent：

```bash
sudo "$monitor" --hide-runtime-noise --events process,file,network \
  --agent 1 --sensitive-path "$sensitive_dir" --workspace "$workspace" \
  --failed-open-threshold 5 --failed-open-window-ms 2000 \
  --cpu-sample-ms 200 --cpu-threshold-percent 50 \
  -- /usr/bin/python3 "$workload" security ... \
  --next \
  --agent 2 --shell-policy deny \
  -- /usr/bin/python3 "$workload" process-network
```

Agent 1 执行安全与资源工作负载。其 Python 代码依次读取敏感文件、删除工作区内文件、
删除工作区外文件、五次打开同一个不存在文件，最后进行约 1.2 秒 CPU 忙循环：

```python
content = sensitive.read_text(encoding="utf-8").strip()
allowed.unlink()
outside.unlink()
for attempt in range(1, 6):
    try:
        missing.open("rb")
    except FileNotFoundError:
        pass
while time.monotonic() < deadline:
    checksum = (checksum * 33 + 17) & 0xFFFFFFFF
```

这段代码分别触发敏感读取、允许删除、工作区外删除、重复失败打开和高 CPU。Agent 2
运行 "/bin/sh"，随后 fork 子进程连接本机临时 TCP 监听端口，用于触发 Shell、fork 和
网络事件。所有目标都由脚本临时创建，不会访问真实敏感数据或外部网络。

典型输出包括：

```text
monitor_exit=0
PASS agent_1_registration
PASS agent_2_registration
PASS process_fork
PASS network_connect
PASS unexpected_shell
PASS sensitive_read
PASS outside_delete
PASS repeated_failed_open
PASS resource_logic_anomaly
PASS agent_1_exit
PASS agent_2_exit
DEMO_RESULT=PASS
```

"monitor_exit=0" 表示监控器正常完成；两个 registration 说明两组 cgroup 映射已经建立；
中间七项对应采集和检测功能；两个 exit 说明两组 cgroup 均已排空且退出码正常；最后的
"DEMO_RESULT=PASS" 是脚本检查全部通过后的总结果。脚本还会输出关键原始证据，例如：

```text
event=security_alert severity=high rule=sensitive_file_access ... agent_id=1 ...
event=security_alert severity=high rule=outside_workspace_delete ... agent_id=1 ...
event=security_alert severity=medium rule=repeated_failed_open ... count=5 ...
event=anomaly_alert severity=high rule=resource_logic_anomaly ... cpu_percent=...
event=security_alert severity=high rule=unexpected_shell ... agent_id=2 ...
event=CONNECT_RESULT ... agent_id=2 ... dst_ip=127.0.0.1 ... ret=0
```

这些行分别证明：Agent 1 触发三类文件相关规则和联合异常，Agent 2 触发 Shell 规则并
完成本地连接。"agent_id" 不同表明并发事件没有串组，"ret=0" 表示该阻塞 connect
系统调用成功。完整日志默认保存在
"/tmp/ebpf-agent-monitor-acceptance-demo.log"。

### 3.2 单真实 Agent 简单演示

入口文件为 "experiments/run_real_agent_demo_simple.sh"。运行命令为：

```bash
./experiments/run_real_agent_demo_simple.sh
```

脚本创建一个权限为 444、内容为 "REAL_AGENT_SIMPLE_DEMO_OK" 的临时文件，把所在目录
配置为敏感目录，然后通过 "run_bailian_codex_no_shell.py" 启动真实 Codex CLI Agent：

```bash
"$monitor" --hide-runtime-noise --events process,file,network \
  --agent 1 --sensitive-path "$sensitive_dir" \
  -- "$launcher" --cd "$sensitive_dir" \
  '只执行一次 cat secret.txt，原样报告读到的内容……'
```

"run_bailian_codex_no_shell.py" 使用 "exec" 直接替换为 Codex 进程，减少额外 Shell 包装
噪声；模型后端由 "BAILIAN_API_KEY"、"BAILIAN_BASE_URL" 和 "BAILIAN_MODEL" 环境变量
配置，Key 不写入仓库。Agent 根据 Prompt 调用 "cat"，BPF LSM 捕获真实文件路径，
Detector 随后产生敏感读取告警。

典型摘要输出为：

```text
monitor_exit=0
PASS agent_registration
PASS target_file_open
PASS sensitive_read_alert
PASS agent_response
PASS agent_exit
DEMO_RESULT=PASS
```

其中 "target_file_open" 表示找到了 "comm=cat" 且目标为 "secret.txt" 的真实
"FILE_OPEN"；"sensitive_read_alert" 表示同一次访问进入规则引擎；"agent_response"
表示模型确实返回了文件标记；"agent_exit" 要求带有 "basis=cgroup_empty"，说明不是
只等待 Codex 根进程，而是等待整个 Agent cgroup 排空。用户实测中，这五项全部通过，
完整日志默认位于 "/tmp/ebpf-agent-monitor-real-demo-simple.log"。

### 3.3 双真实 Agent 全面演示

入口文件为 "experiments/run_real_agent_demo_full.sh"。运行命令为：

```bash
./experiments/run_real_agent_demo_full.sh
```

脚本并发启动两个真实 Agent。Agent 1 在敏感目录中执行一次 "cat secret.txt"；Agent 2
在自己的 workspace 中执行一次针对 workspace 外临时文件的 "rm"。两组均配置
"--shell-policy audit"，Agent 2 还显式配置 Codex 和 Bubblewrap 的 runtime path：

```bash
--agent 1 --shell-policy audit --sensitive-path "$agent1_dir" -- ...
--next
--agent 2 --shell-policy audit --workspace "$agent2_workspace" \
  --runtime-path "$runtime_mounts" --runtime-path "$HOME/.codex" -- ...
```

这里把正常框架 Shell 行为记为审计证据，不把它直接判为攻击；workspace 外的专用
"victim.txt" 仍产生高危告警，而 Codex/Bubblewrap 清理自身运行目录时只产生
"runtime_file_delete" 证据。

典型摘要输出为：

```text
monitor_exit=0
PASS agent_1_registration
PASS agent_2_registration
PASS agent_1_sensitive_read
PASS agent_2_outside_delete
PASS shell_audit
PASS agent_1_network
PASS agent_2_network
PASS agent_1_response
PASS agent_1_exit
PASS agent_2_exit
PASS outside_file_deleted
DEMO_RESULT=PASS
```

两条 registration 对应两个独立 cgroup；两条 network 表示两个 Codex Agent 都产生了
各自归属的模型网络连接；敏感读取只属于 Agent 1，越界删除只属于 Agent 2；
"outside_file_deleted" 又从用户态文件状态确认删除实际成功，补足 LSM 钩子只能表达
“删除尝试”的语义。用户实测十一项全部通过。完整日志默认位于
"/tmp/ebpf-agent-monitor-real-demo-full.log"。该演示会产生两次真实模型调用，网络或
模型不可用时应改用确定性验收演示。

### 3.4 性能演示及输出解说

推荐配置微基准使用：

```bash
./experiments/run_recommended_performance.sh
```

Agent 风格低密度负载使用：

```bash
./experiments/run_agent_like_performance.sh
```

两个脚本都启用 process/file/network，将 "FILE_OPEN" 设为每 100 次采样一次，并关闭
普通事件打印。每一对样本交替采用 baseline-first 和 monitored-first，减轻温度、缓存
和运行顺序造成的偏差。"performance_report.py" 读取两组结果，计算独立中位数以及每对
样本开销的中位数、25% 分位数和 75% 分位数。

输出字段示例：

```text
phase=total baseline_median_ms=... monitored_median_ms=...
overhead_percent=...
paired_overhead_median_percent=...
paired_overhead_p25_percent=...
paired_overhead_p75_percent=...
```

"overhead_percent" 是两组中位数相除的结果；"paired_overhead_median_percent" 是先对每对
样本计算开销，再取中位数，更适合本项目的配对实验；p25/p75 描述中间一半样本的波动。

VirtualBox 的 15 对实测结果如下：

| 场景 | 逐对总开销中位数 | 解读 |
| --- | ---: | --- |
| 高事件密度推荐配置微基准 | 41.52% | 三类事件密集产生，明显未达 5% |
| Agent 风格端到端负载 | 0.98% | 包含约 2 秒等待，等待显著摊薄开销 |
| Agent 风格 active 阶段 | 8.80% | 排除等待后仍高于 5%，且样本波动较大 |

因此不能仅用 "total=0.98%" 宣称系统达到 5% 指标。当前准确结论是：包含等待的低事件
密度任务端到端影响较小，但活跃采集阶段和高事件密度负载仍需优化。

## 4. 在现有基础上继续改进的难度

改进难度不仅取决于代码量，也取决于内核接口稳定性、目标 Agent 技术栈差异、验证
环境和能否得到可信的“正确答案”。可按以下三个层级理解。

### 4.1 难度较低：约半天到两天

| 改进项 | 主要工作 | 难点 |
| --- | --- | --- |
| 补充 "unlinkat"、"rename"、"openat2" | 增加 tracepoint/LSM 事件、共享结构和用户态分派 | 正确区分“尝试”和“成功”，处理相对路径 |
| 增加 JSON/JSONL 日志 | 把当前文本输出封装为结构化序列化 | 保持字段兼容和转义正确 |
| 增加配置文件 | 将命令行策略移入 TOML/JSON | 校验路径、阈值和 Agent ID 冲突 |
| 完善演示摘要 | 增加颜色、统计和失败原因 | 不隐藏原始证据，不把摘要当成事实来源 |

这些改进主要复用现有事件协议、Collector 和 Detector，不需要改变总体架构。

### 4.2 难度中等：约两天到一周

| 改进项 | 主要工作 | 难点 |
| --- | --- | --- |
| 性能优化 | 批量/抽样、缩小事件、减少路径与进程事件开销 | 降低开销与避免漏报之间存在直接权衡 |
| 事件丢失与压力测试 | 多 Agent、高频事件、长时间运行、统计 drop | 需要稳定负载和可验证的事件真值 |
| 真实 Linux/5.15 兼容测试 | 多内核构建、加载和功能回归 | BTF、BPF LSM、tracepoint 字段可能不同 |
| 更强逻辑异常规则 | 加入网络频率、进程重复、文件模式等证据 | 阈值容易依赖具体工作负载并产生误报 |
| 动态接入已有 Agent | 识别进程并迁移或附着现有 cgroup | 无法可靠接管任意已运行进程及其全部后代 |

其中性能优化是最现实也最需要实验的方法：减少事件能够降低开销，但抽样可能漏掉敏感
行为；保留完整安全审计又会提高路径解析和用户态消费成本。因此必须分别定义“审计模式”
与“低开销模式”的目标，而不是只追求单一数字。

### 4.3 难度较高：约一到数周以上

| 改进项 | 主要工作 | 核心困难 |
| --- | --- | --- |
| HTTPS 明文捕获 | 对 TLS 库设置 uprobes，读取明文参数 | Codex 可能使用 Rust TLS、静态链接或不同库，函数和版本不统一 |
| Prompt/Response 捕获 | 识别请求格式、流式响应并按 Agent 重组 | HTTP/2、压缩、分片、重试和多路复用增加关联难度 |
| Prompt 到系统调用因果链 | 建立 interaction ID、线程/任务传播和时间关联 | 同一 Agent 可并发处理多个请求，单靠时间窗口不能证明因果 |
| 协作/竞争异常 | 建立跨 Agent 共享资源和交互模型 | 缺少统一异常定义、标注数据和可靠真值 |
| 通用阻断能力 | 把告警升级为 LSM 拒绝或处置动作 | 误报会直接破坏 Agent 任务，需要更严格策略与恢复机制 |

这些属于研究型工作。尤其是精确因果关联，不能仅增加几个 eBPF 钩子完成，需要应用层
协议解析、上下文传播和内核事件共同配合。对于当前课程项目，优先完成性能复测、压力
测试和少量系统调用扩展更具性价比。

### 4.4 当前完成情况与边界

| 赛题任务 | 当前状态 |
| --- | --- |
| 多 Agent 进程、文件、网络采集 | 已在受控脚本和双真实 Agent 场景验证 |
| cgroup 归属与生命周期 | 已实现，支持根退出后等待后代排空 |
| 真实文件路径 | 成功打开与删除父目录使用 BPF LSM；失败打开为还原尝试路径 |
| 三类安全异常 | Shell、敏感读取、工作区外删除均有真实 Agent 证据 |
| 资源与逻辑异常 | 已实现重复失败打开与高 CPU 的联合规则 |
| 告警与归因日志 | 已含时间、PID/TID、目标、agent ID、cgroup ID 和证据 |
| 性能不大于 5% | 未达到；Agent 风格 total 较低但 active 为 8.80% |
| Prompt/Response、HTTPS 明文 | 未实现，属于进阶方向 |
| 多 Agent 协作/竞争异常 | 未实现，属于进阶方向 |
| Prompt 到系统调用精确因果链 | 未实现，当前只能归因到 Agent 和进程行为 |

## 5. 主要收获

### 5.1 对操作系统机制的理解

本项目把课堂中的多个概念连成了一条实际运行链路。进程并不是单一 PID，而是会 fork、
exec、创建线程、退出和重父化的生命周期；cgroup 不仅用于资源限制，也能作为一组进程
及其后代的稳定身份边界；UID/GID、附加组和 "sudo" 环境决定进程最终以什么权限运行；
系统调用入口、返回值、文件对象、路径解析和 LSM 钩子分别表达不同语义。通过处理根
进程先退出、后代仍存活的情况，也更具体地理解了“进程退出”和“整个任务域结束”的
区别。

### 5.2 对 eBPF 的理解

项目实践了 tracepoint、BPF LSM、BPF map、Ring Buffer、BTF 和 CO-RE。最大的认识是
eBPF 不是把普通用户态程序直接搬进内核：内核程序受 verifier、栈大小、指针可信性和
有限 helper 的严格约束，适合完成过滤、少量状态保存和事件采集；复杂字符串处理、
动态策略和跨事件状态机更适合放在用户态。首次 "path_unlink" 实现因 trusted pointer
问题被 verifier 拒绝，也说明“C 语法正确”并不代表 eBPF 程序可以安全加载。

### 5.3 对监测与异常检测的理解

单条系统调用通常只能算证据，不能直接代表异常。启动 Shell 可能是攻击，也可能是
Codex 正常工作；删除事件可能针对业务文件，也可能是框架清理临时目录；五次失败打开
说明重复活动，但不能单独证明逻辑死循环。因此规则需要显式策略、Agent 归属、目标
对象和多维证据。项目把 Shell 设计为 deny/audit/allow，把删除分为 workspace、runtime
和 outside，并将重复失败与高 CPU 联合，体现了从“采集事件”到“解释行为”的差别。

### 5.4 对并发归因的理解

多 Agent 监测的核心不是记录更多日志，而是保证日志不会串组。使用 cgroup ID 映射
agent ID 后，线程和后代自然继承归属；入口/返回参数则按完整 "pid_tgid" 保存，避免
同一进程不同线程互相覆盖。实验还需要设置对照组，例如单独重复失败、单独高 CPU 和
两者同时出现，才能证明联合规则没有把不同 Agent 的证据错误拼接。

### 5.5 对工程验证的理解

项目从单个 bpftrace 小实验逐步迁移到 libbpf CO-RE 正式原型，并保留可重复的工作
负载、一键验收、真实 Agent 演示和性能脚本。由此认识到“代码能编译”与“功能已经
证明”不同：需要核对 PID、agent ID、cgroup ID、目标路径、返回值、退出状态和对照组；
真实 Agent 测试与受控脚本测试也只能证明各自场景，不能互相替代。

### 5.6 对性能数据的理解

性能百分比必须结合负载和绝对时间解释。Agent 风格 total 开销只有 0.98%，但其中约
2 秒等待会稀释监测成本；排除等待后 active 中位数为 8.80%。文件和网络阶段本身只有
几毫秒，少量固定开销就会形成很大的百分比。因而报告需要同时给出基线、监控耗时、
配对分位数、环境和限制，不能只挑最有利的一个数字。

### 5.7 总结性收获

本项目最终形成了从 Agent 启动、操作系统归属、内核行为采集、用户态关联到异常告警
的完整原型。更重要的收获不是某一个 eBPF API，而是学会了区分事件与结论、功能与
证据、原型与完整系统：对已经验证的能力给出可复现输出，对尚未实现的进阶任务和未
达到的性能指标如实说明。这也是系统软件项目中保证结论可信、设计可继续演进的基础。

## 6. 项目目录与文件说明

项目根目录按“正式实现、公共接口、文档、实验与生成结果”组织。正式系统主要位于
"src/" 和 "include/"；"experiments/" 中的文件用于产生可预测行为、复现实验、运行
真实 Agent 演示及测量性能，并不是另一套正式监控器。

### 6.1 根目录

| 文件或目录 | 含义 |
| --- | --- |
| "README.md" | 项目入口文档，介绍能力、依赖、构建、运行、演示方法和已知限制。 |
| "AGENTS.md" | 项目长期上下文与协作约定，记录重要决策、验证证据和后续接续点。 |
| "problem.md" | 操作系统大赛第 32 题的原始题目，是判断任务范围和评审要求的依据。 |
| "ebpf_environment_plan.md" | 早期开发环境、依赖和推进计划记录；其中的计划不等同于已完成能力。 |
| "Makefile" | libbpf CO-RE 构建入口，依次生成 "vmlinux.h"、BPF 对象、skeleton 和用户态可执行文件。 |
| ".gitignore" | 指定不提交 Git 的生成文件和缓存目录，主要包括 "build/"。 |
| "src/" | 正式实现的 C 与 eBPF 源码。 |
| "include/" | 内核态和用户态共享的事件协议，以及用户态模块接口。 |
| "docs/" | 架构、设计、验收状态和项目报告。 |
| "experiments/" | 早期 bpftrace 实验、受控工作负载、真实 Agent 演示和性能测试。 |
| "build/" | "make" 产生的可再生构建结果，不应手工修改或提交。 |

".git/" 是 Git 自身的版本数据库；".agents/"、".aws/" 和 ".codex/" 是当前开发工具或
运行环境提供的隐藏目录，不属于本项目源码和交付结构。Python 运行后出现的
"experiments/__pycache__/" 也是可删除、可再生的字节码缓存。

### 6.2 正式源码与公共接口

| 文件 | 含义 |
| --- | --- |
| "src/monitor.bpf.c" | 内核态 eBPF 数据面：挂载进程、文件和网络观测点，按 cgroup 过滤 Agent，完成入口/返回配对并向 Ring Buffer 提交事件。 |
| "src/monitor.c" | 用户态主程序：解析参数、创建和管理 Agent cgroup、两阶段启动目标进程、加载 BPF、登记映射、消费事件并管理生命周期。 |
| "src/detector.c" | 用户态检测器：维护每个 Agent 的工作区和规则状态，识别 Shell、敏感读取、越界删除、重复失败打开及联合异常。 |
| "src/resource_sampler.c" | 读取各 Agent cgroup 的 "cpu.stat"，按采样间隔计算单核口径 CPU 使用率并交给检测器。 |
| "include/events.h" | 内核态与用户态共享的事件协议，定义公共事件头、事件类型和各类事件载荷。 |
| "include/detector.h" | 检测器的状态结构和外部调用接口。 |
| "include/resource_sampler.h" | CPU 资源采样器的数据结构和接口。 |

### 6.3 文档

| 文件 | 含义 |
| --- | --- |
| "docs/design.md" | 正式系统设计说明，包括架构、事件模型、归属方式、规则、生命周期和性能结论。 |
| "docs/architecture-diagram.md" | 使用 Mermaid 绘制的项目整体框架图，展示从受控启动到告警输出的数据流。 |
| "docs/acceptance-status.md" | 按赛题基础要求逐项列出当前证据、完成状态和未覆盖边界。 |
| "docs/project-report.md" | 本报告，概括实现方法、任务细节、演示、改进难度、收获以及文件结构。 |
| "experiments/README.md" | 实验手册和历史实测记录，包含运行命令、预期现象、实际输出与结论边界。 |
| "experiments/real_agent_demo.md" | 最早的单真实 Agent 只读文件演示记录。 |
| "experiments/dual_real_agent_readonly.md" | 两个真实 Agent 并发读取各自文件的实验说明。 |
| "experiments/real_agent_sensitive_read.md" | 真实 Agent 触发敏感文件读取规则的实验说明。 |
| "experiments/real_agent_unexpected_shell.md" | 真实 Agent 执行 Shell 时规则从告警模式调整为审计模式的实验说明。 |
| "experiments/real_agent_outside_workspace_delete.md" | 真实 Agent 删除工作区外文件及运行时清理噪声分类的实验说明。 |

### 6.4 早期 bpftrace 探针与配套工作负载

这些文件用于从单一观测点逐步验证概念。".bt" 是 bpftrace 探针，通常由同名或相邻
的 ".py" 文件产生确定性行为。

| 文件 | 含义 |
| --- | --- |
| "experiments/execve.bt" | 最小 execve 入口观测实验，验证能够捕获一次程序执行尝试。 |
| "experiments/process_tree.bt" | 单 Agent 父子进程归属实验探针。 |
| "experiments/fork_exec.py" | 创建一个子进程并让其 exec "/usr/bin/true"，为进程树实验提供已知真值。 |
| "experiments/two_agents.bt" | 按受控启动顺序标记两个根进程，并验证后代归属不会串组。 |
| "experiments/two_agents.py" | 同时启动两组父子进程的工作负载。 |
| "experiments/file_open.bt" | 对 "openat" 入口和返回进行配对，显示路径、flags 和返回值。 |
| "experiments/file_open.py" | 创建、打开测试文件并打开一次不存在文件，用于核对 open 成功和 ENOENT。 |
| "experiments/file_unlink.bt" | 对 "unlink" 入口和返回进行配对，显示目标路径和结果。 |
| "experiments/file_unlink.py" | 对临时测试文件执行成功和失败的删除。 |
| "experiments/two_file_agents.bt" | 验证两个受控进程的文件事件归属。 |
| "experiments/two_file_agents.py" | 产生两组互不相同的文件打开和删除行为。 |
| "experiments/network_connect.bt" | 观察 IPv4 TCP "connect"，记录目标 IP、端口和返回值。 |
| "experiments/network_connect.py" | 建立一次本地成功 TCP 连接。 |
| "experiments/network_connect_fail.py" | 连接未监听的本地端口，产生可核对的连接失败。 |
| "experiments/network_connect_ipv6.py" | 产生本地 IPv6 TCP 连接，用于补充地址族验证。 |
| "experiments/two_network_agents.bt" | 验证两组网络连接事件的 Agent 归属。 |
| "experiments/two_network_agents.py" | 为两个受控进程分别建立本地网络连接。 |
| "experiments/unexpected_shell.bt" | 早期非预期 Shell 规则原型。 |
| "experiments/unexpected_shell.py" | 启动 "/bin/sh"，为 Shell 规则提供受控触发。 |
| "experiments/sensitive_file_access.bt" | 早期敏感文件访问规则原型。 |
| "experiments/sensitive_file_access.py" | 创建并读取专用模拟敏感文件。 |
| "experiments/outside_workspace_delete.bt" | 早期工作区外删除规则原型。 |
| "experiments/outside_workspace_delete.py" | 分别删除工作区内和工作区外测试文件。 |
| "experiments/repeated_failed_open.bt" | 在时间窗口内统计同一目标的重复 ENOENT，并在达到阈值时告警。 |
| "experiments/repeated_failed_open.py" | 快速重复打开同一不存在文件五次。 |

### 6.5 正式监控器的验证工作负载

| 文件 | 含义 |
| --- | --- |
| "experiments/file_activity.py" | 为正式 BPF LSM 文件探针产生成功打开、删除和缺失路径行为。 |
| "experiments/formal_sensitive_file_access.py" | 为正式检测器创建隔离的敏感目录和读取行为。 |
| "experiments/formal_outside_workspace_delete.py" | 为正式检测器产生工作区内允许删除和工作区外异常删除。 |
| "experiments/repeated_failed_open_idle.py" | 只产生重复失败打开而保持低 CPU，用作联合异常的对照组。 |
| "experiments/cpu_busy_only.py" | 只产生高 CPU 而不重复打开文件，用作另一对照组。 |
| "experiments/resource_logic_anomaly.py" | 同时产生重复失败打开和 CPU 忙循环，触发资源/逻辑联合异常。 |
| "experiments/root_exit_descendant.py" | 根进程先退出、后代继续运行，验证监控器等待 cgroup 排空。 |
| "experiments/acceptance_demo_agent.py" | 一键验收中的确定性 Agent 工作负载，根据角色产生敏感读取、越界删除、失败打开、CPU、Shell 和网络行为。 |
| "experiments/run_acceptance_demo.sh" | 启动两个确定性 Agent，运行正式监控器并自动核对 11 项关键证据。 |

### 6.6 真实 Agent 接入与演示文件

| 文件 | 含义 |
| --- | --- |
| "experiments/run_bailian_codex.sh" | 用百炼的 OpenAI 兼容接口启动 Codex CLI；API Key 从环境变量读取，不写入仓库。 |
| "experiments/run_bailian_codex_no_shell.py" | Python 启动包装器，用于测试 Shell 策略并减少包装脚本本身造成的语义干扰。 |
| "experiments/bailian-model-catalog.json" | 为第三方 Qwen 模型补充 Codex 所需的本地模型元数据。 |
| "experiments/run_real_agent_demo_simple.sh" | 启动一个真实 Agent 读取模拟敏感文件，自动检查注册、文件事件、告警、响应和退出。 |
| "experiments/run_real_agent_demo_full.sh" | 并发启动两个真实 Agent，综合展示敏感读取、工作区外删除、Shell 审计、网络和独立归属。 |

### 6.7 性能测试文件

| 文件 | 含义 |
| --- | --- |
| "experiments/performance_workload.py" | 高事件密度微基准，分别测量 CPU、文件、网络和进程阶段。 |
| "experiments/performance_report.py" | 汇总基线与受监控样本，计算中位数、逐对开销以及 p25/p75。 |
| "experiments/run_performance_benchmark.sh" | 通用性能运行器，可选择采集事件类型并交替执行基线和监控样本。 |
| "experiments/run_file_sampling_benchmark.sh" | 比较不同 "FILE_OPEN" 采样率对性能的影响。 |
| "experiments/run_file_sampling_stability.sh" | 用更多配对样本检查文件采样性能结果的稳定性。 |
| "experiments/run_recommended_performance.sh" | 使用当前推荐配置运行 15 对高密度微基准。 |
| "experiments/agent_like_performance_workload.py" | 模拟 Agent 的短暂计算、少量文件/网络/进程活动及等待阶段。 |
| "experiments/run_agent_like_performance.sh" | 对 Agent 风格负载运行配对性能测试，并分别报告 total、active 和 wait。 |

### 6.8 "build/" 中的生成文件

执行 "make" 后，构建目录通常包含以下文件。它们都可以由源码重新生成：

| 文件 | 含义 |
| --- | --- |
| "build/vmlinux.h" | 从当前内核 BTF 导出的内核类型定义，供 CO-RE eBPF 程序编译。 |
| "build/monitor.bpf.o" | Clang 编译得到的 eBPF ELF 对象。 |
| "build/monitor.skel.h" | "bpftool gen skeleton" 生成的 libbpf skeleton，供用户态加载和访问 maps/programs。 |
| "build/monitor" | 最终用户态监控器可执行文件。 |

阅读项目时，建议先看 "README.md" 和 "docs/architecture-diagram.md"，再按
"include/events.h" → "src/monitor.bpf.c" → "src/monitor.c" → "src/detector.c" →
"src/resource_sampler.c" 的顺序理解正式链路。需要复现实验时再查阅
"experiments/README.md" 和对应的运行脚本。

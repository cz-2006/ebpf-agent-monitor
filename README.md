# eBPF Agent Monitor

项目正在把已验证的 bpftrace 实验迁移为 libbpf + CO-RE 正式原型。
赛题基础要求的实测证据、缺口与后续验证顺序见
[验收证据清单](docs/acceptance-status.md)。架构、事件语义、策略设计、验证结果和
扩展边界集中说明于[系统设计与实现说明](docs/design.md)。

## 当前正式原型

当前原型通过受控启动为每个 Agent 创建独立 cgroup，并在 Agent 执行前登记
`cgroup_id → agent_id` 映射：

```text
monitor 加载 eBPF
→ 创建 Agent cgroup 并登记映射
→ fork 出阻塞的子进程
→ 把子进程迁入 cgroup
→ 放行子进程并恢复为 sudo 调用者的 UID/GID
→ exec 命令
→ sys_enter_execve → eBPF → Ring Buffer → C 用户态输出
```

eBPF 只提交已登记 cgroup 的事件，因此不会再输出同一系统中未受控启动的
VS Code、终端等后台进程。事件名 `EXEC_ATTEMPT` 只表示尝试执行程序，不表示
执行成功。

主要文件：

- `include/events.h`：内核态与用户态共享的公共事件头和事件载荷。
- `src/monitor.bpf.c`：查询 cgroup 映射、采集 execve 并写入 Ring Buffer。
- `src/monitor.c`：创建 cgroup、受控启动 Agent、登记映射和消费事件。
- `include/detector.h`、`src/detector.c`：保存各 Agent 策略并处理异常规则。
- `Makefile`：生成 CO-RE 文件并编译程序。
- `build/`：生成文件，不手工修改。

## 构建

```bash
make
```

构建依次生成 `build/vmlinux.h`、`build/monitor.bpf.o`、
`build/monitor.skel.h` 和 `build/monitor`。清理可运行 `make clean`。

## 运行验证

在项目根目录执行：

```bash
sudo ./build/monitor --agent 1 -- /usr/bin/true
echo $?
```

预期输出结构：

```text
event=agent_register agent_id=1 cgroup_id=... root_pid=... run_uid=1000 run_gid=1000 basis=controlled_launch
timestamp_ns=... cgroup_id=... event=EXEC_ATTEMPT pid=... uid=1000 agent_id=1 ... filename=/usr/bin/true
event=agent_exit agent_id=1 cgroup_id=... root_pid=... exit_code=0
```

`agent_root_exit` 表示受控启动的根进程已经退出，但它创建的后代可能仍在运行。
监控器会继续保留 cgroup 归属并采集后代，读取 cgroup v2 的 `cgroup.events`
`populated` 状态；只有整个 cgroup 变空后才输出：

```text
event=agent_cgroup_drained agent_id=1 cgroup_id=... root_pid=...
event=agent_exit agent_id=1 cgroup_id=... root_pid=... exit_code=0 basis=cgroup_empty
```

默认不会因为根进程退出而终止后台计算任务。若后代长期运行，监控器也会继续运行；
当前尚未提供自动超时清理策略。

三行中的 `agent_id` 应均为 1，注册行与业务事件的 `cgroup_id` 应一致。
请回传完整输出和 `echo $?` 的结果。

## 已验证结果与限制

系统范围 Ring Buffer 原型已经实测捕获 `/usr/bin/true`，共享事件布局、
`cgroup_id` 字段和用户态解析均通过。受控启动版本已通过 `-Wall -Wextra -Werror` 构建，并已完成 sudo 实测：

```text
event=agent_register agent_id=1 cgroup_id=11216 root_pid=39526 basis=controlled_launch
timestamp_ns=8816284658059 cgroup_id=11216 event=EXEC_ATTEMPT pid=39526 tid=39526 ppid=39525 uid=0 agent_id=1 comm=monitor filename=/usr/bin/true
event=agent_exit agent_id=1 cgroup_id=11216 root_pid=39526 exit_code=0
```

命令退出状态为 0。三条记录的 Agent、cgroup 和根 PID 对应一致，且注册发生在
业务事件之前，证明这次受控场景中的启动门控、cgroup 迁移、映射和过滤链路有效。
`comm=monitor` 是 execve 入口时尚未替换映像的进程名；`filename` 才是执行目标。
`uid=0` 是当时尚未实现降权的历史结果。当前版本会核验
`SUDO_UID/SUDO_GID/SUDO_USER`，在 exec 前执行
`initgroups → setresgid → setresuid` 并更新 `HOME/USER/LOGNAME`。
若缺少有效的非 root sudo 调用者信息，监控器会拒绝启动。降权版本已实测通过：

```text
event=agent_register agent_id=1 cgroup_id=11286 root_pid=41507 run_uid=1000 run_gid=1000 basis=controlled_launch
timestamp_ns=9182655682354 cgroup_id=11286 event=EXEC_ATTEMPT pid=41507 tid=41507 ppid=41506 uid=1000 agent_id=1 comm=monitor filename=/usr/bin/true
event=agent_exit agent_id=1 cgroup_id=11286 root_pid=41507 exit_code=0
```

整体命令退出状态为 0，证明本次受控场景中 Agent 在第一条业务 exec 事件前已恢复为普通用户。

当前支持一个监控器受控启动最多 16 个根 Agent，cgroup 内的后代会自然继承归属。
正式版已采集 fork/exit 生命周期、open/unlink 真实路径和 IPv4/IPv6 connect 结果，
并开始加入用户态异常规则。Agent 根进程退出后仍存活的后代处理、事件存储、压力测试
和性能评测仍未实现。

## 进程生命周期验证

正式原型已加入 `sched_process_fork` 和 `sched_process_exit`：

- `PROCESS_FORK`：公共头表示当前父任务，载荷包含 `parent_pid`、
  `child_pid` 和 `child_comm`。
- `PROCESS_EXIT`：公共头表示当前退出任务，载荷包含内核
  `task_struct.exit_code` 的 `exit_code_raw`。
- 两类事件与 exec 一样，只提交已登记 Agent cgroup 的事件。

运行：

```bash
sudo ./build/monitor --agent 1 -- /usr/bin/python3 experiments/fork_exec.py
echo $?
```

预期依次观察 Python 根进程的 `EXEC_ATTEMPT`、根进程创建孩子的
`PROCESS_FORK`、孩子执行 true 的 `EXEC_ATTEMPT`、孩子和根进程各自的
`PROCESS_EXIT`。所有事件的 `agent_id` 和 `cgroup_id` 应一致。

该场景已 sudo 实测通过：根 PID 46706 创建孩子 PID 46707，fork 载荷与工作负载
一致；孩子自动继承 agent_id=1 和 cgroup_id=11488，随后执行
`/usr/bin/true`。孩子与根进程的 `PROCESS_EXIT` 均为
`exit_code_raw=0`，最终 Agent exit_code 和整体命令退出状态均为 0。

## BPF LSM 真实文件路径验证

当前内核已启用 BPF LSM。正式采集器新增：

- `FILE_OPEN`：来自 `lsm/file_open`，使用 `bpf_d_path` 输出内核解析后的
  路径，并记录 `flags` 和 `path_ret`。
- `FILE_UNLINK_ATTEMPT`：来自 `lsm/path_unlink`，用 `bpf_d_path`
  解析可信父目录路径，读取目标 dentry 名称，再由用户态组合完整删除路径。
- 两个程序均原样返回已有 LSM 决策，不实施拦截；只观测已登记 Agent cgroup。

验证命令：

```bash
sudo ./build/monitor --agent 1 -- /usr/bin/python3 experiments/file_activity.py
echo $?
```

重点核对工作负载打印的 `sample.txt` 绝对路径是否与两类事件的 `path`
完全一致、`path_ret` 是否为正数，以及 agent_id/cgroup_id 是否一致。
不存在文件在路径解析阶段即失败，通常不会到达这两个 LSM 钩子，因此不会产生
LSM FILE_OPEN/FILE_UNLINK_ATTEMPT；失败 openat 由后文的 FILE_OPEN_RESULT 单独表达。
LSM 文件事件已经完成 sudo 加载与运行验证。

首次加载时 verifier 拒绝将 BPF 栈上合成的 `struct path` 传给
`bpf_d_path`。实现已调整为分别采集可信的父目录真实路径和 dentry 名称，
用户态组合成输出中的完整 `path`。修复后已实测通过：PID 6315、
agent_id=1、cgroup_id=6788；`sample.txt` 创建打开和只读打开分别产生
FILE_OPEN，完整路径均为 `/tmp/ebpf-exp3-pa1mjm4j/sample.txt`、
path_ret=35；删除前产生 FILE_UNLINK_ATTEMPT，同一路径的父目录
path_ret=24、名称 name_ret=11。缺失路径没有 LSM 事件，符合预期。
PROCESS_EXIT、Agent exit_code 和整体命令退出状态均为 0。

本轮还观察到：子进程进入 Agent cgroup 后才执行 initgroups，因此降权准备期间
以 uid=0、comm=monitor 打开的 /proc/sys/kernel/ngroups_max、/etc/group 等文件
也被归入 Agent。真实业务事件正确，但这批启动准备噪声需通过两阶段门控消除。

受控启动现已使用两阶段门控：子进程先在未登记的原 cgroup 完成
`initgroups`，通知父进程后才被迁入 Agent cgroup；放行后执行
`setresgid/setresuid` 和 exec。这样降权准备产生的 root 文件访问不会进入
Agent 事件流。相同文件工作负载已复测通过：PID 7465、agent_id=1、
cgroup_id=6902 的全部事件均为 uid=1000，不再出现 root 的 initgroups 文件访问；
`sample.txt` 两次 FILE_OPEN 和一次 FILE_UNLINK_ATTEMPT 的完整路径仍与工作负载
一致，path_ret/name_ret 正常，Agent 与整体命令退出状态均为 0。

## connect 结果采集

正式采集器已加入 `sys_enter_connect/sys_exit_connect` 配对。入口按完整
`pid_tgid` 保存 socket fd、地址族、目标地址、主机字节序端口及 Agent 归属；
返回时输出 `CONNECT_RESULT` 并删除暂存状态。当前支持 IPv4 和 IPv6，
`ret=0` 表示同步连接成功，负值为内核 errno。

先验证本地 IPv4 成功连接：

```bash
sudo ./build/monitor --agent 1 -- /usr/bin/python3 experiments/network_connect.py
echo $?
```

重点核对工作负载的 fd、目标 IP/端口与 CONNECT_RESULT 一致，ret=0，
agent_id/cgroup_id 一致。该场景已 sudo 实测通过：PID 6325、socket fd 4、
目标 127.0.0.1:56929 与工作负载一致，ret=0，agent_id=1、
cgroup_id=9530，PROCESS_EXIT 和 Agent exit_code 均为 0。本轮未提供单独的
`echo $?` 输出，不推断整体监控命令状态。

IPv4 失败连接也已实测通过：PID 6627、fd 3、目标
`127.0.0.1:37581` 与工作负载一致，Python `errno=111` 对应
`CONNECT_RESULT ret=-111`；Agent 与整体命令退出状态均为 0。

IPv6 回环验证：

```bash
sudo ./build/monitor --agent 1 -- /usr/bin/python3 experiments/network_connect_ipv6.py
echo $?
```

预期 CONNECT_RESULT 为 `family=10 dst_ip=::1 ret=0`，fd 和动态端口与
工作负载一致。

IPv6 正式监控已实测通过：PID 7481、socket fd 4、family=10、目标
`::1:50777` 与工作负载一致，ret=0，agent_id=1、cgroup_id=9714；
PROCESS_EXIT、Agent exit_code 和整体命令退出状态均为 0。

## 多 Agent 并发受控启动

一个监控器现在可以加载一套 BPF 程序和 Ring Buffer，同时启动最多 16 个 Agent。
不同 Agent 段使用 `--next` 分隔：

```bash
sudo ./build/monitor \
  --agent 1 -- /usr/bin/sleep 1 \
  --next \
  --agent 2 -- /usr/bin/sleep 1
echo $?
```

监控器先为每个 Agent 完成身份准备、独立 cgroup 创建和映射登记；全部准备完成后
才依次放行。它等待所有根进程结束；全部成功时返回 0，否则按输入顺序返回第一个
非零状态。Agent ID 必须唯一，当前上限为 16；命令参数中暂不能使用保留分隔符
`--next`。

最小验证已 sudo 实测通过：Agent 1 为 cgroup 9916/PID 11850，Agent 2 为
cgroup 9935/PID 11851；两组 EXEC_ATTEMPT、动态加载 FILE_OPEN 和 PROCESS_EXIT
交错出现但始终保持各自归属，没有串组。两个退出事件的时间戳只相差 29 ns，
说明生命周期重叠；两组 exit_code 和监控器整体退出状态均为 0。

双 Agent 混合行为也已实测通过：Agent 1（cgroup 10005/PID 12320）
执行文件工作负载，`sample.txt` 的 FILE_OPEN/FILE_UNLINK_ATTEMPT 始终归属
Agent 1；Agent 2（cgroup 10024/PID 12321）连接
`127.0.0.1:52379`，CONNECT_RESULT 仅归属 Agent 2。两组 Python 启动事件
高度交错，Agent 2 退出后 Agent 1 继续运行，仍无串组；两组和整体退出状态均为 0。

两个真实 Codex CLI Agent 的只读并发实验也已通过：两组网络连接事件交错，
各自的 `cat` 只打开本组标记文件，cgroup 与 agent_id 均未串组；两组及监控器
退出状态均为 0。命令、证据与模型用量见
[双真实 Agent 实验](experiments/dual_real_agent_readonly.md)。


## 用户态异常检测

采集与检测已拆分：`monitor.c` 负责校验、输出原始事件并把事件交给
`detector.c`；检测器按 `agent_id` 查找策略并输出告警。首条正式规则为
Shell 规则通过每个 Agent 的 `--shell-policy deny|audit|allow` 单独配置；未配置时
保持关闭。`deny` 输出 high `unexpected_shell` 告警，`audit` 输出
`event=activity_evidence rule=shell_execution` 审计证据，`allow` 不产生检测器输出。
旧参数 `--deny-shell` 保留为 `--shell-policy deny` 的兼容别名：

```bash
sudo ./build/monitor   --agent 1 --shell-policy deny -- /usr/bin/python3 experiments/unexpected_shell.py   --next   --agent 2 --shell-policy audit -- /usr/bin/true
echo $?
```

Agent 尝试执行 `sh`、`bash`、`dash`、`zsh`、`ksh` 或 `fish` 时，检测器按其
策略处理。规则使用精确的可执行文件 basename 匹配，证据字段为
`exec_attempt,cgroup_attribution`。告警或审计记录只证明捕获到 execve 尝试，
不证明执行成功。每个 Agent 只能配置一次 Shell 策略，兼容参数与新参数不能并用。

代码已在严格警告设置下构建通过。本地事件样本确认：`deny` 对 `/bin/bash`
产生一条 high 告警，`audit` 产生一条活动证据，`allow` 不产生检测器输出；
`/usr/bin/ssh` 不匹配 Shell 名单。

正式双 Agent 端到端验证已通过：Agent 1（cgroup 10402，根 PID 15588）启用
`--deny-shell`，孩子 PID 15590 的 `EXEC_ATTEMPT filename=/bin/sh` 紧接着产生
唯一一条 `unexpected_shell` 告警；两条记录 timestamp、PID/TID、agent_id 和
cgroup_id 完全一致。Agent 2（cgroup 10421，PID 15589）未启用该策略，执行
`/usr/bin/true` 时没有规则告警。两个 Agent 和监控器整体退出状态均为 0。

真实 Codex 实测说明该规则不能直接等同于攻击判定：即使使用无 Shell 包装器，
Codex 框架在收到任务前仍正常启动两次 Bash，工具调用阶段又启动两次，四次均被
准确告警。采集与字段关联有效，但当前 basename 黑名单缺少启动阶段、命令内容和
授权上下文，会产生框架级误报。详情见
[真实 Agent Shell 实验](experiments/real_agent_unexpected_shell.md)。


### 敏感目录读取规则

每个 Agent 可通过 `--sensitive-path DIR` 配置一个敏感目录。检测器去除多余的
结尾斜杠，再统一保存为带 `/` 的绝对路径前缀；目录本身和子路径边界能够正确
区分，不会把 `/tmp/secrets-old` 当作 `/tmp/secrets/` 的内容。相对路径和
过长路径会被拒绝。

规则只对 `O_RDONLY`、`O_RDWR` 等具有读取能力的普通文件打开产生
`sensitive_file_access` 告警；`O_WRONLY` 和 `O_DIRECTORY` 不告警。
正式验证命令：

```bash
sudo ./build/monitor   --agent 1   --sensitive-path /tmp/ebpf-agent-monitor-sensitive   -- /usr/bin/python3 experiments/formal_sensitive_file_access.py
echo $?
```

预期只有读取 `secret.txt` 的 FILE_OPEN 触发规则，创建夹具的只写打开及清理
目录操作不触发。代码已严格编译；本地构造事件已验证目录边界、读写 flags 和
Agent 策略隔离，工作负载也已单独运行并完成清理。

sudo 端到端验证已通过：Agent 1 为 cgroup 10535、PID/TID 18939。创建夹具的
FILE_OPEN flags=33345 没有告警；读取同一路径的 FILE_OPEN flags=32768 在相同
timestamp=4120192636297 产生唯一一条 sensitive_file_access 告警。告警的
agent_id、cgroup_id、PID/TID 和完整路径均与原始事件一致；清理产生的
FILE_UNLINK_ATTEMPT 未触发该规则。Agent 和监控器整体退出状态均为 0。

真实 Codex Agent 只读打开专用测试文件时，也产生了唯一一条字段完全对应的
`sensitive_file_access` 告警；Codex 原样报告文件内容，文件未改变，Agent 和
监控器均正常退出。完整命令与证据见
[真实 Agent 敏感读取实验](experiments/real_agent_sensitive_read.md)。


### 工作区外删除尝试规则

每个 Agent 可通过 `--workspace DIR` 配置允许删除的业务工作区，并可重复使用
`--runtime-path DIR` 声明 Agent 框架需要维护的运行时目录。目录使用与敏感路径
相同的规范化和边界匹配；`FILE_UNLINK_ATTEMPT` 的父目录与 dentry 名称在
detector 中还原为完整路径。工作区内不输出，运行时目录内输出
`activity_evidence rule=runtime_file_delete` 审计证据，其余路径输出 high
`outside_workspace_delete`。父目录或名称解析失败时不猜测归类。运行时路径是
显式策略，不依据 `comm` 或进程名自动放行。

正式验证命令：

```bash
sudo ./build/monitor   --agent 1   --workspace /tmp/ebpf-agent-monitor-delete/workspace   -- /usr/bin/python3 experiments/formal_outside_workspace_delete.py
echo $?
```

预期 `workspace/allowed.txt` 的删除尝试不告警，
`outside/victim.txt` 产生一条告警。该事件来自删除前的 BPF LSM 钩子，
证据标记为 `unlink_attempt,path_policy,cgroup_attribution`，不能单独证明
删除最终成功。代码已严格编译；本地构造事件验证了内部、外部、相似前缀、
解析失败和 Agent 策略隔离。正式工作负载已单独运行并完成清理，退出状态为 0。

sudo 端到端验证已通过：Agent 1 为 cgroup 10649、PID/TID 22584。工作区内
`allowed.txt` 的 FILE_UNLINK_ATTEMPT 没有告警；工作区外 `victim.txt` 的
FILE_UNLINK_ATTEMPT 与唯一一条 outside_workspace_delete 告警共享
timestamp=4576044265090，且 PID/TID、agent_id、cgroup_id 和完整路径完全对应。
工作负载确认两次删除均完成，Agent 与监控器整体退出状态均为 0；检测规则本身
仍只使用删除前尝试作为证据。

真实 Codex 会正常清理 Bubblewrap 临时挂载项和 `~/.codex` 状态文件。可将这些
目录显式配置为运行时审计范围，使其保留证据而不与真正的越界目标同列为 high：

```bash
--runtime-path /tmp/codex-bwrap-synthetic-mount-targets-1000 \
--runtime-path /home/felix/.codex
```


### 重复失败文件打开规则

正式采集器新增 `sys_enter_openat/sys_exit_openat` 配对。入口按完整
`pid_tgid` 保存原始路径、`dirfd` 和 Agent 归属；返回点立即删除暂存状态，
只把负返回值作为 `FILE_OPEN_RESULT` 送到用户态。成功打开仍由 BPF LSM 的
`FILE_OPEN` 提供内核解析后的真实路径。

规则必须为同一 Agent 同时配置两个参数：

```text
--failed-open-threshold 5 --failed-open-window-ms 2000
```

detector 只累计 `ret=-ENOENT`，键为
`agent_id + reconstructed_path`，使用最多 128 项的有界状态表；满表时复用
最久未活动的状态。首次达到阈值时输出一条 medium 告警，同一窗口内不重复告警。

失败路径按以下方式还原并进行 `.`、`..` 和重复斜杠的词法规范化：

- 绝对路径直接规范化，`reconstruction=absolute`。
- `AT_FDCWD` 相对路径读取 `/proc/PID/cwd`，
  `reconstruction=proc_cwd`。
- 普通 `dirfd` 读取 `/proc/PID/fd/DIRFD`，
  `reconstruction=proc_dirfd`。

输出统一标记 `path_basis=reconstructed_attempt`，不称为真实内核路径。
读取 `/proc` 可能与进程改变 cwd、关闭 fd 或退出发生竞争；还原失败时保留原始
FILE_OPEN_RESULT，但不纳入同目标计数。第一版只覆盖 `openat`，尚未覆盖
`openat2`。

正式验证命令：

```bash
sudo ./build/monitor \
  --agent 1 \
  --failed-open-threshold 5 \
  --failed-open-window-ms 2000 \
  -- /usr/bin/python3 experiments/repeated_failed_open.py
echo $?
```

预期同一目标的 count 从 1 增至 5，在第 5 次只输出一条
`rule=repeated_failed_open` 告警。代码已严格构建；本地构造事件已验证绝对
路径、AT_FDCWD、普通 dirfd、路径规范化、同目标计数和阈值告警。

sudo 端到端验证已通过：Agent 1 为 cgroup 11027、PID/TID 29930。目标
`/tmp/ebpf-exp6-repeat/missing.txt` 的五次 FILE_OPEN_RESULT 均为
dirfd=-100、ret=-2，activity_evidence 的 count 从 1 增至 5；第 5 次在
elapsed_ns=304268 时产生唯一一条 medium 告警，使用
path_basis=reconstructed_attempt、reconstruction=absolute。Python 启动阶段
探测的多个缺失配置文件分别保持 count=1，没有与目标路径合并。Agent 与监控器
整体退出状态均为 0。

## CPU 资源采样与联合异常

resource_sampler.c 在用户态读取各 Agent cgroup 的 cpu.stat。相邻两次
usage_usec 的差值除以单调时钟区间，得到单核等价值：100% 表示占满一个
CPU 核，多线程 Agent 可以超过 100%。采样失败会输出
resource_sample_error，不会用零值代替。

每个 Agent 用以下两个参数成对启用 CPU 采样：

- --cpu-sample-ms MS：采样周期，当前最小 100 ms。
- --cpu-threshold-percent PERCENT：单核等价阈值。

CPU 超阈值本身输出 resource_sample。若同一 Agent 在重复失败打开规则的同一
时间窗内也已达到次数阈值，detector 额外输出一次
rule=resource_logic_anomaly，同时保留原有的 repeated_failed_open 告警。

验证命令：

    sudo ./build/monitor \
      --agent 1 \
      --failed-open-threshold 5 \
      --failed-open-window-ms 2000 \
      --cpu-sample-ms 200 \
      --cpu-threshold-percent 50 \
      -- /usr/bin/python3 experiments/resource_logic_anomaly.py
    echo $?

预期同一路径的计数达到 5，随后出现 CPU 百分比不低于 50 的样本，以及一条
resource_logic_anomaly。该工作负载用于功能验证，阈值不是生产环境默认值。

### 多 Agent 联合异常隔离验证

三组并发测试分别提供“只有重复失败”“只有高 CPU”和“两项证据同时存在”。
所有 Agent 都配置相同阈值，预期只有 Agent 3 输出 resource_logic_anomaly：

    sudo ./build/monitor \
      --agent 1 --failed-open-threshold 5 --failed-open-window-ms 2000 \
      --cpu-sample-ms 200 --cpu-threshold-percent 50 \
      -- /usr/bin/python3 experiments/repeated_failed_open_idle.py \
      --next \
      --agent 2 --failed-open-threshold 5 --failed-open-window-ms 2000 \
      --cpu-sample-ms 200 --cpu-threshold-percent 50 \
      -- /usr/bin/python3 experiments/cpu_busy_only.py \
      --next \
      --agent 3 --failed-open-threshold 5 --failed-open-window-ms 2000 \
      --cpu-sample-ms 200 --cpu-threshold-percent 50 \
      -- /usr/bin/python3 experiments/resource_logic_anomaly.py
    echo $?

Agent 1 仍应产生独立 repeated_failed_open 告警；Agent 2 应出现高 CPU 样本；
Agent 3 应同时产生 repeated_failed_open 和唯一一条联合告警。若 Agent 1 或
Agent 2 出现联合告警，则说明证据隔离或测试时序存在问题。

## 初步性能对比

固定混合工作负载包括 CPU 计算、10000 次 /dev/null 打开、500 次本地 TCP
连接和 100 个 true 子进程。它在业务阶段内部计时，分别报告总耗时及各阶段耗时。
驱动脚本先预热一次，再交替运行无监控和有监控的配对样本，默认各 5 次：

    experiments/run_performance_benchmark.sh

监控输出重定向到 /dev/null，因此终端渲染不计入，但 Ring Buffer 消费与用户态
格式化仍属于当前原型开销。报告使用各组中位数计算：

    overhead_percent = (monitored_median / baseline_median - 1) * 100

这是 VirtualBox 开发环境中的初步端到端测量。它不能直接证明达到赛题 5% 指标；
正式结论还需在真实 Linux 机器上固定 CPU、增加重复次数并记录方差。

### 静默原始事件基准模式

在第一个 Agent 前添加 --quiet-events，可停止普通原始事件的字符串格式化和输出：

    sudo ./build/monitor --quiet-events --agent 1 -- COMMAND

该模式仍加载相同 eBPF 探针、传输和校验 Ring Buffer 事件，并继续调用 detector；
注册、退出、资源样本和告警不受影响。它用于拆分采集/检测成本与逐事件日志成本，
不应作为日常审计日志模式。性能驱动脚本已改用此模式。

### 按事件类别启用探针

全局参数 --events LIST 支持逗号分隔的 process、file、network，必须放在第一个
--agent 前。未指定时默认全部启用。例如只采集文件事件：

    sudo ./build/monitor --quiet-events --events file \
      --agent 1 -- COMMAND

未选择类别的 BPF 程序会在加载前关闭 autoload，不会附着到对应 hook。该接口用于
性能隔离和按需部署；关闭类别也会关闭依赖它的原始事件与规则证据。

### 隐藏 Codex 沙箱文件噪声

在第一个 Agent 前添加 `--hide-runtime-noise`，可隐藏 `bwrap`、
`codex-linux-san` 进程，以及 `/tmp/codex-bwrap-synthetic-mount-targets-`
路径下的普通文件事件输出。默认不隐藏。例如：

    sudo ./build/monitor --hide-runtime-noise --agent 1 -- COMMAND

此选项只影响用户态展示：文件事件仍被采集、校验并交给 detector，告警不隐藏；
进程、网络和 Agent 注册/退出事件照常显示。目标文件由 `cat` 打开的事件也会显示。
隐藏的沙箱临时文件操作仍真实发生，若需完整审计日志，不使用此选项。

### FILE_OPEN 低开销抽样模式

默认全量模式等价于 --file-open-sample-every 1。设置更大的 N 后，内核按 Agent
cgroup 对 FILE_OPEN 计数，只保留第 1 次及之后每隔 N 次的真实路径事件。例如：

    sudo ./build/monitor --file-open-sample-every 100 \
      --agent 1 -- COMMAND

抽样判断发生在 bpf_d_path 和 Ring Buffer 申请之前。FILE_UNLINK、失败 openat、
进程和网络事件不受影响。抽样可能漏掉普通文件打开，因此配置 --sensitive-path
时禁止 N>1；需要完整审计时保持默认值 1。

采样计数和 agent_id 保存在同一个 cgroup 归属 map value 中。每次 FILE_OPEN
只需一次 cgroup map 查询，再对其中的计数原子递增，避免为采样单独查询第二张 map。

比较全量、1/10 和 1/100 文件采集开销：

    ./experiments/run_file_sampling_benchmark.sh

### FILE_OPEN N=100 稳定性复测

完成 15 对相邻样本并报告配对开销中位数及 25%～75% 四分位区间：

    ./experiments/run_file_sampling_stability.sh

paired_overhead_median_percent 是每一对先计算开销后得到的中位数；p25/p75 区间
反映中间 50% 样本的波动。虚拟机结果仍只用于开发阶段判断。

## 使用阿里云百炼 Qwen 运行真实 Codex Agent

experiments/run_bailian_codex.sh 使用 Codex CLI 作为本地 Agent harness，
将模型请求发往百炼 Responses API。脚本当前默认模型为 qwen3.8-27b，
不读取普通 ~/.codex/config.toml，不持久化会话，也不在仓库中保存 API Key。

先从百炼控制台复制当前业务空间的 API Host，然后在终端中安全读入密钥：

    read -rsp "Bailian API Key: " BAILIAN_API_KEY
    export BAILIAN_API_KEY
    echo
    export BAILIAN_BASE_URL='https://你的WorkspaceId.cn-beijing.maas.aliyuncs.com/compatible-mode/v1'

首次先脱离监控器验证 provider、模型名称和 Responses API：

    ./experiments/run_bailian_codex.sh '只回复 BAILIAN_OK，不读取或修改文件'

确认成功后再通过受控启动器运行。sudo 默认可能清理环境变量，因此只显式保留
这两个百炼变量：

    mkdir -p /tmp/ebpf-agent-monitor-qwen-smoke
    sudo --preserve-env=BAILIAN_API_KEY,BAILIAN_BASE_URL \
      ./build/monitor --events process,network --agent 1 -- \
      ./experiments/run_bailian_codex.sh \
      --cd /tmp/ebpf-agent-monitor-qwen-smoke \
      '只回复 MONITORED_AGENT_OK，不读取或修改文件'

可以通过 BAILIAN_MODEL 覆盖默认模型；若使用该变量，sudo 时也需加入
--preserve-env。不要把 API Key 写进命令参数、仓库文件或测试日志。

## 一键基础验收演示

不调用外部模型即可运行一次双 Agent 确定性演示：

```bash
./experiments/run_acceptance_demo.sh
```

脚本以普通用户启动并在内部调用 `sudo`，自动创建唯一的 `/tmp` 夹具目录。Agent 1
产生敏感读取、允许/越界删除、重复失败打开及 CPU 联合异常；Agent 2 产生 fork、
非预期 Shell 和本地 IPv4 连接。正式 `build/monitor` 同时监控两组，脚本随后逐项
检查告警、连接、生命周期和退出状态，成功时输出 `DEMO_RESULT=PASS`。完整日志默认
保存在 `/tmp/ebpf-agent-monitor-acceptance-demo.log`，夹具目录在结束时清理。

该命令用于答辩演示和回归基础链路，不代替真实 Agent、压力、性能或 5.15 实机
验证。运行前若 `build/monitor` 不存在，先执行 `make`。

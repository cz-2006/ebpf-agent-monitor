# eBPF Agent Monitor

项目正在把已验证的 bpftrace 实验迁移为 libbpf + CO-RE 正式原型。

## 当前正式原型

当前原型通过受控启动为一个 Agent 创建独立 cgroup，并在 Agent 执行前登记
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

当前仅支持一次启动一个根 Agent。cgroup 内的后代会自然继承归属，正式版已采集
fork/exit 生命周期及 open/unlink 真实路径事件。Agent 根进程退出后仍存活的后代处理、
多 Agent 同时启动、网络采集、异常规则、事件存储和性能评测仍未实现。

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
不存在文件在路径解析阶段即失败，通常不会到达这两个 LSM 钩子，因此本版本不会为
open/unlink missing 输出事件。代码已编译通过，尚待 sudo 加载与运行验证。

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

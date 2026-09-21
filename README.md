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

当前仅支持一次启动一个根 Agent。cgroup 内的后代会自然继承归属，但正式版的
fork/exit 生命周期事件、Agent 根进程退出后仍存活的后代处理、多 Agent 同时启动、
文件与网络采集、异常规则、事件存储和性能评测仍未实现。

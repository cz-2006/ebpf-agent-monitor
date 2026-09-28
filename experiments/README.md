# 六个实验

2026-09-15：用户确认按以下顺序逐步推进；后续归属方案、接口及规则仍需共同设计。

1. 单程序执行观测：用户实测已捕获目标 execve 入口事件，最小观测目标通过。
2. 两组并发与子进程归属：已确认先做单组进程树跟踪；实验②a 单组单线程父子归属已由用户实测通过，实验②b 双组归属已在受控场景通过，类型警告修正后用户已确认消失。
3. 文件操作：实验③a 短绝对路径 openat 成功/失败配对已由用户实测通过；实验③b unlink 成功/失败配对及实验③c 双组文件归属均在受控场景实测通过。
4. 网络连接：实验④a 单组本地阻塞 IPv4 TCP connect 已由用户实测通过；其他网络场景待设计。
5. 安全规则：实验⑤a 非预期 Shell 告警已通过；实验⑤b 模拟敏感文件访问已准备，工作负载通过，探针告警待验证。
6. 重复活动：实验⑥a 重复打开同一缺失文件已准备，工作负载通过，探针计数与告警待验证。

## 实验①：观察一次 execve 尝试

目的：验证执行一个已知命令时，能从内核观测点收到事件。
使用现成的 `/usr/bin/true` 作为最小工作负载；它正常退出，不需要额外编写测试脚本。

在项目根目录的交互式终端执行：

```bash
sudo bpftrace -c '/usr/bin/true' experiments/execve.bt
```

密码仅在自己的终端输入，不要发到对话中。命令退出后可立即运行 `echo $?` 查看 bpftrace 的退出状态。

探针说明：

- `tracepoint:syscalls:sys_enter_execve`：观察 execve 系统调用入口。
- `pid == cpid`：仅记录 bpftrace 用 `-c` 启动的进程；此过滤不包含其后代，不能作为未来的 Agent 归属方案。
- `args->filename`：调用者传入的程序路径；不代表已解析的真实文件路径。
- `nsecs`：单调时钟纳秒值，用于时间顺序，不是日历时间。
- `pid` / `tid`：进程 ID / 线程 ID。

预期出现含 `event=execve_attempt filename=/usr/bin/true` 的事件，PID/TID 为实际运行值。下方记录了本次实测输出。
入口事件仅证明尝试执行，不证明成功；本轮不验证进程创建、Agent 归属或异常检测。
若探针不存在、权限不足、编译或加载失败，保留完整输出后排查，不计为通过。

## 实验①实测记录（2026-09-15）

用户运行后提供的事件行：

```text
mono_ns=7005211258689 pid=15892 tid=15892 event=execve_attempt filename=/usr/bin/true
```

结果：已捕获目标程序的 execve 入口事件，验证了本次探针从内核观测到用户态输出的最小链路。PID/TID 均为 15892；时间字段为单调时钟纳秒值，不是日历时间或程序耗时。路径为调用参数。

用户仅提供上述事件行，未提供完整终端输出或退出状态。不能由入口事件断言 execve 成功或程序正常退出；子进程归属、多 Agent、异常检测与性能仍未验证。

## 当前核验与限制

- 实测内核：`7.0.0-31-generic`。
- 实测 bpftrace：`v0.20.2`，已核对本机命令帮助。
- `sudo -n true` 此前返回需要密码；此后用户手动运行实验①并提供上述事件，最小观测目标通过。
- 工具沙箱启动报 `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`，本次文件与环境检查通过授权后的沙箱外命令完成；这不说明 eBPF 不可用。


## 脚本阅读与编辑（2026-09-15 讲解记录）

`.bt` 使用 bpftrace 的专用脚本语法。bpftrace 将脚本编译成 eBPF 程序并加载到观测点；基本结构是：

```text
观测点
/过滤条件/
{
    事件触发时执行的动作
}
```

当前脚本在 `sys_enter_execve` 触发时，检查事件进程 `pid` 是否等于 `-c` 启动的进程 `cpid`，满足条件才输出。`execve` 替换当前进程执行的程序，本身不创建新进程。

`printf` 的 `%llu`、`%d`、`%s` 分别对应这里的纳秒值、整数 ID 和字符串；`str(args->filename)` 读取观测点参数中的程序路径字符串。参数字段由观测点定义，不能任意起名。入口记录仅表示尝试执行。

VS Code 语法高亮可选安装 [bpftrace 扩展（bpfdeploy.bpftrace）](https://marketplace.visualstudio.com/items?itemName=bpfdeploy.bpftrace)。安装后若未自动识别，手动选择 bpftrace 语言模式。扩展仅辅助编辑，不是运行实验的前提；用户尚未确认安装。

参考：[bpftrace 官方介绍](https://bpftrace.org/)。

## 实验②a：单组父子进程归属（受控场景实测通过）

用户已确认先用进程树跟踪，从一组单线程父子进程开始，再推进两组并发。此为实验方案，不是正式系统归属方案定稿。

### 文件与流程

- `fork_exec.py`：受控工作负载，无需输入；输出已知父子 PID 和孩子退出状态。父进程 fork 一个孩子，孩子 exec `/usr/bin/true`，父进程 waitpid 等待孩子，避免根进程提前退出导致 `-c` 监控结束。
- `process_tree.bt`：输入是内核事件和 `-c` 根进程 ID；输出登记、创建、执行尝试和退出事件。`agent_id=1` 是测试标签 Agent A。
- 两个文件不互相传递归属信息；工作负载的 `WORKLOAD` 行仅供核对，探针独立观察内核。

`fork()` 创建新进程，父进程得到孩子 PID，孩子得到返回值 0；因此双方可以进入不同代码分支。成功的 `execv()` 将孩子替换为目标程序，不再返回原 Python 代码。`waitpid()` 等待孩子并取得退出状态。

监控逻辑：

1. `BEGIN` 登记 `@agent[cpid] = 1`。
2. `sched_process_fork` 观察实际创建事件，将父标签复制给孩子。这里不使用 fork 系统调用入口，因为入口还不能证明创建成功，也没有返回的孩子 PID。
3. execve 入口查表输出归属；`@agent[tid]` 为非零才记录。
4. 任务退出时删除对应项；`END` 清理残余表项。

`@agent` 是 bpftrace map，可理解为内核侧的键值表。创建事件字段 `parent_pid` / `child_pid` 实际是任务 ID；本轮单线程场景中与进程 ID 相同，所以表按 TID 查询和删除。多线程、非主线程 exec、PID namespace、丢事件与长期 PID 重用安全均未验证，不能直接泛化为正式归属实现。

### 运行

在项目根目录，先单独运行工作负载，认识它自身的输出：

```bash
python3 experiments/fork_exec.py
```

然后在交互终端加载监控：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/fork_exec.py' experiments/process_tree.bt
```

退出后立即执行 `echo $?`，并提供完整输出。密码仅在自己的终端输入。

预期核对（不是实测）：

- `register` 的根 PID 与 `WORKLOAD root_pid` 相同。
- `fork` 的父子 PID 与工作负载打印的 PID 相同，孩子继承 `agent_id=1`。
- `filename=/usr/bin/true` 的 execve 事件属于孩子 PID，并带 `agent_id=1`。
- 孩子有退出事件，工作负载报告 `child_exit_code=0`。
- 可能还会看到根进程执行 Python 的事件。工作负载输出和 bpftrace 异步输出可能交错，按 PID 和事件时间核对，不把显示顺序当作严格发生顺序。

单独运行 Python 成功不代表 eBPF 归属实验通过；入口事件也不代表 exec 成功。暂未验证双组并发、无关进程排除、孙进程、多线程、异常检测和性能。

此前工具侧探针检查受权限限制：普通用户运行 bpftrace 提示需要 root，`sudo -n` 提示需要密码。此后用户在交互终端成功加载并提供下方事件输出，确认本次脚本可运行。

参考：[bpftrace 官方文档（map、BEGIN/END 与 cpid）](https://bpftrace.org/docs/0.21)。本机是 0.20.2，兼容性以实际编译加载结果为准。

### 工作负载单独实测（2026-09-15）

运行 `python3 experiments/fork_exec.py`，退出状态为 0：

```text
WORKLOAD root_pid=21829
WORKLOAD child_pid=21844 parent_pid=21829
WORKLOAD waited_child=21844 child_exit_code=0
```

该次单独运行仅证明受控工作负载可运行；后续 eBPF 实测见下方。

### 实验②a 用户提供的完整事件输出（2026-09-15）

```text
Attaching 5 probes...
event=register root_pid=29031 agent_id=1 basis=launch
mono_ns=9784858056729 event=execve_attempt pid=29031 tid=29031 agent_id=1 filename=/usr/bin/python3 basis=tracked_task
WORKLOAD root_pid=29031
mono_ns=9784873480397 event=fork parent_pid=29031 child_pid=29032 agent_id=1 basis=fork
WORKLOAD child_pid=29032 parent_pid=29031
mono_ns=9784874261346 event=execve_attempt pid=29032 tid=29032 agent_id=1 filename=/usr/bin/true basis=tracked_task
mono_ns=9784878345032 event=exit pid=29032 tid=29032 agent_id=1
WORKLOAD waited_child=29032 child_exit_code=0
mono_ns=9784886442361 event=exit pid=29031 tid=29031 agent_id=1
```

核对结果：根 PID 29031 与工作负载一致；创建事件中的孩子 PID 29032 与工作负载一致；孩子执行 true 时仍为 PID 29032 且继承 agent_id=1；捕获到父子退出事件；工作负载报告孩子退出码 0。实验②a 的单组单线程父子归属目标通过。

`Attaching 5 probes` 对应脚本 BEGIN、fork、execve、exit、END 五个探针块，不代表五个进程。`basis=launch` 表示启动登记，`basis=fork` 表示通过创建关系继承，`basis=tracked_task` 表示查询已有归属表。

退出探针没有输出退出码；孩子退出码 0 来自工作负载 waitpid 的结果。未提供 bpftrace 的 shell 退出状态，不推断该状态。未验证双组并发、无关进程排除、孙进程、多线程、丢事件、长期 PID 重用、真实 Agent 或性能。下一步先理解归属表变化，再共同设计双组并发验证。

## 实验②b：两组并发归属（受控场景通过，用户确认警告消失）

用户要求继续运行两组并发实验。`two_agents.py` 作为启动器，按顺序 fork 两个根进程，并用管道作为启动门：两者创建好后才放行，随后各自 exec 现有 `fork_exec.py`。启动器等待两组退出。此门保证两根进程生命周期重叠，不保证后续 syscall 同时发生或固定交错。

`two_agents.bt` 在启动器创建第一、第二个直接孩子时分别登记 agent_id=1、2，后代通过 fork 继承；启动器自身不登记为 Agent。按创建顺序分配标签只适用于这个恰好创建两个直接孩子的受控启动器，不是正式 Agent 身份方案。仍限定单线程场景，沿用实验②a 的限制。

项目根目录运行（同时启动监控和工作负载，无需另开 Python）：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/two_agents.py' experiments/two_agents.bt
```

结束后立即运行 `echo $?`，提供完整输出。核对：

- 两条 `event=register` 的 root_pid/agent_id 与 `LAUNCHER` 登记行一致。
- 两组根进程各创建一个孩子，`fork` 父子 PID 与 `WORKLOAD` 一致。
- 两个孩子执行 `/usr/bin/true` 的事件分别携带正确的 agent_id，不能串组。
- 两组根进程和孩子均有退出事件，工作负载孩子退出码及启动器报告的两组退出码为 0。
- 输出可能交错，按 PID、标签和时间核对，不要求固定显示顺序。

### 工作负载单独实测（2026-09-15）

`python3 experiments/two_agents.py` 退出状态 0：

```text
LAUNCHER pid=32070
LAUNCHER agent_id=1 root_pid=32081
LAUNCHER agent_id=2 root_pid=32082
WORKLOAD root_pid=32081
WORKLOAD root_pid=32082
WORKLOAD child_pid=32083 parent_pid=32081
WORKLOAD child_pid=32084 parent_pid=32082
WORKLOAD waited_child=32084 child_exit_code=0
WORKLOAD waited_child=32083 child_exit_code=0
LAUNCHER agent_id=1 root_pid=32081 exit_code=0
LAUNCHER agent_id=2 root_pid=32082 exit_code=0
```

随后尝试 `sudo -n bpftrace -c '/usr/bin/python3 experiments/two_agents.py' experiments/two_agents.bt`，返回 `sudo: a password is required`。因此只验证了工作负载，双组探针尚未编译加载验证，不能标记归属实验通过；待用户在交互终端运行上述 sudo 命令。

### 实验②b 用户实测（2026-09-15）

用户运行文档中的 sudo bpftrace 命令，探针成功加载。关键事件摘录：

```text
event=launcher pid=32946
mono_ns=10444771034420 event=register root_pid=32947 agent_id=1 basis=launcher_fork_order
mono_ns=10444774869347 event=register root_pid=32948 agent_id=2 basis=launcher_fork_order
mono_ns=10444777611173 event=execve_attempt pid=32947 tid=32947 agent_id=1 filename=/usr/bin/python3 basis=tracked_task
mono_ns=10444778329715 event=execve_attempt pid=32948 tid=32948 agent_id=2 filename=/usr/bin/python3 basis=tracked_task
mono_ns=10444798389271 event=fork parent_pid=32948 child_pid=32949 agent_id=2 basis=fork
mono_ns=10444799782924 event=execve_attempt pid=32949 tid=32949 agent_id=2 filename=/usr/bin/true basis=tracked_task
mono_ns=10444802545485 event=exit pid=32949 tid=32949 agent_id=2
mono_ns=10444806332648 event=exit pid=32948 tid=32948 agent_id=2
mono_ns=10444808505067 event=fork parent_pid=32947 child_pid=32950 agent_id=1 basis=fork
mono_ns=10444812672491 event=execve_attempt pid=32950 tid=32950 agent_id=1 filename=/usr/bin/true basis=tracked_task
mono_ns=10444816734407 event=exit pid=32950 tid=32950 agent_id=1
mono_ns=10444819894157 event=exit pid=32947 tid=32947 agent_id=1
LAUNCHER agent_id=1 root_pid=32947 exit_code=0
LAUNCHER agent_id=2 root_pid=32948 exit_code=0
```

用户输出中的 WORKLOAD 行与上述父子 PID 一致，两个孩子退出码均为 0。根进程生命周期重叠；Agent 2 的子任务先完成，Agent 1 随后创建自己的孩子。因此验证了两组重叠运行下的归属，不能宣称孩子同时运行或完成高并发压力测试。两组标签未串组，四个退出事件齐全。未提供 bpftrace 的 shell 退出状态。

原版脚本在两处 `args->parent_pid == cpid` 报有符号 int32 与无符号 uint32 比较警告。本次实际 PID 为正，输出核对正确；现将两处统一改为 `(uint32)args->parent_pid == cpid`。此处是实际创建任务的正 PID，可转换为 uint32。只调整比较类型，不改变归属规则或 map 键。用户随后确认复跑已无 warning，未提供修正版完整输出。警告消失按用户反馈记录；归属通过结论仍依据上一轮完整输出，不再要求重复运行。

## 实验③a：打开文件的路径与结果（受控场景实测通过）

用户同意继续文件实验，先采用前述最小范围：专用测试文件的打开观测。复用单组根进程登记和创建关系继承；本轮工作负载自身是单线程，不创建子进程，不重复宣称验证文件操作的多组或子进程归属。

- `file_open.py`：在 `/tmp/ebpf-exp3-*` 独立临时目录创建 sample.txt，再只读打开它，并尝试打开不存在的 missing.txt；成功关闭文件，验证失败错误为 ENOENT，结束自动清理自己的临时目录。
- `file_open.bt`：openat 入口保存路径、flags、进入时间，以 TID 为键；返回时输出同次调用的上下文与原始返回值，然后清理。退出时清理残余状态。
- 为减少 Python 启动噪声，只有已登记任务且传入路径以 `/tmp/ebpf-exp3-` 开头的 openat 调用才进入配对表。此过滤仅用于实验显示，不是工作区安全规则。

运行（在项目根目录，sudo 仅用户执行）：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/file_open.py' experiments/file_open.bt
```

如需记录命令退出状态，结束后立即运行 `echo $?`。提供完整输出以核对：

- WORKLOAD 的 pid 与 openat_result 的 pid 一致，agent_id=1。
- sample.txt 只读打开成功，原始 ret >= 0，是文件描述符（0 也可能成功）；与工作负载 fd 核对。
- missing.txt 的原始 ret 预期为 -2，对应工作负载 errno=2（ENOENT，不存在）。原始系统调用负错误码与用户态库返回 -1 并设置 errno 不同。
- 准备文件也会产生 sample.txt 的成功创建/打开事件，flags 与只读打开不同；临时目录清理也可能产生目录打开事件，不要求输出只有两条。
- mono_ns 为返回时刻，enter_ns 为入口时刻；路径在入口保存，按 TID 与返回配对。输出顺序可能与 WORKLOAD 行交错。

当前仅捕获 openat；不是读取内容、删除或 rename 监控，不覆盖 open/openat2。只验证短的绝对路径；str 长度上限可能截断长路径，不处理相对路径的 dirfd/cwd 解析、符号链接、路径变化与 namespace。filename 为调用参数，不宣称已获得一般意义的解析后真实路径。失败案例是预期行为，不是安全异常。正式路径方案、删除与多组文件归属仍需共同讨论。

### 工作负载单独实测（2026-09-15）

`python3 experiments/file_open.py` 退出状态为 0：

```text
WORKLOAD pid=37978 test_dir=/tmp/ebpf-exp3-13epcmet
WORKLOAD case=existing filename=/tmp/ebpf-exp3-13epcmet/sample.txt fd=3
WORKLOAD case=missing filename=/tmp/ebpf-exp3-13epcmet/missing.txt errno=2
WORKLOAD done=1
```

只证明测试工作负载正常；未执行 sudo，探针字段、编译、加载及事件配对均待用户运行验证。

参考：[open/openat 手册](https://man7.org/linux/man-pages/man2/open.2.html)、[bpftrace 文档](https://bpftrace.org/docs/0.21)。本机 0.20.2 的探针兼容性以实测为准。

### 实验③a 用户实测（2026-09-15）

```text
Attaching 6 probes...
event=register root_pid=53403 agent_id=1 basis=launch
WORKLOAD pid=53403 test_dir=/tmp/ebpf-exp3-ghh7itmu
mono_ns=15294145269320 enter_ns=15294144429167 event=openat_result pid=53403 tid=53403 agent_id=1 filename=/tmp/ebpf-exp3-ghh7itmu/sample.txt flags=524865 ret=3 basis=tracked_task
WORKLOAD case=existing filename=/tmp/ebpf-exp3-ghh7itmu/sample.txt fd=3
mono_ns=15294145907529 enter_ns=15294145885147 event=openat_result pid=53403 tid=53403 agent_id=1 filename=/tmp/ebpf-exp3-ghh7itmu/sample.txt flags=524288 ret=3 basis=tracked_task
mono_ns=15294146732561 enter_ns=15294146701037 event=openat_result pid=53403 tid=53403 agent_id=1 filename=/tmp/ebpf-exp3-ghh7itmu/missing.txt flags=524288 ret=-2 basis=tracked_task
WORKLOAD case=missing filename=/tmp/ebpf-exp3-ghh7itmu/missing.txt errno=2
mono_ns=15294147556621 enter_ns=15294147540118 event=openat_result pid=53403 tid=53403 agent_id=1 filename=/tmp/ebpf-exp3-ghh7itmu flags=526336 ret=3 basis=tracked_task
WORKLOAD done=1
mono_ns=15294159720983 event=exit pid=53403 tid=53403 agent_id=1
```

结果：单组单线程、短绝对路径 openat 的入口/返回配对目标通过。PID/TID 53403 与工作负载一致，agent_id=1；sample.txt 创建和只读打开均返回 fd=3，missing.txt 返回 -2 与工作负载 errno=2 一致；清理阶段还打开了临时目录。捕获任务退出事件。未提供命令 shell 退出状态，不推断该状态。

本机 Python os 常量核对：O_RDONLY=0、O_WRONLY=1、O_CREAT=64、O_TRUNC=512、O_CLOEXEC=524288、O_NONBLOCK=2048。因此 flags=524865 是 O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC；524288 是 O_RDONLY|O_CLOEXEC；526336 是 O_RDONLY|O_NONBLOCK|O_CLOEXEC。flags 表示打开参数，不证明随后执行了 read/write。目录打开结合工作负载代码可解释为临时目录清理准备，不是已观测到删除。

文件描述符关闭后可重用，多次 ret=3 不代表同一文件。WORKLOAD 与探针异步输出可交错；按路径、PID、进入/返回时间和结果核对。后续删除、相对路径/符号链接解析、多组文件归属与性能均未验证，具体设计待共同讨论。

## 2026-09-15 收尾与学习接续

用户确认今天到此为止。实验①、②a、②b、③a 的受控验证结果如上；实验③的后续删除等操作尚未确认或实施，不将整个文件实验标记完成。

本次最后讨论 file_open.bt 的状态表：

- `@path[tid]`、`@flags[tid]`、`@started[tid]` 按线程保存当前 openat 请求的信息；同一进程不同线程可交错调用，按 PID 存储会相互覆盖。当前同步 openat 场景按 TID 配对，不泛化到异步 I/O。
- `@started[tid] = nsecs` 同时保存进入时间并标记待配对请求；返回探针 `/@started[tid]/` 只接受已保存入口的调用，过滤未匹配实验路径的返回。处理结束删除表项。
- `enter_ns` 来自 @started，mono_ns 来自返回时刻；当前仅输出时间，没有计算耗时或实施异常判定。将其替换为 @pending 标记只是解释中的可选写法，没有改代码。
- `@agent` 解决业务归属，入口状态表解决调用配对，是不同职责。当前按任务 ID 继承 Agent 标签仅在受控单线程进程场景验证，多线程支持仍需设计与测试。

下次先回顾需要的概念，再共同确定文件删除等后续实验的最小范围。用户无需补跑已确认无 warning 的实验②b，也无需重复当前已完成验证。


## 实验③b：删除文件的路径与结果（2026-09-16，受控场景实测通过）

用户确认先观察文件删除。范围为单组单线程，在专用临时目录创建并关闭 sample.txt，使用短绝对路径删除，再次删除同一路径以产生 ENOENT；不加入异常判定。

- `file_unlink.py`：用 os.unlink 产生上述两次删除，打印 PID、路径、成功结果或 errno；结束自动清理自己的临时目录。
- `file_unlink.bt`：沿用③a 的根进程登记和标签继承；sys_enter_unlink 保存 pathname 和时间，以 TID 为键；sys_exit_unlink 输出路径、时间、PID/TID、agent_id、原始返回值和归属依据，再清理配对状态。退出时清理任务状态。
- 路径前缀过滤仅用于减少实验噪声，不是工作区安全规则。入口参数名为 pathname，输出字段仍用 filename。

项目根目录运行（sudo 仅用户执行）：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/file_unlink.py' experiments/file_unlink.bt
```

结束后立即运行 `echo $?`，回传完整输出和退出状态。预期核对：

1. register、WORKLOAD 和 unlink_result 的 PID 一致，agent_id=1。
2. 同一 sample.txt 路径出现两条 unlink_result，先 ret=0，再 ret=-2，对应工作负载 deleted=1 和 errno=2。
3. 有 WORKLOAD done=1 和任务退出事件。异步输出可交错，按 PID、路径和时间核对。

unlink 成功返回 0，不返回文件描述符；原始 syscall 失败返回负错误码。严格来说 unlink 移除文件名（目录项）；存在其他硬链接或打开的文件描述符时，不意味着空间立即释放。参考：[Linux unlink/unlinkat 手册](https://man7.org/linux/man-pages/man2/unlink.2.html)。

仅捕获 unlink，不覆盖 unlinkat、rmdir、rename；临时目录清理不作为本轮观测目标。本机 Python 无 dir_fd 的 os.unlink 预期走 unlink，以探针实测为准；未出现目标事件时应排查，不计为通过。路径为调用参数，不处理相对路径、符号链接解析或长路径截断，不证明真实路径解析、多组文件归属、多线程支持或安全异常检测。失败删除是有意安排的正常测试行为。

### 工作负载单独实测

助手运行 `python3 experiments/file_unlink.py`，退出状态 0：

```text
WORKLOAD pid=7995 test_dir=/tmp/ebpf-exp3-1qruaqv3
WORKLOAD case=existing filename=/tmp/ebpf-exp3-1qruaqv3/sample.txt deleted=1
WORKLOAD case=missing filename=/tmp/ebpf-exp3-1qruaqv3/sample.txt errno=2
WORKLOAD done=1
```

仅验证 Python 工作负载；未执行 sudo，探针编译、加载和事件输出均待用户验证。工具沙箱仍报 bwrap loopback 权限错误，此次工作负载通过授权在沙箱外运行。


### 实验③b 用户实测（2026-09-16）

用户提供输出如下，保留末尾附带的 0：

```text
Attaching 6 probes...
event=register root_pid=9848 agent_id=1 basis=launch
WORKLOAD pid=9848 test_dir=/tmp/ebpf-exp3-sl87mcvz
WORKLOAD case=existing filename=/tmp/ebpf-exp3-sl87mcvz/sample.txt deleted=1
mono_ns=3351391842552 enter_ns=3351391792241 event=unlink_result pid=9848 tid=9848 agent_id=1 filename=/tmp/ebpf-exp3-sl87mcvz/sample.txt ret=0 basis=tracked_task
WORKLOAD case=missing filename=/tmp/ebpf-exp3-sl87mcvz/sample.txt errno=2
mono_ns=3351392442468 enter_ns=3351392437611 event=unlink_result pid=9848 tid=9848 agent_id=1 filename=/tmp/ebpf-exp3-sl87mcvz/sample.txt ret=-2 basis=tracked_task
WORKLOAD done=1
mono_ns=3351402058819 event=exit pid=9848 tid=9848 agent_id=1 0
```

核对：登记、工作负载和两次事件的 PID 均为 9848，TID=9848、agent_id=1；同一路径先 ret=0，再 ret=-2，与 deleted=1、errno=2 一致；有完成标记和退出事件。探针成功加载，单组单线程、短绝对路径 unlink 入口/返回配对目标通过，确认本次工作负载触发 unlink。末尾附带的 0 按前文指令理解为 echo $? 输出，不是 exit 探针记录的任务退出码。

Attaching 6 probes 对应 BEGIN、fork、unlink 入口、unlink 返回、任务退出、END 六个探针块，不是六次删除。WORKLOAD 和探针输出异步交错正常。失败删除是预期测试，不是异常告警。尚未验证 unlinkat、真实路径解析、多组文件归属或安全检测；下一步范围待共同讨论。


## 实验③c：两组 Agent 各自打开和删除文件（2026-09-16，受控场景实测通过）

用户确认进行双组文件归属实验。复用②b 的启动门和按直接孩子创建顺序分配标签的受控方案；不改动已有实验。

- `two_file_agents.py`：启动器创建恰好两个单线程根进程，通过管道放行，各自执行 file_activity.py，并等待两组结束；启动器自身不登记为 Agent。
- `file_activity.py`：每组创建独立 /tmp/ebpf-exp3-* 目录，打印 PID 和路径，创建并关闭 sample.txt，只读打开并关闭，删除，再尝试打开和删除已不存在的路径，核对 errno=2。每条工作负载结果带 PID，以便交错时核对。
- `two_file_agents.bt`：沿用②b 的创建顺序登记与后代继承逻辑，合并③a/③b 的 openat/unlink 入口返回观测。两种调用使用独立的按 TID 索引的状态表，返回或任务退出时清理。探针独立采集，不读取 WORKLOAD 输出或按路径分配 Agent。

项目根目录运行（sudo 仅用户执行）：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/two_file_agents.py' experiments/two_file_agents.bt
```

结束后立即运行 `echo $?`，回传完整输出及状态。预期 Attaching 8 probes，对应 BEGIN、fork、openat 入口/返回、unlink 入口/返回、任务退出、END。

核对方法：先从 LAUNCHER 建立 agent_id → root_pid，再从 WORKLOAD 建立 PID → test_dir；所有目标文件事件应同时匹配这两项，不能串组。每组 sample.txt 预期有创建打开成功、只读打开成功、unlink ret=0、删除后 openat ret=-2、再次 unlink ret=-2；只读打开的返回 fd 与对应 WORKLOAD 核对。清理临时目录可能产生额外的目录 openat，不属于错误。两组均应有 done=1、退出事件、LAUNCHER exit_code=0。

### 工作负载单独验证

助手运行 `python3 experiments/two_file_agents.py`，退出状态 0。启动器 PID 13804，Agent 1 根 PID 13815、目录 /tmp/ebpf-exp3-5m4u9as6；Agent 2 根 PID 13816、目录 /tmp/ebpf-exp3-89sq6q76。两组 open_existing fd=3、unlink_existing deleted=1，open_missing/unlink_missing 均 errno=2，两组 done=1 且 exit_code=0。输出有交错。本次只验证 Python 工作负载，尚未编译加载新探针或验证文件事件归属，未运行任何 sudo 命令。

启动门保证根进程生命周期重叠，不保证文件 syscall 同时发生或固定交错；不要求输出逐行交替。每组本轮不再创建后代，不能据此声称验证了后代文件归属、多线程、更多实例或压力测试。仍只覆盖短绝对路径参数、openat/unlink，不覆盖通用真实路径解析、unlinkat、rename、异常判定或性能指标。按创建顺序分配 Agent 标签仅适用于受控启动器，正式身份方案未定。


### 实验③c 用户实测（2026-09-16）

探针成功加载（Attaching 8 probes），启动器 PID 14216。用户完整输出核对摘要：

| Agent | 根 PID/TID | 临时目录 | sample.txt 的结果（按操作顺序） |
| --- | --- | --- | --- |
| 1 | 14217 | /tmp/ebpf-exp3-gt2mtlvk | 创建 openat ret=3；只读 openat ret=3；unlink ret=0；openat ret=-2；unlink ret=-2 |
| 2 | 14218 | /tmp/ebpf-exp3-6b9zemd7 | 创建 openat ret=3；只读 openat ret=3；unlink ret=0；openat ret=-2；unlink ret=-2 |

每条文件事件的 PID、agent_id、路径均与 LAUNCHER 和 WORKLOAD 对应，未见串组；各组另有清理临时目录时的 openat（flags=526336、ret=3）。两组 WORKLOAD done=1、两个退出事件齐全，LAUNCHER 报告两组 exit_code=0。用户原粘贴末尾附带 127，随后明确更正为 0，故命令退出状态按用户更正记录为 0，无待排查退出状态问题。

关键时间证据：Agent 1 登记 mono_ns=4186432694984，Agent 2 登记 4186435338034；Agent 2 最后一条目录 openat 返回 4186482694366，Agent 1 第一条文件创建 openat 进入 4186484833961；Agent 2 退出 4186496918752，Agent 1 退出 4186498322179。两根进程生命周期重叠，但本次观测到的目标文件调用按 Agent 2、Agent 1 先后发生，未验证文件调用同时在途或高并发压力。

用户粘贴中两条失败 openat 出现 ret=-2basis=tracked_task（缺少分隔空格），未影响本次人工核对；不据此推断采集异常或修改代码。

结论：双组单线程、短绝对路径 openat/unlink 入口返回配对和 Agent 归属目标通过。仍不证明通用真实路径解析、后代文件归属、多线程、更多实例规模、安全检测或性能指标。下一步可共同设计实验④网络连接最小范围，尚未确认或实现。


## 实验④a：一次本地 TCP 连接（2026-09-16，受控场景实测通过）

用户确认先做本地连接最小实验。范围为单组、单线程、一次成功的阻塞 IPv4 TCP connect，不依赖 DNS 或外网。

- `network_connect.py`：同一进程先在 127.0.0.1:0 bind，由系统分配端口，再 listen；创建客户端阻塞 socket，connect 到该监听端，最后 accept 并核对双方地址。TCP 握手由内核处理，不需要另起服务线程。上下文管理器关闭全部 socket，signal.alarm(10) 限制整体等待，不使用会引入非阻塞 connect 的 socket 超时模式。
- `network_connect.bt`：复用单组登记与任务继承逻辑；sys_enter_connect 读取 uservaddr 指向的用户态 IPv4 地址结构，检查 addrlen >= 16、family=2（AF_INET）。按 TID 保存地址、端口、fd、时间，sys_exit_connect 输出并清理，任务退出时清理残余状态。
- 自定义结构对应 Linux sockaddr_in 布局；端口两个网络序字节按高字节乘 256 加低字节转换，地址用 ntop 格式化。探针读取实际参数，没有把目标 IP 或端口写死；只过滤跟踪任务和 IPv4。

项目根目录运行（sudo 仅用户执行）：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/network_connect.py' experiments/network_connect.bt
```

结束后立即运行 `echo $?`，回传完整输出及状态。预期 Attaching 6 probes；register、WORKLOAD、connect_result 的 PID 一致，agent_id=1，connect_result 的 fd 与 case=connect 一致，dst_ip=127.0.0.1、dst_port 与 WORKLOAD 监听端口一致，ret=0；应有 connected=1、accepted=1、done=1 和退出事件。端口每次可能变化。accepted 行的 peer_port 是客户端源端口，不应与目标监听端口混淆。输出可异步交错。

### 工作负载单独验证

助手运行 `python3 experiments/network_connect.py`，退出状态 0：

```text
WORKLOAD pid=20434 dst_ip=127.0.0.1 dst_port=38899 listening=1
WORKLOAD pid=20434 case=connect fd=4 dst_ip=127.0.0.1 dst_port=38899
WORKLOAD pid=20434 connected=1
WORKLOAD pid=20434 accepted=1 peer_ip=127.0.0.1 peer_port=58942
WORKLOAD pid=20434 done=1
```

只证明 Python 工作负载成功。新探针尚未编译加载，字段、uptr 和 ntop 的本机 bpftrace 0.20.2 兼容性及实际解析结果均待用户验证。未运行 sudo。

本轮不验证失败连接、非阻塞连接最终结果、IPv6、UDP、双组网络归属、外网、应用内容或性能。connect 探针本身不验证 socket 类型；TCP 来自本次已知工作负载。对于非阻塞连接，不能将 EINPROGRESS 简单视为最终失败，需要另行设计完成状态观测。一次连接不等于一次 API 请求，不证明 HTTPS 明文或模型交互采集。

参考：[Linux connect 手册](https://man7.org/linux/man-pages/man2/connect.2.html)、[bpftrace 文档（uptr、ntop）](https://bpftrace.org/docs/0.21)。本机兼容性以实测为准。


### 实验④a 用户实测（2026-09-16）

```text
Attaching 6 probes...
event=register root_pid=21232 agent_id=1 basis=launch
WORKLOAD pid=21232 dst_ip=127.0.0.1 dst_port=55141 listening=1
WORKLOAD pid=21232 case=connect fd=4 dst_ip=127.0.0.1 dst_port=55141
WORKLOAD pid=21232 connected=1
WORKLOAD pid=21232 accepted=1 peer_ip=127.0.0.1 peer_port=42590
WORKLOAD pid=21232 done=1
mono_ns=5627616924837 enter_ns=5627616504485 event=connect_result pid=21232 tid=21232 agent_id=1 fd=4 family=2 dst_ip=127.0.0.1 dst_port=55141 ret=0 basis=tracked_task
mono_ns=5627625354192 event=exit pid=21232 tid=21232 agent_id=1
0
```

核对：登记、工作负载和事件 PID/TID 均为 21232，agent_id=1、fd=4；目标 127.0.0.1:55141 与监听端一致，ret=0 与 connected=1 一致；accepted=1、done=1 和退出事件齐全，用户提供命令退出状态 0。客户端源端口 42590 与目标监听端口不同是正常的。探针编译加载及本次 IPv4 地址、网络序端口解析通过。

connect_result 显示在 WORKLOAD done=1 之后是异步输出交错，不代表连接在脚本完成后才发生。单组单线程、本地阻塞 IPv4 TCP connect 观测目标通过；失败连接、非阻塞最终结果、IPv6、双组网络归属、真实 Agent、应用请求内容和性能仍未验证。下一步范围待共同讨论。


## 实验④b：两组 Agent 的本地 TCP 连接归属（2026-09-21，受控场景实测通过）

`two_network_agents.py` 创建恰好两个单线程根进程，通过启动门统一放行，各自执行 `network_connect.py`。`two_network_agents.bt` 按启动器创建直接孩子的顺序标记 Agent 1、2，并按 TID 配对 IPv4 connect 的入口与返回。

用户实测中，启动器 PID 9331；Agent 1 根 PID 9332，目标 `127.0.0.1:54075`；Agent 2 根 PID 9333，目标 `127.0.0.1:51883`。两条 `connect_result` 均为 fd=4、ret=0，PID、agent_id、IP 和端口分别与对应 WORKLOAD 一致，未见串组。两组均有 connected=1、accepted=1、done=1、退出事件和 LAUNCHER exit_code=0；用户提供监控命令退出状态 0。

本次 Agent 2 的连接和退出先于 Agent 1 的连接，两个根进程生命周期有重叠，但目标 connect 没有同时在途，因此不是并发压力验证。创建顺序分配标签仍只适用于受控启动器。本实验不证明更多实例、任意并发下无事件丢失、失败或非阻塞连接、IPv6、外网、应用层请求或性能指标。


## 实验④c：本地 TCP 连接失败（2026-09-21，受控场景实测通过）

`network_connect_fail.py` 先绑定 `127.0.0.1:0` 取得系统分配端口，随后关闭该 socket，再用阻塞 TCP socket 连接刚释放的端口。正常情况下没有监听者，Python 应得到 `ECONNREFUSED`（errno 111）。复用已验证的 `network_connect.bt`，检查入口参数和原始系统调用返回值。

运行：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/network_connect_fail.py' experiments/network_connect.bt
```

结束后立即运行 `echo $?`，回传完整输出和状态。预期 `connect_result` 的 PID、fd、IP 和端口与 WORKLOAD 一致，agent_id=1，ret=-111；同时有 `connect_failed=1 errno=111`、`done=1`、退出事件和命令退出状态 0。

工作负载单独运行已通过：PID 11735、fd=3、目标 `127.0.0.1:59007`，得到 errno=111，脚本退出状态 0。端口每次变化。关闭预留 socket 到发起 connect 之间存在很小的端口被其他进程占用窗口；若连接意外成功，脚本会明确失败，不把该次计为通过。

本轮只验证阻塞 IPv4 TCP 的立即拒绝，不覆盖超时、路由不可达、防火墙拒绝、非阻塞连接最终状态或 IPv6。


### 实验④c 用户实测

探针成功加载。PID/TID 12114、agent_id=1、fd=3，目标 `127.0.0.1:54331` 在 WORKLOAD 与 `connect_result` 中一致。Python 输出 `connect_failed=1 errno=111`，探针输出原始返回值 `ret=-111`；有 `done=1`、退出事件，用户提供命令退出状态 0。因此单组本地阻塞 IPv4 TCP 立即拒绝的观测目标通过。

输出中的 `^[[A` 是终端方向键的转义序列，不属于探针或工作负载事件，不影响结论。验证范围仍不覆盖超时、路由不可达、防火墙拒绝、非阻塞连接最终状态或 IPv6。


## 实验⑤a：非预期 Shell 启动告警（2026-09-21，受控场景实测通过）

本轮策略明确设为 Agent 1 不允许启动 `/bin/sh` 或 `/bin/bash`。`unexpected_shell.py` 创建一个孩子，孩子执行无副作用的 `/bin/sh -c 'exit 0'`；父进程等待并输出孩子退出码。`unexpected_shell.bt` 复用进程树标签继承，在已跟踪任务的 execve 入口输出审计事件，并在目标恰好为上述两个路径之一时输出 `security_alert`。

告警包含单调时间、PID/TID、agent_id、目标、严重度、规则、策略和证据字段。`evidence=execve_attempt,process_tree_attribution` 表示告警依据是 Shell 执行尝试以及进程树归属。本轮只验证 execve 尝试；工作负载的 child_exit_code=0 用于辅助确认受控案例确实执行成功，不是探针直接观测到的 execve 返回结果。

运行：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/unexpected_shell.py' experiments/unexpected_shell.bt
```

结束后立即运行 `echo $?`，回传完整输出与状态。预期孩子的 PID 在 fork、WORKLOAD、execve_attempt、security_alert 和 exit 中一致，agent_id=1、target/filename=/bin/sh；仅有一条目标安全告警，孩子退出码和命令退出状态均为 0。

工作负载单独运行已通过：根 PID 14217、孩子 PID 14229，目标 `/bin/sh`，child_exit_code=0，脚本退出状态 0。只验证了工作负载，探针编译加载和告警字段待用户验证。

这是规则证据与告警格式的 bpftrace 原型，规则判断目前写在探针脚本中，不等同于已完成正式用户态检测器。所有 Shell 启动也不天然恶意；本轮告警成立是因为受控策略明确禁止该 Agent 启动 Shell。尚未验证相对路径、其他 Shell 路径、符号链接、execveat、双组策略差异、误报率或绕过方式。


### 实验⑤a 用户实测

探针成功加载（Attaching 5 probes）。根 PID 14653 以 agent_id=1 登记，启动 `/usr/bin/python3` 时只输出普通 `execve_attempt`，没有安全告警。根进程创建孩子 PID 14661，孩子通过 fork 继承 agent_id=1；其 `/bin/sh` execve 尝试同时输出审计事件和一条 `severity=high rule=unexpected_shell` 告警，target、policy 和 evidence 字段符合设计。

孩子随后退出，工作负载报告 child_exit_code=0；根任务也有退出事件，用户提供监控命令退出状态 0。由受控工作负载可辅助确认本次 `/bin/sh -c 'exit 0'` 实际执行成功。PID、归属、目标、规则和证据链一致，因此本轮最小告警目标通过。

本次只产生一条目标告警，且 Python 启动未误报，但这不足以评估一般场景的误报率。探针仍在 execve 入口判断尝试，并且规则位于 bpftrace 脚本中；正式用户态规则引擎、其他 Shell 路径、符号链接、execveat、双组差异策略和绕过测试仍未完成。


## 实验⑤b：模拟敏感文件访问告警（2026-09-21，受控场景实测通过）

本轮把 `/tmp/ebpf-exp5-sensitive-*` 定义为 Agent 1 禁止读取的模拟敏感路径。`sensitive_file_access.py` 的启动器先创建无害的 `secret.txt`，再 fork 一个孩子作为 Agent 1；孩子使用只读 open 和 read 核对内容。启动器等待孩子后清理自己创建的文件与目录。启动器本身不登记为 Agent，因此夹具准备和清理不会触发该 Agent 的告警。

`sensitive_file_access.bt` 在启动器创建直接孩子时登记 Agent 1，后代沿进程树继承。它按 TID 配对匹配敏感路径前缀的 openat 入口与返回，先输出 `openat_result`，再输出 `rule=sensitive_file_access` 告警。成功访问为 high、`outcome=success`，失败尝试为 medium、`outcome=failed`；告警包含时间、PID/TID、agent_id、路径、flags、ret、策略和证据。

运行：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/sensitive_file_access.py' experiments/sensitive_file_access.bt
```

结束后立即运行 `echo $?`，回传完整输出与状态。预期 LAUNCHER 的 agent_id=1/root_pid 与 WORKLOAD PID、register、openat_result、security_alert 和 exit 一致；目标都是同一个 secret.txt，openat ret>=0，告警 severity=high、outcome=success；read_sensitive=1 bytes=21，孩子和监控命令退出状态均为 0。启动器不应因创建或清理夹具产生该规则告警。

工作负载单独运行已通过：启动器 PID 17500，Agent 1 根 PID 17522，夹具 `/tmp/ebpf-exp5-sensitive-3qr0z637/secret.txt`，成功读取 21 字节，孩子退出码和脚本退出状态为 0。探针尚未编译加载。

这是 bpftrace 规则原型，只匹配短绝对路径参数前缀，不是通用真实路径或权限语义；相对路径、符号链接、路径规范化、open/openat2、读取内容、双组差异策略、失败访问和正式用户态检测器尚未验证。这里的文件内容是专用无害测试数据，不接触真实敏感文件。


### 实验⑤b 用户实测

探针成功加载（Attaching 6 probes）。启动器 PID 17990 创建夹具 `/tmp/ebpf-exp5-sensitive-mvpfxwio/secret.txt`，但未登记为 Agent。其孩子 PID/TID 17991 登记为 Agent 1，并对同一路径执行 openat；事件 flags=524288（本机为 O_RDONLY|O_CLOEXEC）、ret=3，随后输出一条 `severity=high rule=sensitive_file_access outcome=success` 告警。WORKLOAD 成功读取 21 字节。

路径、PID/TID、agent_id、flags 和 ret 在访问事件与告警中一致；孩子退出事件齐全，LAUNCHER exit_code=0，用户提供监控命令退出状态 0。输出中没有启动器准备或清理夹具产生的规则告警，符合“启动器不属于 Agent”的设计。因此模拟敏感文件成功访问的最小告警目标通过。

本次只验证一次短绝对路径的成功只读访问。flags 表示打开方式，不证明探针观测了 read 内容；读取 21 字节来自工作负载自检。相对路径、符号链接、规范化路径、open/openat2、失败访问、写入、双组策略、误报率与正式用户态检测器仍未验证。


## 实验⑤c：超工作区删除告警（2026-09-21，受控场景实测通过）

本轮使用固定专用测试根目录 `/tmp/ebpf-exp5-delete/`，其中 `workspace/` 是 Agent 1 允许删除的范围，兄弟目录 `outside/` 位于工作区之外。`outside_workspace_delete.py` 的启动器创建两个无害测试文件，孩子作为 Agent 1 先删除 `workspace/allowed.txt`，再删除 `outside/victim.txt`；启动器等待孩子并清理专用目录。若测试根目录预先存在，脚本会停止，不覆盖或删除未知内容。

`outside_workspace_delete.bt` 在启动器创建直接孩子时登记 Agent 1，按 TID 配对测试根目录内的 unlink 入口与返回。两次删除都输出 `unlink_result` 和 `outside_workspace` 标记；只有路径位于 outside 且 ret=0 时输出 `rule=outside_workspace_delete severity=high outcome=success` 告警。启动器本身不属于 Agent。

运行：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/outside_workspace_delete.py' experiments/outside_workspace_delete.bt
```

结束后立即运行 `echo $?`，回传完整输出及状态。预期 Agent PID 在 register、WORKLOAD、两条 unlink_result、告警和 exit 中一致。allowed.txt 应为 ret=0、outside_workspace=0 且不告警；victim.txt 应为 ret=0、outside_workspace=1，并且只产生一条 outside_workspace_delete 告警。孩子和监控命令退出状态均为 0。

工作负载单独运行已通过：启动器 PID 20976，Agent 1 PID 20989，两次删除成功，孩子和脚本退出状态 0，专用目录已清理。只验证了工作负载，探针尚未编译加载。

这是固定测试路径上的 bpftrace 规则原型，不是一般路径边界算法。它只捕获 unlink，不覆盖 unlinkat、rename、rmdir；相对路径、符号链接、`..`、挂载点、namespace、竞态、失败删除、双组独立工作区与正式用户态检测器仍未验证。


### 实验⑤c 用户实测

探针成功加载（Attaching 6 probes）。启动器 PID 21413，直接孩子 PID/TID 21414 登记为 Agent 1。Agent 先删除 `/tmp/ebpf-exp5-delete/workspace/allowed.txt`，unlink 返回 0、`outside_workspace=0`，没有产生安全告警；随后删除 `/tmp/ebpf-exp5-delete/outside/victim.txt`，unlink 返回 0、`outside_workspace=1`，输出一条 `severity=high rule=outside_workspace_delete outcome=success` 告警。

两条删除事件及告警的 PID/TID、agent_id、路径、返回值和策略对应正确。孩子退出事件齐全，LAUNCHER exit_code=0，用户提供监控命令退出状态 0。因此“允许范围内删除不告警、工作区外成功删除告警”的正反对照目标通过。

该结论仍限于固定专用路径、短绝对路径和 unlink。它不证明相对路径或符号链接解析、路径规范化、unlinkat/rename/rmdir、失败删除、TOCTOU 竞态、namespace、双组独立工作区、误报率或正式用户态规则引擎。


## 实验⑥a：重复失败文件打开告警（2026-09-21，受控场景实测通过）

本轮规则定义为：同一 Agent 在 2 秒窗口内，对固定路径 `/tmp/ebpf-exp6-repeat/missing.txt` 的 openat 连续至少 5 次返回 ENOENT（原始 ret=-2），输出一次 `repeated_failed_open` 告警。证据同时包含相同目标、重复失败、次数阈值、时间窗口和进程归属，避免仅凭单次失败告警。

`repeated_failed_open.py` 创建专用空目录，对不存在的 missing.txt 连续只读打开 5 次并核对 errno=2，结束后删除空目录。若专用目录已存在则停止，不清理未知内容。`repeated_failed_open.bt` 按 TID 配对 openat，按 agent_id 保存窗口起点、失败次数和是否已告警；逐次输出 openat_result 与 activity_evidence，只在达到阈值且本窗口尚未告警时输出一条 medium 告警，任务退出时清理状态。

运行：

```bash
sudo bpftrace -c '/usr/bin/python3 experiments/repeated_failed_open.py' experiments/repeated_failed_open.bt
```

结束后立即运行 `echo $?`，回传完整输出及状态。预期同一 PID/TID、agent_id=1、相同路径出现 5 条 ret=-2；activity_evidence 的 count 从 1 到 5，elapsed_ns 小于或等于 2000000000；只在 count=5 时产生一条 repeated_failed_open 告警；有 done=1、退出事件和命令退出状态 0。

工作负载单独运行已通过：PID 22491，连续 5 次 errno=2，done=1，脚本退出状态 0，专用目录已清理。探针尚未编译加载。

这是固定路径、固定阈值的 bpftrace 原型。当前计数按 agent_id 聚合，但只测试单线程单目标；多线程并发更新、多个目标分别计数、滑动窗口、事件丢失、成功操作是否重置、告警冷却、正常重试误报和正式用户态检测器均未验证。该规则只是重复无意义文件活动的一种证据，不足以单独证明逻辑死循环或资源浪费。


### 实验⑥a 用户实测

探针成功加载（Attaching 6 probes）。PID/TID 22858 登记为 Agent 1，对固定路径 `/tmp/ebpf-exp6-repeat/missing.txt` 连续产生 5 条 openat_result，全部 ret=-2。对应 activity_evidence 的 count 严格从 1 增长到 5；首次 elapsed_ns=0，第 5 次 elapsed_ns=1250703，约 1.25 ms，明显小于 2 秒窗口。

只在 count=5 时输出一条 `severity=medium rule=repeated_failed_open` 告警，字段包含相同路径、errno=2、阈值、窗口、累计时间和四项 evidence。任务退出事件齐全，用户提供命令退出状态 0。WORKLOAD 的 5 次 errno=2 和 done=1 与探针证据一致；WORKLOAD 行先于探针事件显示属于异步输出交错。

因此固定路径、单 Agent、单线程场景下的计数、时间窗口和单次告警目标通过。它仍不证明逻辑死循环或资源浪费；多目标分别计数、多线程原子性、窗口边界与重置、告警冷却、正常重试误报、事件丢失、资源指标融合和正式用户态检测器尚未验证。

## 正式 CPU 与重复活动联合异常（已实测通过）

resource_logic_anomaly.py 在专用目录内对同一缺失文件执行 5 次打开，再持续
约 1 秒进行 CPU 计算。正式监控器每 200 ms 读取 Agent cgroup 的 cpu.stat，
以单核 100% 为基准计算区间 CPU 使用率。detector 保留原有
repeated_failed_open 告警，并在相同 Agent、相同 2 秒窗口内同时满足
CPU >= 50% 时额外输出一次 resource_logic_anomaly。

运行命令见根目录 README。代码已严格编译并完成下述 sudo 端到端验证；该组合
只是“重复无意义活动 + CPU 消耗”的受控证据，不等同于一般逻辑死循环识别。

### CPU 与重复活动联合异常用户实测

用户已完成正式端到端验证：Agent 1 为 cgroup 12072、PID/TID 41002。专用缺失
路径连续 5 次返回 -ENOENT，count 1→5，第 5 次 elapsed_ns=447759，并产生一条
medium repeated_failed_open 告警。随后首个 CPU 区间为 232420 us，累计使用
230982 us，单核等价 99.38%，产生一条 high resource_logic_anomaly；其
agent_id、cgroup_id、PID/TID、目标路径和 2 秒窗口与活动证据一致。

后续 100.02%、99.89%、99.93% 和 60.14% 的 CPU 样本没有重复产生联合告警，
验证了同一活动窗口只告警一次。工作负载打印 cpu_busy_done=1 和 done=1，
PROCESS_EXIT 的 exit_code_raw=0。补充输出确认 agent_exit exit_code=0，监控器整体退出状态也为 0，因此本次
正式端到端功能验证完整通过。退出前紧邻的强制采样形成 328 us、0% 的短区间，
不影响告警结论，后续可作为日志降噪项处理。

## 多 Agent 联合异常隔离（已实测通过）

repeated_failed_open_idle.py 在解释器启动后等待 0.5 秒，再产生 5 次相同 ENOENT
并保持空闲；cpu_busy_only.py 同样等待 0.5 秒，随后只持续占用 CPU。二者与已有
resource_logic_anomaly.py 三组并发运行，分别构成重复活动反例、CPU 反例和联合
正例。预期只有 Agent 3 产生 resource_logic_anomaly，运行命令见根目录 README。


### 多 Agent 联合异常隔离用户实测

三组根进程并发运行并正常退出：Agent 1 为 cgroup 12142/PID 42942，
Agent 2 为 cgroup 12161/PID 42943，Agent 3 为 cgroup 12180/PID 42944。
Agent 1 对专用路径 5 次 ENOENT 后产生一条 medium repeated_failed_open，
随后 CPU 为 0.15%、0% 和 7.04%，没有联合告警。Agent 2 的 CPU 达到
86.17% 和 99.75%，没有目标重复失败，也没有联合告警。

Agent 3 在 2763672 ns 内达到 5 次失败阈值，首个关联 CPU 样本为 96.53%，
产生唯一一条 high resource_logic_anomaly；后续 100.04% 和 99.87% 未重复告警。
三组 PROCESS_EXIT、agent_exit 均为 0，监控器整体退出状态为 0。该结果验证本次
三组并发受控场景中活动状态和 CPU 样本按 agent_id+cgroup_id 隔离，未发生串组；
仍不等同于更大规模压力测试。

## 固定混合工作负载性能对比（已完成首轮）

performance_workload.py 依次执行固定 CPU 计算、10000 次文件打开、500 次本地
TCP 连接和 100 个子进程，记录总耗时与分阶段耗时。run_performance_benchmark.sh
先预热，再默认完成 5 对基线/监控运行，并由 performance_report.py 使用中位数
计算开销百分比。完整运行方式和解释边界见根目录 README。


### 首轮性能结果

用户在 VirtualBox 环境完成 5 对配对运行。中位数结果为：总耗时从
631.674 ms 增至 1333.965 ms，开销 111.18%；CPU 阶段 9.21%；文件阶段
1900.00%；网络阶段 804.12%；进程阶段 62.19%。当前完整原始日志模式明显未达到
5% 参考指标。

监控输出虽重定向到 /dev/null，但每条事件仍执行 Ring Buffer 传输、用户态分派、
字符串格式化和 printf。文件与网络高频事件的结果表明日志热路径是主要候选瓶颈；
当前数据不能区分内核采集成本与逐事件文本输出成本。下一步应增加不格式化原始事件
的基准模式，再使用相同工作负载拆分测量，之后才决定是否需要内核侧过滤或聚合。

### 静默模式复测（已完成）

监控器新增全局 --quiet-events。性能驱动已使用该参数，普通事件仍被采集、传输、
校验并交给 detector，但跳过文本格式化与 printf。重新运行相同脚本可与首轮完整
日志模式比较，估计逐事件日志在总开销中的占比。


静默模式 5 对复测结果：总耗时 694.504→1639.633 ms，开销 136.09%；
CPU 6.40%、文件 3098.88%、网络 785.74%、进程 66.62%。静默后没有改善，
因此首轮将主要开销归因于文本格式化的假设被实测否定。文件阶段的 bpf_d_path、
各探针的全量事件构造/Ring Buffer 提交，以及一个进程带来的多类事件放大是当前
主要候选原因。该负载属于高事件密度微基准，不能代表真实 Agent 平均开销，但证明
当前全量采集配置未达到 5% 参考目标。

## 按事件类别隔离性能（已实测）

监控器新增全局 --events process,file,network，可组合选择。未选择类别的 BPF
程序在加载前关闭 autoload。性能驱动现在依次测试 process、file、network 和 all
四种静默配置，每种完成 5 对相邻基线/监控运行并单独报告中位数，便于识别各类
探针对所有工作负载阶段的影响。


### 分类性能结果

用户完成四类各 5 对配对运行。process-only 总开销 11.48%，其中 100 个子进程
阶段 25.95%；file-only 总开销 102.07%，10000 次打开阶段 3599.13%；
network-only 总开销 34.32%，500 次连接阶段 866.38%；all 总开销 135.43%，
文件、网络和进程阶段分别为 2784.51%、923.57% 和 64.08%。

结果明确将 file_open 真实路径全量采集定位为最大热点，其次为逐连接网络事件；
子进程还会加载动态库并触发文件事件，因此全量模式的进程阶段存在事件放大。CPU
及无关阶段出现负值或较大波动，反映 5 次样本与 VirtualBox 调度噪声，不能解释为
性能提升。当前全量模式未达到 5% 参考目标，后续优化必须明确事件完整性取舍。

## FILE_OPEN 每 N 次抽样性能（已完成首轮）

新增全局 --file-open-sample-every N。默认 N=1 全量采集；N>1 时 BPF 在
bpf_d_path 之前按 cgroup 确定性保留约 1/N 的 FILE_OPEN。删除和失败 openat
仍全量，--sensitive-path 与抽样互斥。run_file_sampling_benchmark.sh 使用
file-only 静默模式分别完成 N=1、10、100 的 5 对配对测试。


### FILE_OPEN 抽样性能结果

用户完成 N=1/10/100 各 5 对测试。N=1 总开销 126.91%，文件阶段
3227.18%；N=10 总开销 15.87%，文件阶段 682.20%；N=100 总开销 5.94%，
文件阶段 313.24%。N=100 将总耗时中位数从 678.162 ms 增至 718.424 ms，
绝对增加约 40.3 ms，已经接近但仍高于 5% 参考目标。

N=100 的 CPU 阶段为 12.35%，无关网络阶段为 -25.58%，说明 5 次 VirtualBox
样本存在明显调度波动。当前不能宣称达标；应增加重复次数、报告离散程度，并在真实
Linux 机器复测。结果同时证明在 bpf_d_path 前抽样能显著降低全量路径采集成本。

## FILE_OPEN N=100 稳定性复测（已实测）

run_file_sampling_stability.sh 固定 N=100，完成 15 对相邻基线/监控样本。
performance_report.py 已增加配对开销中位数及 p25/p75，减少两组独立中位数受
虚拟机时间漂移影响的问题。


15 对复测结果：总耗时中位数 703.902→768.113 ms，两组中位数开销 9.12%；
逐对开销中位数 8.74%，p25/p75 为 4.60%/12.60%。文件阶段逐对开销中位数
253.55%，p25/p75 为 231.27%/345.45%。因此先前 5 对得到的 5.94% 偏乐观，
N=100 在当前实现和虚拟机中不能宣称达到 5%。

CPU、网络等无关阶段仍有跨零的大幅波动，但总开销区间的稳定中心高于 5%。
当前每次 FILE_OPEN 即使未被采样保留，也会额外查询 file_open_counts map；
下一优化候选是把采样计数并入已有 cgroup 归属 map，去掉第二次 map 查询。

### FILE_OPEN 采样 map 合并（待实机复测）

`agent_by_cgroup` 的 value 已由单个 agent_id 扩展为 agent_context，同时保存
agent_id 和 file_open_count。FILE_OPEN 用已有归属查询结果完成原子计数与抽样，
独立 file_open_counts map 已删除；N=1/100 的外部语义不变。严格构建、Python
语法、shell 语法与 git diff --check 已通过。BPF verifier 加载和 15 对性能结果
仍待 sudo 实测，不能提前认定开销下降或达到 5%。

### FILE_OPEN 采样 map 合并复测结果

用户完成合并后的 N=100、15 对稳定性复测。两组中位数总开销为 7.29%，逐对
开销中位数为 8.08%，p25/p75 为 6.02%/15.29%；文件阶段逐对中位数为
294.00%，p25/p75 为 239.19%/357.29%。相比合并前的总开销逐对中位数
8.74%，中心值只下降 0.66 个百分点，而 p75 从 12.60% 上升至 15.29%，
文件阶段中心值也未改善。该优化已通过 verifier 和端到端运行，但一次额外 map
查询不是主要瓶颈，差异不足以从 VirtualBox 波动中稳定区分，仍未达到 5%。

## 真实 Codex Agent + 百炼 Qwen（直连已通过，受控网络待复测）

当前启动器默认模型已于 2026-09-28 从额度耗尽的 qwen3.8-max-0902 切换为
qwen3.8-27b；下面保留的是首次接入 Max 模型时的历史验证记录。

## 一键基础验收演示（2026-09-28）

`run_acceptance_demo.sh` 使用正式监控器同时启动两个确定性 Python Agent，不调用
百炼或其他外部模型。Agent 1 覆盖敏感读取、工作区内/外删除、5 次同目标 ENOENT
及约 1.2 秒 CPU 忙循环；Agent 2 覆盖 Shell、fork 和本地 IPv4 connect。脚本使用
`mktemp` 创建专用夹具，结束后清理，并检查两组注册/退出、进程、网络、三类安全
规则、重复失败和资源联合异常。全部出现且 monitor 状态为 0 时输出
`DEMO_RESULT=PASS`，日志写入 `/tmp/ebpf-agent-monitor-acceptance-demo.log`。

运行命令：

```bash
./experiments/run_acceptance_demo.sh
```

脚本语法、Python 语法和两个工作负载的无监控执行已验证。用户随后完成正式
sudo/eBPF 一键运行：Agent 1 为 cgroup 7886/PID 25750，Agent 2 为 cgroup
7905/PID 25751；两组注册/退出、fork、本地 connect、三类安全规则、重复失败
打开和资源联合异常的 11 项检查全部 PASS，monitor_exit=0，最终
`DEMO_RESULT=PASS`。联合异常 CPU 样本为 97.70%，两组归因未串组。

## 根进程先退出、后代继续运行（2026-09-28）

`root_exit_descendant.py` 的根进程 fork 一个孩子后立即退出；孩子继续运行约
0.8 秒再自然退出。该实验验证监控器不会在根退出时注销 cgroup 映射或终止孩子，
并区分 `agent_root_exit`、`agent_cgroup_drained` 与最终 `agent_exit`。

```bash
sudo ./build/monitor --events process \
  --agent 1 -- /usr/bin/python3 experiments/root_exit_descendant.py
echo $?
```

预期根进程的 PROCESS_EXIT 和 `agent_root_exit` 先出现；随后孩子输出
`state=done` 并产生 PROCESS_EXIT；最后才出现 `agent_cgroup_drained` 以及
`agent_exit ... basis=cgroup_empty`。监控器应返回根进程的退出状态。代码已严格
编译，Python 语法已检查。

用户 sudo 实测通过：Agent 1 为 cgroup 7756、根 PID 7605，孩子 PID 7606。
根进程 exit_code_raw=0 后先输出 `agent_root_exit`；孩子此时继续运行，随后
`state=done`，退出事件中的 PPID 已变为 1，但 agent_id=1、cgroup_id=7756 保持
不变。孩子自然退出后才输出 `agent_cgroup_drained` 和
`agent_exit ... exit_code=0 basis=cgroup_empty`，监控命令状态为 0。该结果验证
根进程退出后不会终止计算后代，也不会提前撤销其 cgroup 归属。

生命周期修改后的完整一键回归也已通过：Agent 1 为 cgroup 8178/PID 10412，
Agent 2 为 cgroup 8197/PID 10413；11 项检查全部 PASS，CPU 联合异常样本为
95.67%，monitor_exit=0，最终 `DEMO_RESULT=PASS`。两组最终退出记录均带
`basis=cgroup_empty`，说明新的 cgroup 排空条件没有破坏原有多 Agent、进程、
文件、网络和 detector 链路。

新增 run_bailian_codex.sh，使用本机 Codex CLI 0.155.1 作为 Agent harness，
通过独立命令行配置将 qwen3.8-max-0902 指向百炼 Responses API。脚本使用
--ignore-user-config 和 --ephemeral，API Key 只从 BAILIAN_API_KEY
环境变量读取，避免修改现有 ChatGPT/Codex Pro 配置或将密钥写入仓库。
BAILIAN_BASE_URL 必须是控制台提供的 HTTPS compatible-mode/v1 API Host。

shell 语法、缺少密钥时的拒绝路径和 git diff --check 已通过。尚未发起模型请求，
因此 provider、模型 ID、免费额度扣减和受控启动下的 Agent 事件仍待用户实测。

- 首次直连出现 qwen3.8-max-0902 缺少本地 metadata 的警告，Codex 会退回通用
  元数据。已新增 bailian-model-catalog.json，并让启动脚本通过
  model_catalog_json 显式加载；字段按百炼官方 qwen3.8-max 示例配置并映射到
  用户实际模型 ID。JSON、shell 语法和 git diff --check 已通过，待用户复跑确认
  warning 消失并取得 BAILIAN_OK。

- 用户首次直连复跑成功：Codex 0.155.1 显示 model=qwen3.8-max-0902、
  provider=bailian、reasoning effort=low，未再出现 metadata fallback；模型只回复
  BAILIAN_OK，tokens used=44,877，退出状态 0。该结果验证百炼 Responses API
  和本地 metadata 配置可用。仓库 AGENTS.md 当前约 55 KB，自动上下文是简单
  请求 token 较高的主要候选；后续真实 Agent 实验应使用独立小工作目录。


- 首次受控启动使用独立 /tmp 工作目录时，进程采集与归属成功：根 PID 99752
  以及 Codex 的线程、lsb_release/getconf 辅助进程均保持 agent_id=1、
  cgroup_id=18468、uid=1000，证明真实多线程 Agent 及其后代可由 cgroup 统一归属。
  Codex 随后因该目录不是受信任 Git 仓库而在请求模型前退出，提示需要
  --skip-git-repo-check；因此本轮没有 CONNECT_RESULT，Agent exit_code=1，整体状态 1。
  启动脚本现已固定加入该选项，待按相同命令复跑网络与模型响应。


- 加入 --skip-git-repo-check 后，真实 Codex Agent 受控复测完整通过：根 PID 101701、
  agent_id=1、cgroup_id=18538、uid=1000；Codex 输出 MONITORED_AGENT_OK，
  tokens used=1,433，Agent exit_code 和整体命令状态均为 0。捕获两条到 443 端口的
  CONNECT_RESULT，目标分别为 198.18.0.53 和 198.18.0.36，ret=-115 表示非阻塞
  connect 的 EINPROGRESS，不代表最终连接失败；模型成功响应证明异步连接随后完成。
  198.18.0.0/15 在当前虚拟机/代理环境中可能是合成或转发地址，不将其宣称为百炼
  服务的真实公网 IP。Codex 的线程及 lsb_release/getconf 辅助进程始终保持相同
  agent_id/cgroup_id，真实 Agent 的进程与网络归属链路已在该受控场景验证。


- 2026-09-22 首次真实 Codex 文件读取实验未完成：使用独立 /tmp 目录及只读
  marker.txt，Codex 模型已响应，但所有 shell 工具调用在执行前因 bubblewrap
  `Failed RTM_NEWADDR: Operation not permitted` 失败，未发生 marker.txt 的
  FILE_OPEN。模型报告无法读取文件，本轮 tokens used=4,550。后续需共同选择
  修复用户命名空间/沙箱环境，或在隔离虚拟机中明确放弃 Codex 内层沙箱再复测；
  仅使用 --cd 不能限制 Agent 对文件系统的访问。


- 2026-09-22 按 OpenAI Docs 的 Ubuntu 24.04 步骤加载 bwrap AppArmor 配置后，
  本地 bwrap 只读测试成功，真实 Codex 文件读取实验也已通过。单监控器受控启动
  Agent 1：root PID 12080、cgroup_id=8028、run_uid/run_gid=1000。Codex 经
  bubblewrap 调用 `cat marker.txt`，PID/TID 12437 的 FILE_OPEN 给出内核解析路径
  `/tmp/ebpf-agent-monitor-qwen-readonly/marker.txt`、flags=32768、path_ret=49、
  agent_id=1、cgroup_id=8028；Codex 原样报告 EBPF_AGENT_READONLY_20260922，
  工具退出码、Agent exit_code 和监控命令状态均为 0。模型用量 1,755 tokens。
  实验后目标文件仍为 444 权限、29 字节且内容未变。日志中大量 bwrap/Codex
  初始化文件事件属于同组环境活动，不能把它们当成业务文件读取。

- 为方便复核上述业务事件，新增可选 `--hide-runtime-noise`。它仅在用户态隐藏
  bwrap、codex-linux-san 和 Codex 临时挂载路径的普通文件事件打印；目标文件
  `cat` 打开事件、其他类别事件及告警照常显示，detector 仍处理完整事件。
  用户 sudo 实测本地 bwrap 只读命令通过：agent_id=1、cgroup_id=8274，
  bwrap 的普通文件事件未展示；cat（PID 16346）的目标文件 FILE_OPEN
  保留，路径为 `/tmp/ebpf-agent-monitor-qwen-readonly/marker.txt`，
  path_ret=49，读到 EBPF_AGENT_READONLY_20260922，Agent exit_code=0。
  exec 过渡期有两条 comm=monitor 的 FILE_OPEN，当前过滤规则未覆盖它们。

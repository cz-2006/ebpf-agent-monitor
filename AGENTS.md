# 项目长期上下文

更新时间：2026-09-28

## 项目与资料

- 项目题目：操作系统大赛第 32 题「基于 eBPF 的系统级多智能体异常监测框架与方法」。
- 项目目录：`/home/felix/projects/ebpf-agent-monitor`。
- `problem.md`：赛题原文，是任务范围、基础/进阶要求和评审指标的依据。
- `ebpf_environment_plan.md`：用户记录的开发环境和初步推进建议，不代表已完成的实现或最终设计。
- 本文件用于后续会话快速恢复项目背景、约束与进度。涉及具体赛题要求或环境细节时，再阅读上述原始文件。

## 外部参考方案

用户提供以下两个已有队伍的同题解决方案仓库，说明其中包含可供参考的代码：

- https://gitlab.eduxiji.net/T2026900029910646/project3136859-387988
- https://gitlab.eduxiji.net/T202690002999777/project3136859-378675

当前仅记录用户提供的链接，尚未阅读或验证仓库代码。后续设计讨论与实现时可按需分析其采集方式、Agent 归属、跨层关联、异常规则和评测方法；引用具体结论时记录对应文件及版本。参考方案不代表本项目已确定的设计或已验证的能力。

## 当前状态

项目仍采用小步设计与验证，但已形成可构建、可运行的 libbpf CO-RE 正式原型：
单监控器可受控启动最多 16 个 Agent，以 cgroup 归属事件，采集进程、真实文件路径、
网络连接和失败 openat；独立用户态 detector 已有三类安全规则、重复失败活动规则，
并结合 cgroup CPU 样本识别一种资源/逻辑联合异常。两个真实 Codex Agent 的
并发进程、网络及各自文件读取已实测；真实 Codex 触发敏感读取、Shell 审计和
工作区外删除告警也已验证。根进程先退出时，监控器会继续跟踪同 cgroup 后代，
直到 cgroup 排空后再输出最终 agent_exit。VirtualBox 中已完成初步性能测量，
未达到 5% 参考指标。生命周期修改后的双 Agent 一键验收已于 2026-09-28 复跑，
11 项检查全部 PASS，monitor_exit=0，DEMO_RESULT=PASS。
现状与缺口按赛题基础要求汇总于 `docs/acceptance-status.md`。

已验证（依据用户提供的输出，详见 experiments/README.md）：

- 实验①：捕获 `/usr/bin/true` 的 execve 入口事件。
- 实验②a：单组单线程父子进程标签继承、执行与退出观测。
- 实验②b：两组根进程生命周期重叠时，孩子归属未串组；不是高并发压力验证。类型比较警告修正后，用户确认已消失。
- 实验③a：单组单线程、短绝对路径 openat 入口/返回配对；文件创建及打开成功、不存在路径返回 -2，与工作负载一致。

- 实验③b：单组单线程、短绝对路径 unlink 配对通过；PID/TID 9848、agent_id=1，同一路径返回 0/-2，与工作负载一致，有完成标记和退出事件。

- 实验③c：双组文件事件归属在受控场景通过；Agent 1 PID 14217、Agent 2 PID 14218，各自 openat/unlink 成功及失败结果正确，未见串组，两个退出事件齐全、工作负载退出码均为 0。用户更正末尾命令退出状态为 0。根进程生命周期重叠，文件操作按组先后发生，不是压力测试。

- 实验④a：单组单线程、本地阻塞 IPv4 TCP connect 实测通过；PID/TID 21232、agent_id=1、fd=4、目标 127.0.0.1:55141 与工作负载一致，ret=0，退出事件齐全，命令退出状态 0。
- 实验④b：双组本地 IPv4 TCP connect 归属在受控场景通过；Agent 1 PID 9332 对应 127.0.0.1:54075，Agent 2 PID 9333 对应 127.0.0.1:51883，两条 connect 均 ret=0，未见串组，退出事件、两组工作负载退出码及监控命令退出状态均为 0。两组目标连接按 Agent 2、Agent 1 先后发生，不是压力测试。
- 实验④c：单组本地阻塞 IPv4 TCP 连接失败观测通过；PID/TID 12114、agent_id=1、fd=3、目标 127.0.0.1:54331，Python errno=111 与探针原始 ret=-111 对应，退出事件齐全，命令退出状态 0。
- 实验⑤a：非预期 Shell 规则原型在受控场景通过；根 PID 14653 创建孩子 14661，孩子继承 agent_id=1 并尝试执行 /bin/sh，输出一条 unexpected_shell 告警，孩子退出码和监控命令退出状态均为 0；根进程执行 /usr/bin/python3 未告警。
- 实验⑤b：模拟敏感文件访问规则原型在受控场景通过；启动器 PID 17990 创建夹具但不属于 Agent，Agent 1 PID/TID 17991 只读打开模拟敏感文件，flags=524288、ret=3，输出一条 high/success 告警，读取 21 字节，孩子和监控命令退出状态均为 0，准备与清理未触发告警。
- 实验⑤c：超工作区删除规则原型在受控场景通过；启动器 PID 21413、Agent 1 PID/TID 21414。workspace/allowed.txt 删除成功且 outside_workspace=0、未告警；outside/victim.txt 删除成功且 outside_workspace=1，输出一条 high/success 告警；孩子和监控命令退出状态均为 0。
- 实验⑥a：重复失败文件打开规则原型在受控场景通过；PID/TID 22858、agent_id=1，同一路径 5 次 openat 均 ret=-2，count 从 1 到 5，第 5 次 elapsed_ns=1250703（约 1.25 ms，小于 2 s），只输出一条 medium 告警，命令退出状态 0。

尚未覆盖 unlinkat、rename、openat2、更多实例压力与事件丢失测试。当前联合异常
只使用重复失败打开与 CPU 高占用，不等同于一般逻辑死循环检测；性能只有
VirtualBox 初测，尚无真实 Linux 机器或 5.15 实机复测。失败 openat 使用明确标注的
还原尝试路径，不宣称为真实规范路径。环境计划中的工具链安装与 feature probe
记录仍按用户原始环境资料理解，不推断为本次重新验证。

不要将建议架构、候选技术和实施顺序当作已定稿设计，也不要把受控脚本实验等同于完整满足赛题基础要求。

## 已确认的交付目标与时间约束

- 用户要求在一个月内完成项目设计和验证，净投入最好控制在 24 小时内；这是时间规划目标，不预设通过加班扩大范围。
- 老师允许半成品；大赛评审指标仅供参考，不把比赛全部指标直接当作本次课程交付的硬性验收条件。
- 最新确认的优先级：先尽量完成 `problem.md` 的基础要求；基础要求完成且仍有余力，再推进进阶要求。
- 基础阶段优先覆盖多 Agent 并发下的进程、文件、网络 IP/端口采集，Agent 归属，安全异常与资源/逻辑异常检测，以及带时间、PID/TID、操作对象和归因依据的告警。
- 基础阶段的总体设计和正式原型已经形成，设计说明见 `docs/design.md`；后续以课程交付整理、复现验证和如实记录限制为先。
- 验证和文档属于基础交付的一部分，应先于进阶开发完成。如有缺项或仅在受控场景验证，明确记录限制，不宣称完整满足基础要求。
- HTTPS 明文、Prompt/Response 精确因果关联及多智能体协作/竞争异常属于后续进阶方向。可视化界面和容器化部署暂非优先事项。
- 性能可做初步测量并如实报告；比赛的性能损耗不大于 5% 指标保留为参考目标，未经测量不得宣称达标。

## 赛题要求与评审参考（区别于本次交付约束）

设计并实现基于 eBPF 的非侵入式系统，同时实时观测和分析同一设备中的多个 AI Agent。无需修改内核源码或重编译目标程序。

基础要求：

- 捕获多智能体并发时的进程管理（如 execve、fork）、文件操作（如 open、unlink）和网络连接 IP、端口等上下文；评审强调真实文件路径。
- 在用户态识别资源使用与逻辑异常，以及非预期 Shell 启动、敏感文件越权访问、超工作区异常删除等安全异常。
- 逻辑死循环与资源浪费应结合高频 API 调用、重复请求、重复或无意义文件活动等多维证据综合判断。
- 输出告警与归因日志，至少包含时间戳、PID/TID、操作对象等关键上下文。
- 运行于 Linux Kernel >= 5.15；数据捕获功能的性能损耗不大于 5%。

进阶方向：

- 获取各 Agent 独立的 Prompt/Response；尝试通过 eBPF uprobes Hook 用户态加密库，非侵入式捕获 HTTPS 明文。
- 识别多智能体协作或竞争异常。
- 建立应用交互与内核事件的跨层关联，实现特定 Prompt 到底层异常操作的因果回溯。

评审权重：功能实现与异常回溯 40%，观测深度与兼容性 30%，系统性能与工程 30%。不能只追求 syscall 采集数量而忽略多智能体区分、异常分析及归因。

## 开发环境

以下为用户在 2026-09-14 记录的信息，实际编译、加载探针或评测前按需核验：

- Windows 宿主机，Ubuntu 24.04.3 Desktop AMD64 VirtualBox 虚拟机。
- 虚拟机内核 `7.0.0-31-generic`，按记录满足赛题最低版本要求。
- 虚拟机资源：6 GB 内存、4 vCPU、60 GB 动态虚拟硬盘，NAT 网络，EFI 关闭。
- SSH：Windows `127.0.0.1:2222` 转发至虚拟机端口 22，用户 `felix`，SSH 别名 `ubuntu-vm`。
- 开发方式：Windows VS Code Remote SSH 连接 Ubuntu；源码、编译、测试与 eBPF 运行均位于虚拟机中。
- 已记录安装：clang/LLVM、libbpf、bpftool、bpftrace、BCC、Linux headers/BTF 相关支持、C/C++ 构建工具、CMake/Ninja、Python venv/pip 等；完整清单见环境计划。
- 用户使用 Codex CLI，记录版本为 `0.154.0`；后续会话应依靠仓库文档恢复上下文，不假设历史对话可用。

观测边界：虚拟机内的 eBPF 只能观测 Ubuntu 虚拟机中的进程与系统调用。被监控 Agent 必须运行在虚拟机中，无法借此直接监控 Windows 宿主机 Agent。

VirtualBox 用于开发、功能验证与原型调试。最终性能评测优先使用真实 Linux 机器、实验室服务器或比赛指定环境，记录基线、工作负载与测量方法；不能用未经验证的虚拟机结果宣称达到 5% 指标。

## 早期技术方向（历史记录，后续正式设计以 `docs/design.md` 为准）

建议主线为 libbpf + CO-RE；bpftrace/BCC 用于快速实验。候选数据流：

```text
eBPF C → clang/LLVM → libbpf + CO-RE → BPF Ring Buffer
→ 用户态 Collector → 关联引擎 → 异常检测 → 告警与归因
```

原则是内核态轻量采集、用户态关联与检测。2026-09-21 用户确认第一阶段正式实现采用 libbpf + CO-RE、全 C 单程序：eBPF 侧轻量采集并通过 Ring Buffer 发送事件，C 用户态负责消费、归属、检测和告警。模块接口、事件格式、存储方式和具体探针仍待共同设计。

第一阶段候选观测范围：

- 进程：execve、fork/clone、exit。
- 文件：openat、unlink/unlinkat、rename。
- 网络：connect、目标 IP 与端口。
- 统一事件候选字段：timestamp、pid、tid、ppid、uid、comm、event_type、target；字段语义与扩展仍需设计。

候选 Agent 归属方式：PID/PPID、进程树与 cgroup 映射到 agent_id。后续可用 Docker、cgroup、namespace 模拟和区分多个 Agent；尚未引入这些组件。

目标关联链路：Prompt/Interaction → Agent → Model Response → 进程树/子进程 → 系统调用 → 文件或网络操作 → 告警。

HTTPS 明文采集是后期研究方向。OpenSSL 的 SSL_read/SSL_write 仅是候选 Hook 点，需先核实目标 Agent 的 TLS 实现，不能假定所有 Agent 都适用。

基础规则候选：非预期 Shell、敏感文件访问、超工作区删除、高频 API/网络调用、重复进程/文件活动。规则阈值、工作区边界、授权语义及多维判定方法尚未定义；网络连接次数不能直接等同于 API 调用次数。

## 实验方向与当时讨论进度（历史记录，2026-09-15）

- 用户初步同意先用可控脚本验证监测流程，再接入真实 Agent；具体真实 Agent 尚未选定。
- 两个脚本是第一轮并发实验的最小规模，不是系统支持数量上限。后续需验证更多实例的归属准确性、事件丢失和开销，支持规模未经测量。
- 测试脚本用于产生已知的进程、文件和网络行为；监控程序负责采集、归属和检测。脚本实验不能替代真实 Agent 验证，也不能证明已识别协作/竞争异常或逻辑死循环。
- 用户已确认的实验顺序：单程序执行观测 → 两组并发与子进程归属 → 文件操作 → 网络连接 → 安全规则 → 重复活动。文件规则实验建议使用专门创建的临时测试文件。
- 用户已确认开始六个实验，按共同设计模式逐步推进。实验①已由用户运行并提供目标 execve 入口事件，最小观测目标通过；未提供完整终端输出或退出状态，不据此断言 execve 成功或程序正常退出。记录见 experiments/README.md。实测内核 7.0.0-31-generic、bpftrace v0.20.2；sudo 需要交互密码。实验②已确认先采用进程树跟踪，从一组父子进程开始。已准备 experiments/fork_exec.py 与 experiments/process_tree.bt，运行与限制见 experiments/README.md；实验②a 已由用户成功加载探针并实测通过：根 PID 29031 创建孩子 29032，孩子执行 true 时继承 agent_id=1，父子退出事件齐全，工作负载报告孩子退出码 0。实验②b 已准备 experiments/two_agents.py 与 experiments/two_agents.bt；用户实测双组归属通过：Agent 1 根 32947 → 孩子 32950，Agent 2 根 32948 → 孩子 32949，四个退出事件齐全、工作负载均成功。根进程生命周期重叠，孩子并非同时运行；不是压力测试。两处符号类型比较警告已用 uint32 显式转换修正，用户已复跑并确认 warning 消失，未提供新版完整输出；归属通过结论依据上一轮完整输出。正式归属方案及后续实验设计仍需共同讨论。

## 当时接续点（历史记录，2026-09-16）

- 实验①至⑤c及⑥a 的既定受控目标已由用户实测通过，详见 experiments/README.md。⑥a 中 PID 22858 对同一路径 5 次 openat 均返回 -2，计数 1→5，第 5 次累计约 1.25 ms，只产生一条 medium 告警，命令退出状态 0。该规则只是重复无意义文件活动的一种证据，不单独证明逻辑死循环或资源浪费。下一步应共同回顾六组实验与正式系统设计范围，不自动把实验脚本视为正式实现。 用户随后确认正式实现路线选择 libbpf + CO-RE、全 C 单程序。第一个里程碑只打通 execve 的内核 tracepoint → Ring Buffer → C 用户态输出；观测点确认使用 sys_enter_execve，事件语义和名称为 EXEC_ATTEMPT，只表示执行尝试，不表示成功，后续可新增 EXEC_SUCCESS。仓库当前未发现正式 C 源码、Makefile/CMake 或 vmlinux.h。用户确认统一事件格式采用“公共事件头 + 各事件专属载荷”，用户态先按 event_type 分派。第一版公共头最初确认为 timestamp_ns（单调时钟）、size、event_type、pid、tid、ppid、uid、agent_id、comm[16]；EXEC_ATTEMPT 载荷为 filename[256]。后续用户正式确认以 cgroup 作为唯一 Agent 归属依据、进程树只负责生命周期和回溯，因此公共头已增加原始归因字段 cgroup_id；agent_id 是 cgroup_id→agent_id map 的业务结果，当前仍为 0。构建方案确认为 Makefile + 标准 libbpf CO-RE skeleton；计划目录为 include/events.h、src/monitor.bpf.c、src/monitor.c，build/ 存放生成的 vmlinux.h、BPF 对象、skeleton 和可执行文件，生成文件不手工修改。具体运行过滤方式仍待共同确认。 已按确认方案创建第一版正式骨架：include/events.h、src/monitor.bpf.c、src/monitor.c、Makefile、README.md 和 .gitignore；make 构建成功，生成 build/vmlinux.h、monitor.bpf.o、monitor.skel.h、monitor。BPF 对象为 eBPF ELF，用户程序为 x86-64 ELF 并正确链接 libbpf。用户已 sudo 实测正式原型通过：捕获 `/usr/bin/true` 的 EXEC_ATTEMPT（timestamp_ns=5354623581568，PID/TID 29389，PPID 29373，UID 1000，agent_id=0，comm=bash），Ring Buffer 与用户态解析正常，Ctrl-C 后命令退出状态 0；系统范围输出包含大量 VS Code 后台事件，符合当前无过滤设计。构建时将共享结构名由通用 event_header 改为 monitor_event_header 以避开本机 vmlinux.h 同名结构，字段设计不变；对生成的 vmlinux.h 关闭 Clang 18 的 missing-declarations 警告。 用户确认 cgroup 主归属方案后，已在共享头、BPF 生产端和用户态输出加入 cgroup_id，并重新 make 成功。用户 sudo 实测字段通过：`/usr/bin/true` 事件 timestamp_ns=7103999361810、cgroup_id=9201、PID/TID 32795、PPID 32768、UID 1000、agent_id=0、comm=bash；未出现尺寸错误。所示 VS Code 与终端事件均为 cgroup_id=9201，说明当前尚未分组；用户未提供本轮退出状态，不推断。
- 用户此前不了解 eBPF，需经常指导和解释；继续按“解释概念 → 运行小步骤 → 解读输出”推进，不假设已掌握。
- 最近已解释：按 TID 保存 openat 入口上下文，避免同一进程的不同线程覆盖记录；当前单线程测试的 PID=TID，不代表赛题是单进程，也不证明完整多线程支持。
- 用户询问 `@started` 是否无用，已解释其双重作用：保存入口时间并输出 enter_ns；作为返回探针过滤条件，非零表示有已记录的待配对调用。当前未用耗时做异常检测。可以改用 pending 标记是解释性替代方案，用户未要求修改，代码保持原状。
- 实验③a 已核对 PID 53403、agent_id=1，sample.txt 创建/只读打开返回 3，missing.txt 返回 -2；目录打开是清理过程中的打开行为，不能据此声称捕获了删除。flags、文件描述符重用与异步输出交错的说明见 experiments/README.md。
- 所有 sudo 命令（包括 sudo -n）均交用户运行，助手不得尝试。工具沙箱此前持续报 bwrap loopback 权限错误，文件操作通过工具授权在沙箱外完成；此问题不代表 eBPF 不可用。
- VS Code bpftrace 高亮扩展仅介绍过，未确认安装；无需为接续实验再次要求安装。

## 当前后续推进建议（2026-09-28）

1. 完成课程交付材料：统一 README、设计说明、验收状态与演示步骤，确保新环境可复现。
2. 做一次干净构建与无特权静态检查；需要 sudo 的 eBPF 验收仍由用户运行并回传结果。
3. 整理演示讲解与已知限制，明确受控脚本证据、真实 Agent 证据和性能数据的边界。
4. 如仍有时间，再选择补充 openat2/unlinkat/rename、压力与事件丢失测试，或真实 Linux/5.15 性能复测。
5. 基础交付稳定后，再研究 HTTPS 明文、Prompt/Response 关联及多智能体协作/竞争异常。

## 后续协作与记录约定

- 默认使用中文沟通，保留代码标识符与工具的原名。
- 所有需要 sudo 的命令均交给用户在交互终端运行；助手不得自行执行或尝试，包括 sudo -n 权限检查。提供完整命令、用途及需要回传的输出，收到用户结果后再核对。
- 将 `AGENTS.md` 作为简洁的项目指令与长期上下文维护。官方未规定固定更新频率；本项目采用重要变化及时记录的协作约定，不依赖关闭 CLI 前整理，也不要求用户在退出前提醒。
- 在相关任务中主动记录新增的重要项目资料、已确认决策、约束、完成进度、关键阻塞和下一步；普通知识问答、重复确认和无新结论的讨论无需更新。未定方案标注为待确认，及时替换过时内容，避免堆积聊天记录。
- 记录重要结论是已授权的日常维护，应在产生重要结论的任务中主动完成，无需用户提醒或另行确认；共同设计中的方案确认不应成为延后记录已确认结论的理由。更新后简要告知实际写入的内容。
- 随文档增长，将详细设计、实验过程和历史记录放入独立文档，在本文件保留摘要与入口。
- 开始任务时先依据本文件恢复背景，再阅读相关源码或原始文档；不要假设已有未记录的实现和决策。
- 区分赛题要求、用户环境记录、设计建议、实测结果。信息冲突时以赛题原文判断赛题要求，以实际检查结果更新环境状态。
- 已建立 Makefile 构建流程；仍不得编造未实际执行的命令或通过结果。新增实现时记录可复现的构建、运行和验证方法。
- 完成重要阶段、确定技术方案或发现环境变化后，更新本文件的状态、决策、验证结果和下一步，保持简洁；详细实验过程放入单独文档。
- 保留 `problem.md` 作为赛题依据，不将实现假设混入赛题原文。

## 协作与学习规则

- 默认采用共同设计模式。对架构、模块划分、数据流、接口设计、技术选型、异常检测策略等非平凡决策，不要自行决定并直接实现。
- 当遇到需要设计的问题时，先向我解释“现在需要决定什么、为什么需要决定”，然后给出 2～3 个合理方案，说明各自优缺点、复杂度和适用场景。优先通过提问引导我思考，由我做最终决定。
- 不要为了“把任务做完”而一次性搭建大量目录、抽象层、框架或子系统。采用小步迭代，每次只实现已经讨论并确认的部分。
- 将可维护性与可扩展性作为重要设计约束：基础阶段就应考虑向进阶要求平滑升级，在模块边界、事件格式和关联接口上保留合理扩展空间，使后续加入 HTTPS 明文采集、Prompt/Response 关联及多智能体协作/竞争检测时，能够复用已有采集、归属、检测与告警能力，避免因新增要求而整体推翻重写。重要设计讨论中应说明后续如何扩展及可能需要调整的部分；具体方案仍需共同确认，不以预留扩展为由提前实现进阶功能或引入过度抽象。
- 在写重要代码之前，先简要说明它在系统中的作用、输入输出、与其他模块的关系以及为什么这样实现。简单机械代码和明显的 bug 修复无需反复确认。
- 如果发现我的设计存在问题，不要直接偷偷换成你认为更好的设计。指出问题、解释原因、提出替代方案，然后让我决定。
- 学习优先于代写。对 eBPF、操作系统、进程关系、ring buffer、libbpf/CO-RE、tracepoint/kprobe/uprobe、跨层关联等核心知识，尽量让我理解设计原因，而不仅仅给最终代码。
- 你可以主动承担样板代码、Makefile/CMake、重复性代码、API 查询、编译错误修复、测试代码和其他机械工程工作。
- 允许显式切换为代办模式。如果我明确说“直接帮我实现”“这一部分你来设计”“不用教学，先做出来”“全权处理”或表达类似意思，则可以在该任务范围内自行完成设计和实现，不必继续逐项征求我的决定；完成后仍需简要说明关键设计和改动。
- 代办模式只对我明确指定的当前任务生效。任务结束后，自动恢复默认的共同设计模式。
- 如果无法判断某个决定是否属于需要我参与的重要设计，宁可先问我，不要擅自扩大项目范围。

## 受控启动原型（2026-09-21）

- 用户确认第一版采用单 Agent 受控启动接口：`sudo ./build/monitor --agent 1 -- COMMAND [ARG...]`。
- 用户态创建 cgroup v2 子组、取得 cgroup_id、写入 BPF 的
  `cgroup_id → agent_id` map；eBPF 只向 Ring Buffer 提交已登记 cgroup 的
  `EXEC_ATTEMPT`，因此过滤系统中无关 exec 事件。
- fork 后子进程先阻塞在 pipe；父进程将其写入 `cgroup.procs` 并核验归属，
  再输出 register 记录并放行 exec。这保证第一条 exec 业务事件发生前映射已就绪。
- 代码已用 `make` 在 `-Wall -Wextra -Werror` 下构建成功；无参数调用会输出新用法并返回 2。
  用户已 sudo 实测通过：register、EXEC_ATTEMPT、exit 均为 agent_id=1、
  cgroup_id=11216、root PID=39526，业务事件在注册之后，Agent exit_code=0，
  整体命令退出状态 0。该结果验证了单 Agent 受控场景中的门控、cgroup 迁移、
  映射及过滤链路。
- 实测 EXEC_ATTEMPT 的 comm=monitor 符合 execve 入口语义，filename=/usr/bin/true
  才是目标。uid=0 表明当前 sudo 监控器派生的 Agent 也以 root 运行；接入真实 Agent 前
  需共同设计目标 UID/GID 的保留或降权流程，当前不能把 root 身份当作最终运行方案。
- 当时边界：一次只启动一个根 Agent，尚无正式 fork/exit 和后代排空处理；这些能力
  已在后续里程碑实现。本段保留用于说明演进过程。

- 2026-09-21 用户选择受控启动降权方案 1：自动继承 sudo 调用者身份。监控器现在
  在加载前核验非 root 的 SUDO_UID/SUDO_GID/SUDO_USER 与 passwd 数据库；
  子进程完成 cgroup 迁移并被放行后，按 initgroups → setresgid → setresuid
  顺序彻底放弃 root，再更新 HOME/USER/LOGNAME 并 exec。缺少有效 sudo 身份时拒绝启动。
  register 输出新增 run_uid/run_gid。代码已严格编译并由用户 sudo 实测通过：
  register 的 run_uid/run_gid 均为 1000，EXEC_ATTEMPT 的 uid=1000，
  agent_id=1、cgroup_id=11286、PID=41507 在注册、业务事件和退出记录中一致，
  Agent exit_code=0，整体命令退出状态 0。这验证了普通用户身份在第一条业务
  exec 事件前已生效。

## 正式进程生命周期采集（2026-09-21）

- 用户确认正式原型第二个里程碑使用 `sched_process_fork` 与
  `sched_process_exit`。公共头 pid/tid 始终表示产生事件的当前任务。
- `PROCESS_FORK` 载荷为 parent_pid、child_pid、child_comm；本机 BTF 将
  comm 表示为 `__data_loc_child_comm`，BPF 程序按低 16 位偏移读取动态字符串。
  `PROCESS_EXIT` 载荷为 task_struct.exit_code 的 exit_code_raw，用户态暂不擅自
  解释为正常退出码或信号。
- 两个探针均先用当前 cgroup_id 查询 agent_by_cgroup，未登记 cgroup 不输出。
  用户态已按 event_type 和 size 分派三种事件。make 在严格警告设置下通过。
  用户已 sudo 实测正式生命周期链路通过：根 PID 46706 的 Python exec 后创建
  孩子 PID 46707，PROCESS_FORK 的父子 PID 与工作负载一致；孩子继承
  agent_id=1、cgroup_id=11488 并 exec /usr/bin/true；孩子和根进程 exit_code_raw
  均为 0，Agent exit_code 及整体命令退出状态均为 0。事件顺序完整，无串组迹象。
- 验证命令为
  `sudo ./build/monitor --agent 1 -- /usr/bin/python3 experiments/fork_exec.py`；
  预期同组出现根 exec、fork、孩子 exec、孩子 exit、根 exit。

## 真实文件路径方向（2026-09-21）

- 用户决定跳过 syscall 调用路径过渡版，直接推进内核真实路径方案，并选择启用
  BPF LSM。实机核对：内核配置 `CONFIG_BPF_LSM=y`，
  `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`；当前
  `/sys/kernel/security/lsm` 没有 bpf，GRUB 参数为 `quiet splash`，
  `/proc/cmdline` 无 lsm 参数。
- 用户已完成 GRUB 修改和重启。实测 `/proc/cmdline` 包含
  `lsm=landlock,lockdown,yama,integrity,apparmor,bpf`，
  `/sys/kernel/security/lsm` 输出
  `lockdown,capability,landlock,yama,apparmor,bpf,ima,evm`，
  BPF LSM 已实际启用，可以开始实现并加载验证真实路径探针。

## BPF LSM 文件事件实现（2026-09-21）

- 已按用户确认的纯 LSM 方案增加 FILE_OPEN 与 FILE_UNLINK_ATTEMPT。
  FILE_OPEN 使用 file->f_path 调用 bpf_d_path，载荷为 path、f_flags、path_ret；
  FILE_UNLINK_ATTEMPT 对 path_unlink 提供的可信父目录 path 调用 bpf_d_path，
  并读取目标 dentry 名称，由用户态组合完整路径；载荷为 dir_path、name、
  path_ret、name_ret。
- 两个程序只处理 agent_by_cgroup 已登记的 cgroup，并原样返回已有 LSM ret，
  不实施访问控制。unlink 事件明确是删除前尝试，不能单独证明删除成功。
  不存在路径通常不会到达 file_open/path_unlink，因此纯 LSM 版本不会产生失败事件。
- 共享协议与用户态分派已扩展，make 严格编译通过；尚未 sudo 加载验证。
  验证使用 experiments/file_activity.py，重点核对 sample.txt 的工作负载绝对路径、
  LSM path、path_ret、agent_id 和 cgroup_id。
- 首次 sudo 加载时 handle_path_unlink 被 verifier 以 -13 拒绝：栈上合成的
  struct path 不是 bpf_d_path 要求的 trusted pointer。未产生运行事件。
  已改为直接对 LSM 提供的可信父目录 path 调用 bpf_d_path，并从可信 dentry
  读取名称；用户态将 dir_path/name 拼为完整目标路径。共享载荷新增 name_ret。
  修复后 make 严格编译通过，待重新 sudo 加载验证。

- 修复后用户 sudo 实测 BPF LSM 文件路径通过：PID 6315、agent_id=1、
  cgroup_id=6788；sample.txt 两次 FILE_OPEN 的完整绝对路径与工作负载一致，
  path_ret=35；FILE_UNLINK_ATTEMPT 完整路径一致，父目录 path_ret=24、
  name_ret=11。缺失 open/unlink 没有 LSM 事件，符合纯 LSM 语义。
  PROCESS_EXIT、Agent exit_code 和整体命令退出状态均为 0。
- 实测同时发现启动边界噪声：子进程被迁入已登记 cgroup 后才执行 initgroups，
  因而 /proc/sys/kernel/ngroups_max、/etc/group 及 NSS 库等降权准备访问以
  uid=0、comm=monitor 被归入 Agent。业务路径本身正确；需要共同决定是否采用
  两阶段门控，在迁移/登记前完成 initgroups，再迁移并执行 setresgid/setresuid/exec。
- 用户选择两阶段门控消除降权准备噪声。实现已改为两条 pipe：子进程先在原
  cgroup 中执行 initgroups，成功后向父进程发送 ready；父进程收到 ready 后才
  迁移并核验 Agent cgroup、输出 register 并放行；子进程随后执行
  setresgid/setresuid、更新环境并 exec。initgroups 失败会通知父进程并以 126
  退出。make 严格编译通过，待复跑文件工作负载，重点确认不再出现
  uid=0/comm=monitor 的 FILE_OPEN。

- 两阶段门控已由用户复测通过：PID 7465、agent_id=1、cgroup_id=6902，
  全部采集事件均为 uid=1000，不再出现 uid=0/comm=monitor 的 initgroups 文件访问。
  exec 入口及动态加载器早期事件仍可能 comm=monitor，但 uid 已降为 1000，这是
  exec 映像替换时序，不是 root 准备噪声。sample.txt 的两次 FILE_OPEN 与一次
  FILE_UNLINK_ATTEMPT 路径保持正确，path_ret/name_ret 为正，PROCESS_EXIT、
  Agent exit_code 和整体命令退出状态均为 0。两阶段门控问题已解决。

## 正式网络连接采集（2026-09-21）

- 用户确认使用 connect syscall 入口/返回配对方案。已新增 CONNECT_RESULT，
  载荷为 socket_fd、ret、family、destination_port（主机字节序）和
  destination_address[16]；支持 AF_INET/AF_INET6。
- BPF 入口仅处理已登记 cgroup，按完整 pid_tgid 将参数和 agent_id/cgroup_id
  保存到 pending_connects hash；返回点复制后立即删除暂存项，再写 Ring Buffer。
  用户态使用 inet_ntop 输出 dst_ip。make 严格编译通过，尚未 sudo 验证。
- 第一项验证使用 experiments/network_connect.py。用户已 sudo 实测 IPv4
  成功连接通过：PID 6325、socket fd 4、目标 127.0.0.1:56929 与工作负载一致，
  ret=0，agent_id=1、cgroup_id=9530，PROCESS_EXIT 与 Agent exit_code 均为 0。
  本轮未提供单独 echo $? 输出，不推断整体监控命令状态。下一步验证失败连接，
  之后再验证 IPv6。
- 用户已 sudo 实测 IPv4 失败连接通过：PID 6627、socket fd 3、目标
  127.0.0.1:37581 与工作负载一致，Python errno=111 对应内核 ret=-111；
  agent_id=1、cgroup_id=9600，PROCESS_EXIT、Agent exit_code 和整体命令状态均为 0。
- 已新增 experiments/network_connect_ipv6.py，用 IPv6 回环 ::1 和动态端口验证
  family=10、16 字节地址格式化与 ret=0；不访问外部网络。脚本先无 sudo
  单独运行通过；随后用户 sudo 正式监控实测通过：PID 7481、socket fd 4、
  family=10、目标 ::1:50777 与工作负载一致，ret=0，agent_id=1、
  cgroup_id=9714，PROCESS_EXIT、Agent exit_code 和整体命令状态均为 0。
  正式网络采集目前已验证 IPv4 成功、IPv4 ECONNREFUSED 和 IPv6 成功。

## 正式多 Agent 控制面（2026-09-21）

- 用户选择单监控器共享一套 BPF/Ring Buffer，同时管理多 Agent 的方案。
  CLI 确认为
  `--agent ID -- COMMAND [ARG...] --next --agent ID -- COMMAND [ARG...]`；
  保留原单 Agent 格式，`--next` 是命令参数中的保留分隔符。
- 用户态已重构为最多 16 项的 agent_process 表。Agent ID 必须唯一；每项有独立
  cgroup、cgroup_id 映射、双 pipe 身份准备/放行门控、PID、退出状态和清理状态。
  所有 Agent 完成 initgroups、迁移和登记后才统一放行，共享事件消费循环等待全部
  根进程退出；全部成功返回 0，否则按输入顺序返回第一个非零状态。Ctrl-C 向所有
  未退出根进程发送 SIGTERM。
- make 严格编译通过；无 root 参数解析确认两个不同 ID 能进入权限检查，重复 ID
  会在加载前拒绝并返回 2。用户已 sudo 实测两个 `sleep 1` 的最小并发场景：
  Agent 1 为 cgroup 9916/PID 11850，Agent 2 为 cgroup 9935/PID 11851；两组
  EXEC_ATTEMPT、动态加载 FILE_OPEN、PROCESS_EXIT 交错但归属稳定，无串组。
  两个退出时间戳只相差 29 ns，生命周期重叠；两组 exit_code 和整体命令状态均为 0。
  这是两组受控短任务验证，不是更多实例或压力测试。
- 当时仍只直接等待根 PID；根进程退出后的 cgroup 排空等待已于 2026-09-28 实现并
  实测。最多 16 个根 Agent 是控制面上限，仍不能视为压力或事件丢失测试结论。
- 用户已 sudo 实测双 Agent 混合行为通过：Agent 1 为 cgroup 10005/PID 12320，
  sample.txt 的 FILE_OPEN/FILE_UNLINK_ATTEMPT 均保持 Agent 1 归属；Agent 2 为
  cgroup 10024/PID 12321，CONNECT_RESULT 目标 127.0.0.1:52379、fd 4、ret=0
  且只属于 Agent 2。两组 Python 启动事件高度交错，Agent 2 先退出后 Agent 1
  继续运行，归属仍稳定；两组 exit_code 和整体命令状态均为 0。该结果验证两种
  事件类型的双组受控并发，不是压力测试或真实 Agent 验证。


## 正式用户态异常检测模块（2026-09-21）

- 用户确认采集与检测分离，新增 `include/detector.h` 和 `src/detector.c`。
  Ring Buffer 回调继续校验并输出原始事件，随后把已解析事件交给 detector；
  detector 按 agent_id 保存和查询各 Agent 策略。当前只是小型固定规则模块，
  未引入通用配置文件或规则引擎。
- 第一条正式规则为 `unexpected_shell`。CLI 采用每 Agent 策略格式
  `--agent ID [--deny-shell] -- COMMAND`，因此同一监控器中的 Agent 可分别启用。
  检测器对 EXEC_ATTEMPT 的可执行文件 basename 精确匹配 sh、bash、dash、zsh、
  ksh、fish，命中时输出 high 告警以及 timestamp、PID/TID、agent_id、cgroup_id、
  target、policy 和 `exec_attempt,cgroup_attribution` 证据。该规则只表示执行
  尝试，不宣称 exec 成功。
- make 在 `-Wall -Wextra -Werror` 下通过；参数解析确认单个
  `--deny-shell` 可进入权限检查，重复参数会返回用法错误。本地构造事件确认
  Agent 1 启用策略时 `/bin/sh` 产生一条告警，Agent 2 未启用策略及
  `/usr/bin/ssh` 均不告警。
- 用户已 sudo 完成正式双 Agent 端到端验证：Agent 1 为 cgroup 10402、根 PID
  15588，启用 deny-shell；孩子 PID/TID 15590 的 EXEC_ATTEMPT target=/bin/sh
  产生唯一一条 unexpected_shell 告警，二者 timestamp=3189507899723、
  agent_id=1、cgroup_id=10402 完全对应。未启用策略的 Agent 2 为 cgroup
  10421/PID 15589，执行 /usr/bin/true 时无规则告警。两组 exit_code 与监控器
  整体状态均为 0。该结果验证规则的按 Agent 隔离和正例，尚不是 Shell 名单全覆盖、
  exec 结果确认或高并发压力验证。


## 正式敏感目录读取规则（2026-09-21）

- 用户确认敏感路径采用目录范围策略，并统一规范化为带结尾 `/` 的绝对路径
  前缀；命令行格式为每 Agent 一个 `--sensitive-path DIR`。匹配目录自身及
  子路径，同时通过边界判断避免把相似前缀目录误认为范围内路径。相对路径、
  重复参数和超长路径会拒绝启动。
- detector 已新增 `sensitive_file_access`：仅 FILE_OPEN 的访问模式为
  O_RDONLY/O_RDWR 等可读方式时匹配，O_WRONLY 和 O_DIRECTORY 不告警；输出
  high、target、flags、agent_id/cgroup_id、policy=sensitive_read_denied 和
  `file_open,path_policy,cgroup_attribution`。它证明打开事件到达 LSM 钩子，
  不单独证明应用实际 read 或最终读取成功。
- 新增 `experiments/formal_sensitive_file_access.py`，只在专用
  `/tmp/ebpf-agent-monitor-sensitive/secret.txt` 创建、只读读取并清理无害
  夹具。本地工作负载退出 0；make 严格编译通过；构造事件验证目录本身/子文件
  命中、相似前缀不命中、只写/目录打开不命中、未配置 Agent 不命中。
- 用户已 sudo 完成正式端到端验证：Agent 1 为 cgroup 10535、PID/TID 18939；
  创建夹具的 FILE_OPEN flags=33345 无告警，只读 FILE_OPEN flags=32768 与唯一
  一条 sensitive_file_access 告警共享 timestamp=4120192636297，且 PID/TID、
  agent_id=1、cgroup_id=10535 和完整目标路径完全对应。清理 unlink 未触发该
  规则，Agent 和整体命令状态均为 0。该结果验证正例与同一工作负载中的只写
  反例，规则仍不证明应用实际 read 的结果。


## 正式工作区外删除尝试规则（2026-09-21）

- 用户选择基于现有 FILE_UNLINK_ATTEMPT 检测工作区外删除尝试，不新增 syscall
  返回值关联，也不实施访问阻止。每 Agent CLI 为 `--workspace DIR`，目录按
  绝对路径及结尾斜杠规范化。
- detector 将 LSM 事件中的可信父目录路径和 dentry 名称还原为目标路径；工作区
  内不告警，工作区外输出 high、rule=outside_workspace_delete、target、
  agent_id/cgroup_id、policy=workspace_delete_only 和
  `unlink_attempt,path_policy,cgroup_attribution`。路径或名称解析失败时不
  猜测。该事件只证明删除尝试，不证明最终删除成功。
- make 严格编译通过；构造事件验证工作区内部不命中、外部和相似前缀目录命中、
  解析失败及未配置 Agent 不命中。新增不 fork 的
  `experiments/formal_outside_workspace_delete.py` 作为正式验证负载，避免旧
  bpftrace 实验中的 launcher/Agent 根进程术语与正式受控启动语义混淆。该负载
  已单独运行、清理并退出 0。
- 用户已 sudo 完成正式端到端验证：Agent 1 为 cgroup 10649、PID/TID 22584；
  工作区内 allowed.txt 的 FILE_UNLINK_ATTEMPT 无告警，工作区外 victim.txt 的
  FILE_UNLINK_ATTEMPT 与唯一一条 outside_workspace_delete 告警共享
  timestamp=4576044265090，且 PID/TID、agent_id=1、cgroup_id=10649 和完整路径
  完全对应。工作负载确认两次删除完成，Agent 与整体命令状态均为 0；规则本身
  仍只证明 LSM 钩子处的删除尝试。


## 正式重复失败打开规则（2026-09-21）

- 用户确认新增失败 openat 采集，并明确失败目标不存在时不能称为真实路径。
  eBPF 使用 sys_enter_openat/sys_exit_openat 按完整 pid_tgid 配对，入口保存
  原始用户路径、dirfd、agent_id/cgroup_id，返回点先删除暂存项，只为负返回值
  输出 FILE_OPEN_RESULT。成功打开继续使用 BPF LSM FILE_OPEN 的真实路径。
  第一版未覆盖 openat2。
- 用户确认每 Agent 用
  `--failed-open-threshold N --failed-open-window-ms MS` 成对启用规则；缺一、
  重复、为零或超出 u32 会在加载前拒绝。计数键为
  `agent_id + reconstructed_path`，不是 Agent 汇总或 PID 级；detector 使用
  128 项有界状态表，满时复用最久未活动项。
- 路径还原支持绝对路径、AT_FDCWD 对应的 /proc/PID/cwd、普通 dirfd 对应的
  /proc/PID/fd/DIRFD，并词法消解点号分量。日志标记
  path_basis=reconstructed_attempt 及 reconstruction 来源，不宣称真实路径。
  /proc 读取存在 cwd/fd 变化或进程退出的时序竞争；失败时原始事件仍输出但不计数。
- detector 只累计 -ENOENT；每次输出 activity_evidence，首次达到阈值输出一条
  medium repeated_failed_open 告警，同一窗口不重复告警。make 严格构建通过；
  本地构造事件验证 absolute/proc_cwd/proc_dirfd 三种来源均能规范化、按同目标
  累计并在阈值 2 告警；单独一个阈值参数会返回用法错误。现有
  experiments/repeated_failed_open.py 使用绝对缺失路径，可用于首次正式验证。
- 用户已 sudo 完成正式端到端验证：Agent 1 为 cgroup 11027、PID/TID 29930；
  /tmp/ebpf-exp6-repeat/missing.txt 五次 FILE_OPEN_RESULT 均为 dirfd=-100、
  ret=-2，count 1→5，第 5 次 elapsed_ns=304268 时产生唯一一条 medium 告警，
  path_basis=reconstructed_attempt、reconstruction=absolute。Python 启动阶段
  的多个缺失配置文件各自 count=1，未与目标路径合并。Agent 和整体命令状态均
  为 0。用户粘贴的告警中 absolute/evidence 视觉上相连；复查源码与 build/monitor
  字符串均存在分隔空格，不作为代码缺陷记录。


## 2026-09-21 阶段收口与下一接续点

- 本阶段正式原型已覆盖：最多 16 个受控 Agent、cgroup 唯一归属、普通用户降权、
  exec/fork/exit、BPF LSM 真实文件打开与删除尝试、IPv4/IPv6 connect 结果、
  失败 openat 尝试，以及独立 detector 中的 unexpected_shell、
  sensitive_file_access、outside_workspace_delete、repeated_failed_open。
  上述主链路均已有用户 sudo 实测记录；受控脚本结果不等同真实 Agent 或压力验证。
- 阶段提交前重新运行 make、全部 experiments Python 语法检查和 git diff --check，
  均通过。下一步已由用户确定：加入 cgroup CPU 使用增量，并与重复活动证据联合，
  形成资源/逻辑异常判断；开始前仍按共同设计模式确认采样周期、阈值及告警语义。

## cgroup CPU 采样与资源/逻辑联合异常（2026-09-21）

- 用户确认 CPU 数据源采用用户态周期读取每个 Agent cgroup 的 cpu.stat；
  使用单核等价值，100% 表示占满一个 CPU 核，允许多线程任务超过 100%。
- 用户确认保留独立 repeated_failed_open 告警，并额外输出 CPU 高占用与重复失败
  活动的联合异常；模块采用独立 resource_sampler.c/.h，detector 只接收区间样本
  并做关联。
- 已实现每 Agent 成对参数 --cpu-sample-ms 与 --cpu-threshold-percent。采样器在
  Agent 放行前建立 usage_usec 基线，运行中周期采样，根进程退出时强制采最后一次；
  采样失败输出 resource_sample_error，不伪造零值。
- detector 在同一 Agent、repeated_failed_open 时间窗内达到活动阈值且 CPU 达到
  阈值时，只输出一次 high、rule=resource_logic_anomaly，保留原 medium 告警。
  新增 experiments/resource_logic_anomaly.py：5 次 ENOENT 后持续约 1 秒 CPU 计算。
- make 严格构建、全部 Python 语法检查、工作负载单独运行和 git diff --check
  均通过；后续用户 sudo 端到端验证也已通过，具体数据见下一条。

- CPU 联合异常已由用户 sudo 实测通过：Agent 1 为 cgroup 12072、PID/TID 41002；
  专用路径 5 次 ENOENT 在 447759 ns 内达到阈值并保留一条 medium 告警，首个 CPU
  样本为 99.38% 并产生唯一一条 high resource_logic_anomaly。后续多个高 CPU
  样本未重复联合告警，工作负载完成且 PROCESS_EXIT exit_code_raw=0；补充输出确认
  agent_exit exit_code=0、监控器整体状态 0。本次正式端到端验证完整通过。退出前的
  强制采样形成 328 us、0% 短区间，不影响告警结论，后续可考虑日志降噪。

## 多 Agent 联合异常隔离验证（2026-09-21，已实测通过）

- 用户选择下一步验证多 Agent 联合异常隔离。已设计三组并发对照：Agent 1 只在
  启动 CPU 区间结束后产生 5 次同目标 ENOENT 并保持空闲；Agent 2 只持续占用
  CPU；Agent 3 使用已有联合正例，同时产生重复失败和高 CPU。
- 三组配置相同的 5 次/2 秒、200 ms CPU 采样和 50% 阈值。预期 Agent 1 只有
  repeated_failed_open，Agent 2 只有高 CPU 样本，只有 Agent 3 产生唯一一条
  resource_logic_anomaly。该设计用于检查不同 Agent 的两半证据不会串联。
- 新增 experiments/repeated_failed_open_idle.py 和 cpu_busy_only.py。make、
  全部 Python 语法检查、两个新工作负载单独运行及 git diff --check 均通过；
  三 Agent 正式链路仍待用户 sudo 验证。


- 三 Agent sudo 端到端验证通过：Agent 1（cgroup 12142/PID 42942）只有
  repeated_failed_open，后续 CPU 最高 7.04%；Agent 2（cgroup 12161/PID 42943）
  只有 86.17%/99.75% 高 CPU；二者均无联合告警。Agent 3（cgroup 12180/PID
  42944）在 5 次失败后以 96.53% CPU 产生唯一一条 resource_logic_anomaly，
  后续高 CPU 未重复告警。三组及监控器整体退出状态均为 0。本次受控并发场景
  验证 agent_id+cgroup_id 双条件隔离有效，尚不是更大规模压力测试。

## 初步固定工作负载性能对比（2026-09-21，已完成首轮）

- 用户选择先做固定工作负载的前后对比。新增 performance_workload.py，业务计时
  覆盖固定 CPU 计算、10000 次 /dev/null 打开、500 次本地 TCP 连接和 100 个
  true 子进程，并报告总耗时及分阶段耗时。
- 新增 run_performance_benchmark.sh：先预热，再交替执行 5 对无监控/有监控运行；
  监控输出重定向至 /dev/null，排除终端渲染，但 Ring Buffer 消费和事件格式化仍
  计入。performance_report.py 使用两组中位数计算开销百分比。
- make、Python 语法检查、shell 语法检查、报告器合成数据测试和工作负载单独运行
  均通过。一次无监控烟雾测试总耗时约 831 ms，不作为性能结论。正式配对结果待
  用户运行；VirtualBox 数据只作开发期初测，不能直接宣称达到赛题 5% 指标。


- 用户完成 5 对性能测试：总耗时中位数 631.674→1333.965 ms，开销 111.18%；
  CPU 9.21%、文件 1900.00%、网络 804.12%、进程 62.19%。完整原始日志模式明显
  未达到 5% 参考指标。重定向 /dev/null 仍保留事件格式化和 printf，因此当前结果
  混合了内核采集、Ring Buffer、用户态分派与逐事件文本输出成本；下一步应先增加
  静默原始事件基准模式，用相同负载拆分采集与日志成本，不能据此直接断定 eBPF
  探针本身具有同等开销。

## 静默原始事件性能模式（2026-09-21，已复测）

- 用户选择先拆分采集与日志成本。新增全局 --quiet-events，必须放在第一个
  --agent 前；eBPF、Ring Buffer、事件尺寸校验和 detector 调用保持不变，只跳过
  普通 EXEC/FORK/EXIT/FILE/CONNECT 事件的格式化与打印。register、agent_exit、
  资源样本和告警仍输出，默认模式行为不变。
- 性能驱动脚本已在监控组启用静默模式。make 严格构建、Python/shell 语法检查和
  git diff --check 通过；相同 5 对工作负载的静默复测待用户运行。


- 用户完成静默模式 5 对复测：总开销 136.09%，CPU 6.40%、文件 3098.88%、
  网络 785.74%、进程 66.62%，没有比完整日志模式改善。此前“文本格式化是主要
  瓶颈”的推断被实测否定。主要候选转为 file_open 的 bpf_d_path、全量事件构造/
  Ring Buffer 提交，以及子进程触发多类事件放大。该高事件密度微基准证明当前
  全量采集未达到 5%，但不能外推真实 Agent 平均开销；下一步需按事件类别隔离
  测量，再决定内核过滤、采样或按需启用策略。

## 按事件类别隔离性能（2026-09-21，已实测）

- 用户选择增加事件类别开关定位探针成本。新增全局 --events LIST，支持逗号分隔的
  process、file、network，默认全开；必须位于第一个 --agent 前。用户态在 BPF
  load 前对未选择类别的程序设置 autoload=false，因此不会附着对应 hook。
- process 包含 exec/fork/exit，file 包含 LSM open/unlink 和失败 openat 配对，
  network 包含 connect 入口/返回配对。关闭类别会同时移除依赖其证据的规则能力。
- 性能驱动扩展为 process、file、network、all 四组，每组 5 对相邻基线/监控样本，
  均使用 --quiet-events。make 严格构建、Python/shell 语法及 git diff --check
  通过；合法参数已进入权限检查，非法类别返回用法错误。正式分类数据待用户运行。


- 分类性能实测：process-only 总开销 11.48%、进程阶段 25.95%；file-only 总开销
  102.07%、文件阶段 3599.13%；network-only 总开销 34.32%、网络阶段 866.38%；
  all 总开销 135.43%，文件/网络/进程阶段分别 2784.51%/923.57%/64.08%。
  file_open 真实路径全量采集是最大热点，逐连接网络事件次之；子进程加载库会触发
  文件事件，形成跨类别放大。负开销和无关阶段波动视为 5 次样本及 VirtualBox
  调度噪声，不宣称性能提升。当前全量模式未达到 5%，优化需明确完整性取舍。

## FILE_OPEN 双模式与确定性抽样（2026-09-21，已完成首轮性能实测）

- 用户确认保留默认全量真实路径模式，并增加低开销“每 N 次保留一次”模式。新增
  全局 --file-open-sample-every N，默认 1；BPF 用 cgroup 键的 LRU 计数表，
  第 1 次及之后每隔 N 次在 bpf_d_path/Ring Buffer 之前放行。
- 抽样只影响成功 FILE_OPEN；FILE_UNLINK、失败 openat、进程和网络保持全量。
  N>1 与任何 Agent 的 --sensitive-path 互斥，参数解析阶段拒绝，避免漏掉敏感
  访问告警。完整审计继续使用 N=1。
- 新增 run_file_sampling_benchmark.sh，在 file-only 静默模式比较 N=1/10/100，
  每档 5 对。BPF/用户态严格构建、Python/shell 语法、冲突与合法参数解析及
  git diff --check 均通过；内核加载、抽样事件数量和性能仍待用户 sudo 实测。


- FILE_OPEN 抽样 5 对实测：N=1 总开销 126.91%、文件 3227.18%；N=10 总开销
  15.87%、文件 682.20%；N=100 总开销 5.94%、文件 313.24%。N=100 总耗时
  中位数 678.162→718.424 ms，绝对增加约 40.3 ms，接近但仍未达到 5%。
  CPU 12.35% 与无关网络 -25.58% 表明 5 次 VirtualBox 样本噪声明显，不能宣称
  达标；需增加重复次数、离散度报告并在真实 Linux 机器复测。抽样在昂贵路径解析
  前生效的性能收益已得到验证。

## FILE_OPEN N=100 稳定性复测（2026-09-21，已实测）

- 用户选择先提高 N=100 测量可信度。新增 run_file_sampling_stability.sh，
  固定 file-only、quiet、N=100，预热后运行 15 对相邻基线/监控样本。
- performance_report.py 保留两组中位数开销，并新增逐对开销的中位数和
  p25/p75 四分位区间，用于观察虚拟机调度波动。正式数据待用户运行。


- N=100 的 15 对稳定性结果：两组中位数总开销 9.12%，逐对中位数 8.74%，
  p25/p75 为 4.60%/12.60%；文件阶段逐对中位数 253.55%，p25/p75 为
  231.27%/345.45%。先前 5 对的 5.94% 偏乐观，当前不能宣称达到 5%。
  未保留的每次 FILE_OPEN 仍额外查询 file_open_counts map；可在不提高抽样 N
  的前提下，把计数并入已有 cgroup 归属 map，去掉第二次 map 查询后再测。

## FILE_OPEN 采样 map 合并（2026-09-21，待实机复测）

- 用户选择在保持 N=100 确定性抽样语义的前提下，先减少一次 BPF map 查询。
  agent_by_cgroup 的 value 已由 __u32 agent_id 扩展为 agent_context，包含
  agent_id 与 file_open_count；FILE_OPEN 复用归属查询结果并原子递增计数，
  独立 file_open_counts map 已删除。其他事件仍读取同一结构中的 agent_id。
- make 严格构建、Python 语法、性能脚本 shell 语法和 git diff --check 均通过。
  尚需用户 sudo 加载验证 verifier，再重跑 15 对 N=100 稳定性测试。当前不得
  宣称该优化降低了实测开销或已达到 5%。

- 用户已完成 map 合并后的 N=100、15 对复测，证明新结构通过 verifier 并可正常
  端到端运行。总开销两组中位数为 7.29%，逐对中位数 8.08%，p25/p75 为
  6.02%/15.29%；文件阶段逐对中位数 294.00%，p25/p75 为
  239.19%/357.29%。与合并前总开销逐对中位数 8.74% 相比仅下降 0.66 个
  百分点，p75 反而由 12.60% 升至 15.29%，文件阶段也未改善。结论是额外一次
  map 查询不是主要瓶颈，变化被 VirtualBox 波动覆盖，当前仍不能宣称达到 5%。

## 真实 Agent 接入方案（2026-09-21，已确认总体方向）

- 用户决定继续使用开源 Codex CLI 作为本地 Agent harness，将模型后端替换为
  阿里云百炼的 Qwen；目标是由 Codex 负责上下文、工具调用和本地执行，模型请求
  与 token 消耗走百炼，不使用 ChatGPT/Codex Pro 模型额度。
- 本机 Codex CLI 实测版本为 0.155.1。该新版需要 Responses API；百炼官方文档
  明确给出 qwen3.8-max 的新版 Codex/Responses 配置，而用户额度列表中的
  qwen3.7-flash-2026-07-15 是否支持 Responses 尚未确认。下一步先选定兼容模型，
  再采用不覆盖现有 OpenAI 登录配置、不把 API Key 写入仓库的独立启动配置。

- 用户选择 qwen3.8-max-0902 作为首个百炼后端。已新增
  experiments/run_bailian_codex.sh：Codex CLI 0.155.1 使用 Responses API，
  通过 --ignore-user-config 与 --ephemeral 隔离现有 Pro 配置，默认 low 推理，
  API Key 和业务空间 API Host 分别只从 BAILIAN_API_KEY、BAILIAN_BASE_URL
  读取。脚本不保存密钥，语法、缺少密钥拒绝路径和 git diff --check 已通过；
  首次直连和 sudo 受控启动仍待用户执行。

- 百炼首次直连报告 qwen3.8-max-0902 缺少模型 metadata、使用 fallback。已新增
  experiments/bailian-model-catalog.json，并在启动脚本中显式设置
  model_catalog_json；元数据依据百炼官方 qwen3.8-max 示例映射到带日期模型 ID。
  JSON 与 shell 语法通过，待复跑确认连接结果。

- 百炼 Qwen 首次直连已由用户验证通过：Codex 0.155.1 输出
  model=qwen3.8-max-0902、provider=bailian、low，回复 BAILIAN_OK，使用
  44,877 tokens，退出状态 0，且 metadata fallback 警告已消失。AGENTS.md
  实测约 55 KB，是简单请求仍消耗较多上下文的主要候选。受控监控验证尚未进行；
  脚本增加 $HOME/.local/bin/codex fallback，以适配 sudo secure_path。

- 2026-09-28 qwen3.8-max-0902 免费额度已耗尽。用户从仍有 1M 额度的模型中
  选择继续配置合适后端；当前默认切换为 qwen3.8-27b。百炼官方资料确认该模型
  支持 Function Calling 和 Responses API，最大输入长度为 991808。两个启动器
  和本地 model catalog 已同步更新，API Key 与 Base URL 的配置方式不变；旧 Max
  实验记录保留为历史证据。新模型尚待一次最小直连验证。


- 百炼真实 Codex Agent 首次受控启动完成了进程侧验证：根 PID 99752 及 Codex
  创建的线程和 lsb_release/getconf 辅助进程全部保持 agent_id=1、
  cgroup_id=18468、uid=1000，cgroup 对真实多线程 Agent 的归属链路有效。
  由于测试工作目录位于非 Git 的 /tmp，Codex 在模型请求前以
  `Not inside a trusted directory` 退出，本轮无网络事件，Agent 和监控命令状态均为 1。
  run_bailian_codex.sh 已固定加入 --skip-git-repo-check，待原命令复跑确认
  CONNECT_RESULT、MONITORED_AGENT_OK 和退出状态 0。


- 修复 Git 工作目录检查后，百炼真实 Codex Agent 受控端到端复测通过：根 PID
  101701、agent_id=1、cgroup_id=18538、uid=1000；输出 MONITORED_AGENT_OK，
  tokens used=1,433，Agent 与监控命令退出状态均为 0。观测到同组线程对
  198.18.0.53:443 和 198.18.0.36:443 的 CONNECT_RESULT，ret=-115 是非阻塞
  connect 的 EINPROGRESS，成功模型响应证明连接随后异步完成；该网段可能由当前
  代理/虚拟网络合成，不视为百炼真实公网 IP。真实 Agent 的进程、后代、线程和
  网络事件 cgroup 归属已在该受控场景验证。


- 2026-09-22 真实 Codex Agent 读取 /tmp 只读文件的实验遇到环境阻塞：模型能
  响应，但调用 shell 工具时 bubblewrap 报 `Failed RTM_NEWADDR: Operation not
  permitted`，命令在执行前失败，因此没有目标文件 FILE_OPEN，tokens used=4,550。
  单纯 --cd 只改变工作目录，不构成文件访问隔离；需共同决定修复沙箱环境或在
  受控虚拟机中关闭 Codex 内层沙箱后再验证实际工具行为。


- 2026-09-22 bwrap 修复与真实 Agent 文件读取已由用户实测通过：按官方 Ubuntu
  24.04 方法安装/加载 bwrap AppArmor 配置后，本地 bwrap 能读取测试文件。
  Codex Qwen 在 cgroup_id=8028、agent_id=1、uid=1000 下经工具执行一次
  `cat marker.txt`；监控器记录 PID 12437 的 FILE_OPEN，真实路径为
  `/tmp/ebpf-agent-monitor-qwen-readonly/marker.txt`，flags=32768，path_ret=49；
  Agent 原样报告 EBPF_AGENT_READONLY_20260922，工具、Agent、监控命令状态均为 0，
  tokens used=1,755。目标文件实验后仍为 444 权限、29 字节且内容未变。
  真实 Agent 的文件工具调用与内核路径采集、cgroup 归属已在该受控场景验证。

- 2026-09-22 用户选择对 Codex 沙箱文件噪声采用用户态展示过滤。已新增全局
  `--hide-runtime-noise`（默认关闭）：仅隐藏普通文件事件中 comm 为 `bwrap`、
  `codex-linux-san` 或路径位于 `/tmp/codex-bwrap-synthetic-mount-targets-` 下的打印。
  事件仍进入 detector，告警、进程、网络及 Agent 生命周期输出不受影响。
  `make` 和参数解析检查已通过。用户 sudo 实测本地 bwrap 只读命令：
  agent_id=1、cgroup_id=8274，bwrap 的普通文件事件未展示，cat 的目标文件
  FILE_OPEN 保留，读取内容正确，Agent exit_code=0。exec 过渡期仍出现两条
  comm=monitor 的 bwrap/动态加载器 FILE_OPEN；该选项并未隐藏所有启动文件事件。

- 2026-09-22 已按 problem.md 整理 `docs/acceptance-status.md` 验收证据清单。
  整理时受控脚本已覆盖正式原型的主要基础采集、规则和联合异常；真实 Codex
  尚只验证单 Agent 的进程、网络与文件读取。双真实 Agent 并发已于下文完成，
  真实 Agent 安全规则、真实 Linux 机器性能与 5.15 兼容验证仍缺证据；
  虚拟机 N=100 抽样逐对总开销中位数 8.08%，不能宣称达到 5%。

- 2026-09-22 用户选择先验证两个真实 Codex Agent 并发归属。已在
  `experiments/dual_real_agent_readonly.md` 写明短任务、完整运行命令和核对标准；
  `/tmp/ebpf-agent-monitor-qwen-dual/agent{1,2}/marker.txt` 已创建为 444 权限，
  内容分别为 AGENT_ONE_20260922、AGENT_TWO_20260922。无 sudo 的监控器参数解析
  已进入权限检查，准备阶段未调用模型；随后用户已完成 sudo/百炼测试。

- 2026-09-22 双真实 Codex Agent 只读实验已由用户 sudo 实测通过，详情见
  `experiments/dual_real_agent_readonly.md`。Agent 1 为 cgroup 10074/PID 24056，
  Agent 2 为 cgroup 10093/PID 24057，run_uid/run_gid 均为 1000；两组 443 端口
  CONNECT_RESULT 交错，cat 分别只打开本组 marker.txt，未见串组。两组回复
  对应标记内容，Agent exit_code 和 monitor_exit 均为 0。文件仍为 444 权限且
  内容未变。Codex CLI 分别报告 2,070 和 72,777 tokens；后者高于短任务预期，
  不推断实际计费，不为重复证明同一结论而重跑。当前双真实 Agent 归属已在
  此场景验证。当时仍缺的真实 Agent 安全规则和根进程退出后代管理证据已于
  2026-09-28 补齐；压力与事件丢失测试仍缺。

- 2026-09-28 用户选择验证真实 Codex Agent 触发 sensitive_file_access。
  已创建 `experiments/real_agent_sensitive_read.md`，并准备 444 权限的无害夹具
  `/tmp/ebpf-agent-monitor-real-sensitive/secret.txt`，内容为
  REAL_AGENT_SENSITIVE_20260928。实验将使用 `--sensitive-path` 和单次 cat，
  核对 FILE_OPEN 与告警的时间、PID/TID、agent_id、cgroup_id 和路径；尚未 sudo
  运行或调用百炼模型。

- 2026-09-28 真实 Codex Agent 敏感读取实验已由用户 sudo 实测通过，详情见
  `experiments/real_agent_sensitive_read.md`。Agent 1 为 cgroup 7052/PID 7243；
  cat PID/TID 8041 打开专用 secret.txt 的 FILE_OPEN 与唯一一条 high
  sensitive_file_access 告警共享 timestamp=1656748469967、agent_id/cgroup_id、
  PID/TID、target 和 flags=32768。Codex 原样报告标记内容，Agent 与 monitor
  状态均为 0；文件仍为 444、30 字节且内容未变。Codex CLI 报告 73,323 tokens，
  不推断实际计费，不为重复证明同一结论而重跑。真实 Agent 安全规则已有敏感读取
  证据；Shell 和工作区外删除仍只有受控脚本证据。

- 2026-09-28 用户选择继续验证真实 Agent 非预期 Shell。因原有
  `run_bailian_codex.sh` 本身会启动 Bash，直接使用会污染告警归因；用户选择方案 1，
  新增 `experiments/run_bailian_codex_no_shell.py`，校验相同百炼配置后以 os.execv
  直接替换为 Codex。已通过 Python 语法、缺少密钥和非法 URL 拒绝路径检查。
  `experiments/real_agent_unexpected_shell.md` 记录完整实验；只读夹具位于
  `/tmp/ebpf-agent-monitor-real-shell/marker.txt`。尚未 sudo 运行或调用模型。

- 2026-09-28 真实 Codex 非预期 Shell 实验已由用户 sudo 实测，详情见
  `experiments/real_agent_unexpected_shell.md`。无 Shell 启动器消除了包装脚本
  干扰，但 Codex 框架在收到任务前仍由 tokio worker 启动两次 /bin/bash；工具
  阶段又启动两次，共产生 4 条字段与 EXEC_ATTEMPT 完全对应的 high 告警。
  cat 正确读取 marker，Agent/monitor 状态均为 0，文件未变，tokens used=2,088。
  结论是采集与告警关联有效，但 basename 黑名单对真实 Codex 存在框架级误报，
  不能将每条命中解释为 Prompt 引发的攻击。改进需共同设计命令、父子链或授权
  上下文，不应未经讨论直接添加进程名例外。

- 2026-09-28 用户选择用按 Agent 的三态策略处理真实框架 Shell：
  `--shell-policy deny|audit|allow`。deny 保持输出 high unexpected_shell；audit
  输出 `activity_evidence rule=shell_execution`，只记录活动而不判异常；allow
  不产生检测器输出。未配置时仍关闭该规则，旧 `--deny-shell` 保留为 deny 的
  兼容别名，重复或冲突配置会拒绝启动。实现已通过严格 make、参数解析与本地
  构造事件验证。

- 2026-09-28 真实 Codex audit 模式已由用户 sudo 复测通过：Agent 1 为
  cgroup 7456、根 PID 15170，monitor_exit 和 Agent exit_code 均为 0。框架启动
  与工具阶段共 4 次 /bin/bash EXEC_ATTEMPT，各自对应一条
  `activity_evidence rule=shell_execution policy=shell_audit`，时间戳、PID/TID、
  agent_id、cgroup_id、target 完全对应；未出现 unexpected_shell 安全告警。
  cat 正确打开 marker.txt 并读出预期内容。该结果验证 audit 在真实 Agent 中能
  保留 Shell 证据而不将已知框架行为直接判为 high 异常。

- 2026-09-28 用户选择用真实删除专用临时夹具的方式验证真实 Agent 工作区外
  删除规则。已创建 `experiments/real_agent_outside_workspace_delete.md` 和
  `/tmp/ebpf-agent-monitor-real-delete/{workspace,outside}`；victim.txt 是内容为
  REAL_AGENT_OUTSIDE_DELETE_20260928 的无害 644 文件。实验让 Codex 只执行一次
  指定绝对路径的 rm，核对 FILE_UNLINK_ATTEMPT、outside_workspace_delete 告警、
  字段对应关系和最终文件消失；尚未 sudo 运行或调用模型。

- 2026-09-28 真实 Codex 工作区外删除实验已由用户 sudo 实测。Agent 1 为
  cgroup 7614、根 PID 19630；rm PID/TID 20276 的 FILE_UNLINK_ATTEMPT 与 high
  outside_workspace_delete 告警共享 timestamp=4989584454548、agent/cgroup、
  PID/TID 和 victim.txt 完整路径，path_ret/name_ret 为正。Codex、Agent、monitor
  状态均为 0，victim_exists=0，目标链路通过。但 Bubblewrap 的 synthetic mount
  清理以及 Codex 的 shell_snapshots、SQLite shm/wal、tmp/arg0 清理也产生多条
  high 告警，唯一告警标准失败。结论是采集与路径规则正确，但单一 workspace
  策略无法表达真实 Codex 的运行时授权目录，当前告警精度不可宣称达标。

- 2026-09-28 用户选择用显式运行时审计路径改进删除规则。新增每 Agent 可重复的
  `--runtime-path DIR`（最多 8 个）：workspace 内删除不输出；runtime-path 内
  输出 `activity_evidence rule=runtime_file_delete policy=runtime_delete_audit`；
  其余路径仍输出 high outside_workspace_delete。匹配使用规范化目录边界，不按
  comm/进程名硬编码忽略。严格 make、重复参数解析、相对路径拒绝及本地构造的
  workspace/runtime/outside 三类事件均通过。真实复测将显式配置 Bubblewrap
  synthetic mount 根目录和 `/home/felix/.codex`，尚待用户运行。

- 2026-09-28 删除分级策略已由真实 Codex sudo 复测通过。Agent 1 为 cgroup
  7772、根 PID 22730；rm PID/TID 23335 的目标 FILE_UNLINK_ATTEMPT 与唯一一条
  high outside_workspace_delete 共享 timestamp=6028612007968 及全部归因字段，
  victim_exists=0。Bubblewrap synthetic mount 的 6 次清理和 `~/.codex` 内的
  snapshot、SQLite shm/wal、tmp/arg0 清理全部变为 runtime_file_delete 审计证据，
  未再混入 high。Agent/monitor 状态均为 0。该受控场景通过，但 runtime-path
  仍由部署者显式配置，不宣称系统能自动理解任意业务授权边界。

- 2026-09-28 用户选择先整理可复现交付演示。新增
  `experiments/acceptance_demo_agent.py` 和 `run_acceptance_demo.sh`：不调用模型，
  一次正式 monitor 启动两个确定性 Agent；Agent 1 覆盖敏感读取、允许/越界删除、
  重复 ENOENT 与 CPU 联合异常，Agent 2 覆盖 shell、fork 和本地 IPv4 connect。
  外层脚本用 mktemp 准备/清理无害夹具，逐项检查证据并输出 DEMO_RESULT。
  shell/Python 语法、安全角色和沙箱外本地回环角色均已验证；完整 sudo/eBPF 一键
  运行尚待用户执行。

- 2026-09-28 一键基础验收演示已由用户 sudo 运行通过。Agent 1 为 cgroup
  7886/PID 25750，Agent 2 为 cgroup 7905/PID 25751；两组注册/退出、fork、
  CONNECT_RESULT、unexpected_shell、sensitive_file_access、
  outside_workspace_delete、repeated_failed_open 和 resource_logic_anomaly 共 11 项
  检查全部 PASS，联合异常 CPU=97.70%，monitor_exit=0，最终 DEMO_RESULT=PASS。
  该演示定位为确定性、零模型额度的基础回归；真实 Codex 证据仍由各专项实验提供。

- 2026-09-28 用户选择根进程退出后一直等待 Agent cgroup 自然变空，不自动终止
  后代。监控器新增读取 cgroup v2 `cgroup.events` 的 populated 状态：waitpid
  根进程后输出 `agent_root_exit`，继续保留 BPF 映射、Ring Buffer 和 CPU 采集；
  populated=0 后输出 `agent_cgroup_drained` 和带 `basis=cgroup_empty` 的最终
  `agent_exit`，再进入注销与清理。新增 `experiments/root_exit_descendant.py`，
  根先退出、孩子延迟 0.8 秒退出。严格 make 和 Python 语法通过，待用户 sudo
  验证事件顺序与后代未被终止。

- 2026-09-28 根退出后代等待已由用户 sudo 实测通过。Agent 1 为 cgroup 7756、
  根 PID 7605、孩子 PID 7606。根 exit 后先输出 agent_root_exit；孩子继续运行
  约 0.8 秒，PPID 变为 1，但 PROCESS_EXIT 仍为 agent_id=1/cgroup_id=7756。
  孩子自然退出后才输出 agent_cgroup_drained 和
  `agent_exit exit_code=0 basis=cgroup_empty`，监控状态为 0。该结果确认根退出
  不会杀死后代或提前撤销归属。

- 2026-09-28 已新增 `docs/design.md` 作为交付设计说明，集中记录总体架构、
  cgroup 归属和根退出生命周期、七类事件语义、用户态安全/联合异常策略、确定性
  与真实 Codex 验证、性能数据、已知限制及 Prompt/Response 扩展接口。README
  已增加入口；文档明确不把失败 openat 还原路径、unlink 尝试、EINPROGRESS、
  VirtualBox 性能或受控实验夸大为更强结论。

- 2026-09-28 cgroup 排空生命周期修改后的完整一键回归已由用户 sudo 通过。
  Agent 1 为 cgroup 8178/PID 10412，Agent 2 为 cgroup 8197/PID 10413；11 项
  检查全部 PASS，resource_logic_anomaly CPU=95.67%，monitor_exit=0，最终
  DEMO_RESULT=PASS。两组 agent_exit 均为 exit_code=0、basis=cgroup_empty，确认
  新退出条件未破坏既有多 Agent 采集和检测链路。

- 2026-09-28 为课堂演示新增两个真实 Agent 一键脚本及 `experiments/real_agent_demo.md`。
  简单版单 Agent 展示敏感读取；全面版双 Agent 展示归属、网络、敏感读取、Shell
  审计和工作区外删除。两者都自动准备无害临时夹具、记录完整日志并输出 PASS/FAIL。
  API Key 缺失时由终端隐藏读取，避免写入命令历史；Base URL 和模型使用安全默认值。
  用户已完成两套 sudo/真实模型端到端复测：简单版五项检查全部 PASS，Agent 1
  cgroup=8443/PID=17103；全面版十一项检查全部 PASS，Agent 1 为
  cgroup=8557/PID=17989，Agent 2 为 cgroup=8576/PID=17990。两次 monitor_exit
  和 DEMO_RESULT 均为 0/PASS；全面版两组网络、Shell audit、安全规则和最终
  cgroup_empty 退出均正确，未见串组。

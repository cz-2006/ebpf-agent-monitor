# 项目整体架构图

更新时间：2026-09-29

这张图描述当前已经实现的正式原型。实线表示主要运行数据流，虚线表示配置、
控制或关联关系。图中不包含尚未实现的 HTTPS 明文、Prompt/Response 精确关联和
多 Agent 协作/竞争检测。

```mermaid
flowchart TB
    Operator["用户 / 演示脚本<br/>配置 Agent、策略与工作负载"]

    subgraph UserSpace["用户态：控制、关联与检测"]
        direction LR
        CLI["参数与策略解析<br/>最多 16 个 --agent"]
        Identity["sudo 调用者身份恢复<br/>initgroups → setresgid → setresuid"]
        Lifecycle["Agent 生命周期管理<br/>fork、两阶段门控、waitpid"]
        CgroupCtl["cgroup v2 控制<br/>创建、迁移、核验、排空检测"]
        Collector["Ring Buffer Collector<br/>长度校验、事件分派、展示过滤"]
        Sampler["资源采样器<br/>读取 cgroup cpu.stat"]
        Detector["用户态 Detector<br/>按 agent_id 保存独立策略与状态"]
        Output["结构化输出<br/>activity_evidence<br/>security_alert<br/>anomaly_alert"]

        CLI --> Lifecycle
        CLI --> Detector
        Lifecycle --> Identity
        Lifecycle --> CgroupCtl
        Collector --> Detector
        Sampler --> Detector
        Detector --> Output
    end

    subgraph AgentRuntime["被监控运行域：每个 Agent 一个独立 cgroup"]
        direction LR
        Agent1["Agent 1 根进程<br/>Codex / Qwen 或测试负载"]
        Desc1["线程与后代进程"]
        AgentN["Agent 2…16 根进程"]
        DescN["线程与后代进程"]

        Agent1 --> Desc1
        AgentN --> DescN
    end

    subgraph Kernel["Linux 内核：eBPF 数据面"]
        direction TB

        subgraph Hooks["观测点"]
            direction LR
            ProcHooks["进程 tracepoints<br/>execve / fork / exit"]
            FileHooks["文件观测<br/>BPF LSM file_open / path_unlink<br/>openat 入口与返回"]
            NetHooks["网络 tracepoints<br/>connect 入口与返回"]
        end

        AgentMap["agent_by_cgroup BPF map<br/>cgroup_id → agent_id + 抽样计数"]
        PendingMaps["临时配对 maps<br/>pending_openats<br/>pending_connects<br/>key = pid_tgid"]
        EventBuild["统一事件协议<br/>时间、PID/TID/PPID、UID<br/>comm、cgroup_id、agent_id、payload"]
        Ring["BPF Ring Buffer<br/>内核态 → 用户态"]

        ProcHooks --> EventBuild
        FileHooks --> PendingMaps
        NetHooks --> PendingMaps
        PendingMaps --> EventBuild
        AgentMap -.->|"仅保留已登记 cgroup"| ProcHooks
        AgentMap -.->|"归属与 FILE_OPEN 抽样"| FileHooks
        AgentMap -.->|"归属过滤"| NetHooks
        EventBuild --> Ring
    end

    subgraph Rules["当前检测规则"]
        direction LR
        ShellRule["Shell 三态策略<br/>deny / audit / allow"]
        SensitiveRule["敏感文件读取"]
        DeleteRule["删除分级<br/>workspace / runtime / outside"]
        RepeatRule["同 Agent、同目标<br/>时间窗内重复 ENOENT"]
        JointRule["资源/逻辑联合异常<br/>重复失败 + 高 CPU"]

        RepeatRule --> JointRule
    end

    Operator --> CLI
    Identity --> Agent1
    Identity --> AgentN
    CgroupCtl --> Agent1
    CgroupCtl --> AgentN
    CgroupCtl -.->|"加载前登记映射"| AgentMap

    Agent1 -->|"系统调用与内核行为"| Hooks
    Desc1 -->|"自然继承同一 cgroup"| Hooks
    AgentN -->|"系统调用与内核行为"| Hooks
    DescN -->|"自然继承同一 cgroup"| Hooks

    Ring --> Collector
    CgroupCtl -.->|"cgroup 路径"| Sampler
    CgroupCtl -.->|"populated=0 后注销"| AgentMap

    Detector --> ShellRule
    Detector --> SensitiveRule
    Detector --> DeleteRule
    Detector --> RepeatRule
    Sampler -.->|"CPU 时间窗证据"| JointRule
    ShellRule --> Output
    SensitiveRule --> Output
    DeleteRule --> Output
    RepeatRule --> Output
    JointRule --> Output

    classDef control fill:#E8F1FF,stroke:#2457A6,color:#102A43;
    classDef agent fill:#FFF4D6,stroke:#B7791F,color:#5F370E;
    classDef kernel fill:#E7F8EF,stroke:#25855A,color:#123B2A;
    classDef detect fill:#F6EAFE,stroke:#805AD5,color:#3C2463;
    classDef output fill:#FFE8E8,stroke:#C53030,color:#63171B;

    class CLI,Identity,Lifecycle,CgroupCtl,Collector,Sampler control;
    class Agent1,Desc1,AgentN,DescN agent;
    class ProcHooks,FileHooks,NetHooks,AgentMap,PendingMaps,EventBuild,Ring kernel;
    class Detector,ShellRule,SensitiveRule,DeleteRule,RepeatRule,JointRule detect;
    class Output output;
```

## 阅读顺序

1. 用户通过 `monitor` 或演示脚本配置一个或多个 Agent。
2. 用户态控制面创建独立 cgroup，执行两阶段门控和降权，并在 BPF map 中登记
   `cgroup_id → agent_id`。
3. Agent 及其后代在内核中触发进程、文件和网络观测点；未登记 cgroup 的事件被过滤。
4. eBPF 生成统一事件，经 Ring Buffer 送到用户态 Collector。
5. Detector 把事件与每个 Agent 的策略、重复活动状态和 cgroup CPU 样本关联。
6. 系统输出活动证据、安全告警或资源/逻辑联合异常。
7. 根进程退出后仍继续监控后代；只有 `cgroup.events` 显示 `populated=0`，才注销
   BPF map 并输出最终 `agent_exit`。

## 源码对应关系

| 图中模块 | 主要源码 |
| --- | --- |
| 统一事件协议 | `include/events.h` |
| eBPF 观测点、maps、Ring Buffer | `src/monitor.bpf.c` |
| 参数、受控启动、cgroup、Collector | `src/monitor.c` |
| 用户态异常规则 | `include/detector.h`、`src/detector.c` |
| CPU 资源采样 | `include/resource_sampler.h`、`src/resource_sampler.c` |
| 工作负载、演示与性能评测 | `experiments/` |

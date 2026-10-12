# 一键真实 Agent 演示

这组脚本用于课堂现场演示。脚本必须由普通用户运行，会自行调用 `sudo`；API Key
只从环境变量读取，不写入仓库或终端摘要。

## 演示前准备

```bash
cd ~/projects/ebpf-agent-monitor
make
```

不要把真实 API Key 写在命令行。直接启动演示；如果当前环境没有 Key，脚本会显示
`Bailian API Key (hidden):`，此时粘贴 Key 并回车。输入内容不会回显，也不会进入
Shell 历史。Base URL 和模型默认分别为百炼兼容接口与 `qwen3.8-flash`，需要切换时
才单独导出非敏感的 `BAILIAN_BASE_URL` 或 `BAILIAN_MODEL`。

## 简单版

```bash
./experiments/run_real_agent_demo_simple.sh
```

简单版调用一个真实 Codex Agent，让它读取脚本临时创建的无害敏感文件。脚本检查
Agent 注册、目标 FILE_OPEN、sensitive_file_access 告警、模型回复和 cgroup 排空
退出，成功时输出 `DEMO_RESULT=PASS`。完整日志默认位于
`/tmp/ebpf-agent-monitor-real-demo-simple.log`。

## 全面版

```bash
./experiments/run_real_agent_demo_full.sh
```

全面版并发调用两个真实 Codex Agent，因此会产生两次模型调用。Agent 1 读取敏感
文件；Agent 2 删除其工作区外的专用临时文件。两组都启用 Shell audit。脚本检查
两组独立注册、网络事件、敏感读取告警、工作区外删除告警、Shell 审计、实际删除
结果和两组 cgroup 排空退出，成功时输出 `DEMO_RESULT=PASS`。完整日志默认位于
`/tmp/ebpf-agent-monitor-real-demo-full.log`。

两种演示都只产生观测和告警，不阻止文件操作。全面版使用的删除目标由脚本在
`/tmp` 下临时创建，退出时清理整个临时目录。

可用 `DEMO_LOG` 改写日志位置，例如：

```bash
DEMO_LOG=/tmp/my-real-agent-demo.log ./experiments/run_real_agent_demo_simple.sh
```

网络或模型临时不可用时，使用不调用模型的确定性备用演示：

```bash
./experiments/run_acceptance_demo.sh
```

## 用户实测结果（2026-09-28）

简单版通过：monitor_exit=0，五项检查全部 PASS，最终 DEMO_RESULT=PASS。Agent 1
为 cgroup 8443、根 PID 17103；cat PID/TID 17544 的目标 FILE_OPEN 与 high
sensitive_file_access 共享 timestamp、agent_id、cgroup_id 和完整路径。模型正确
报告 `REAL_AGENT_SIMPLE_DEMO_OK`，最终 agent_exit 为 exit_code=0、
basis=cgroup_empty。

全面版通过：monitor_exit=0，十一项检查全部 PASS，最终 DEMO_RESULT=PASS。Agent 1
为 cgroup 8557、根 PID 17989，Agent 2 为 cgroup 8576、根 PID 17990。两组均有
独立的 443 CONNECT_RESULT 和 Shell audit；Agent 1 产生唯一目标敏感读取告警并
报告 `REAL_AGENT_FULL_DEMO_ONE`，Agent 2 产生目标 outside_workspace_delete，
且临时 victim.txt 实际消失。两组最终均以 exit_code=0、basis=cgroup_empty 退出，
未见归属串组。

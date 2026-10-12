#ifndef EBPF_AGENT_MONITOR_DETECTOR_H
#define EBPF_AGENT_MONITOR_DETECTOR_H

/*
 * 用户态异常检测器接口。
 *
 * 采集器把原始事件交给 detector_process()，资源采样器把 CPU 样本交给
 * detector_process_cpu_sample()。检测器只输出证据与告警，不参与 BPF 加载、
 * cgroup 创建或目标进程控制。
 */

#include <limits.h>
#include <stddef.h>
#include <linux/types.h>

#include "events.h"
#include "resource_sampler.h"

#define DETECTOR_MAX_AGENTS 16
#define DETECTOR_MAX_FAILED_OPEN_STATES 128
#define DETECTOR_MAX_RUNTIME_DIRS 8

enum detector_shell_policy {
    DETECTOR_SHELL_DISABLED = 0, /* 不启用这条规则。 */
    DETECTOR_SHELL_DENY,         /* 发现 Shell 时输出 high 告警。 */
    DETECTOR_SHELL_AUDIT,        /* 只输出 activity_evidence。 */
    DETECTOR_SHELL_ALLOW,        /* 明确允许，不输出规则结果。 */
};

/* 单个 Agent 的静态规则配置；空路径表示对应规则未启用。 */
struct detector_agent_policy {
    __u32 agent_id; /* 与事件头中的 agent_id 精确匹配。 */
    enum detector_shell_policy shell_policy;
    char sensitive_dir[EVENT_FILENAME_LEN]; /* 读取即告警的目录边界。 */
    char workspace_dir[EVENT_FILENAME_LEN]; /* 允许删除文件的业务目录。 */
    /* Codex/bwrap 等框架可正常清理的目录：记录审计证据而非 high 告警。 */
    char runtime_dirs[DETECTOR_MAX_RUNTIME_DIRS][EVENT_FILENAME_LEN];
    size_t runtime_dir_count;
    __u32 failed_open_threshold;    /* 同一目标在窗口内的失败次数门槛。 */
    __u32 failed_open_window_ms;    /* 重复失败统计窗口。 */
    __u32 cpu_threshold_percent;    /* 联合异常的单核百分比门槛。 */
};

/*
 * 一条 (agent_id, path) 的跨事件窗口状态。Detector 用固定数组避免运行中
 * 动态分配；槽位满时复用最久未见的状态。alerted 与 joint_alerted 分别保证
 * 单项重复失败告警和“重复失败 + 高 CPU”联合告警在一个窗口内只输出一次。
 */
struct failed_open_state {
    int used;
    int alerted;
    int joint_alerted;
    __u32 agent_id;
    __u32 count;
    __u64 window_start_ns; /* 本窗口第一条失败事件时间。 */
    __u64 last_seen_ns;    /* 最近失败时间，也用于选择可复用槽位。 */
    __u32 pid;
    __u32 tid;
    __u64 cgroup_id;
    char path[PATH_MAX];
};

/* Detector 的完整内存状态，生命周期与 monitor 主进程一致。 */
struct detector {
    struct detector_agent_policy policies[DETECTOR_MAX_AGENTS];
    struct failed_open_state failed_open_states[DETECTOR_MAX_FAILED_OPEN_STATES];
    size_t policy_count;
};

/* 清零策略表与所有跨事件状态；添加策略前必须调用。 */
void detector_init(struct detector *detector);
/* 注册一个 Agent 的路径、Shell、失败打开与 CPU 联合判定策略。 */
int detector_add_agent(struct detector *detector, __u32 agent_id,
                       enum detector_shell_policy shell_policy,
                       const char *sensitive_path,
                       const char *workspace_path,
                       const char *const runtime_paths[],
                       size_t runtime_path_count,
                       __u32 failed_open_threshold,
                       __u32 failed_open_window_ms,
                       __u32 cpu_threshold_percent);
/* 消费一条已经过协议长度校验的 Ring Buffer 事件。 */
void detector_process(struct detector *detector, const void *data,
                      size_t size);
/* 将 cgroup CPU 样本与此前保存的重复失败证据关联。 */
void detector_process_cpu_sample(
    struct detector *detector, const struct resource_cpu_sample *sample);

#endif

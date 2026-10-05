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
    DETECTOR_SHELL_DISABLED = 0,
    DETECTOR_SHELL_DENY,
    DETECTOR_SHELL_AUDIT,
    DETECTOR_SHELL_ALLOW,
};

struct detector_agent_policy {
    __u32 agent_id;
    enum detector_shell_policy shell_policy;
    char sensitive_dir[EVENT_FILENAME_LEN];
    char workspace_dir[EVENT_FILENAME_LEN];
    char runtime_dirs[DETECTOR_MAX_RUNTIME_DIRS][EVENT_FILENAME_LEN];
    size_t runtime_dir_count;
    __u32 failed_open_threshold;
    __u32 failed_open_window_ms;
    __u32 cpu_threshold_percent;
};

struct failed_open_state {
    int used;
    int alerted;
    int joint_alerted;
    __u32 agent_id;
    __u32 count;
    __u64 window_start_ns;
    __u64 last_seen_ns;
    __u32 pid;
    __u32 tid;
    __u64 cgroup_id;
    char path[PATH_MAX];
};

struct detector {
    struct detector_agent_policy policies[DETECTOR_MAX_AGENTS];
    struct failed_open_state failed_open_states[DETECTOR_MAX_FAILED_OPEN_STATES];
    size_t policy_count;
};

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

#ifndef EBPF_AGENT_MONITOR_DETECTOR_H
#define EBPF_AGENT_MONITOR_DETECTOR_H

#include <limits.h>
#include <stddef.h>
#include <linux/types.h>

#include "events.h"
#include "resource_sampler.h"

#define DETECTOR_MAX_AGENTS 16
#define DETECTOR_MAX_FAILED_OPEN_STATES 128

struct detector_agent_policy {
    __u32 agent_id;
    int deny_shell;
    char sensitive_dir[EVENT_FILENAME_LEN];
    char workspace_dir[EVENT_FILENAME_LEN];
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
int detector_add_agent(struct detector *detector, __u32 agent_id,
                       int deny_shell, const char *sensitive_path,
                       const char *workspace_path,
                       __u32 failed_open_threshold,
                       __u32 failed_open_window_ms,
                       __u32 cpu_threshold_percent);
void detector_process(struct detector *detector, const void *data,
                      size_t size);
void detector_process_cpu_sample(
    struct detector *detector, const struct resource_cpu_sample *sample);

#endif

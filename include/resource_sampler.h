#ifndef EBPF_AGENT_MONITOR_RESOURCE_SAMPLER_H
#define EBPF_AGENT_MONITOR_RESOURCE_SAMPLER_H

#include <limits.h>
#include <stddef.h>
#include <linux/types.h>

#define RESOURCE_SAMPLER_MAX_AGENTS 16

/* 相邻两次 cpu.stat 读数形成一个采样区间；10000 表示 100.00%。 */
struct resource_cpu_sample {
    __u32 agent_id;
    __u64 cgroup_id;
    __u64 timestamp_ns;
    __u64 interval_usec;
    __u64 usage_delta_usec;
    __u64 cpu_percent_x100;
};

struct resource_sampler_agent {
    int active;
    __u32 agent_id;
    __u64 cgroup_id;
    __u32 interval_ms;
    __u64 previous_timestamp_ns;
    __u64 previous_usage_usec;
    __u64 next_sample_ns;
    char cpu_stat_path[PATH_MAX];
};

struct resource_sampler {
    struct resource_sampler_agent agents[RESOURCE_SAMPLER_MAX_AGENTS];
    size_t count;
};

typedef void (*resource_sample_callback)(
    void *context, const struct resource_cpu_sample *sample);

void resource_sampler_init(struct resource_sampler *sampler);
int resource_sampler_add_agent(struct resource_sampler *sampler,
                               __u32 agent_id, __u64 cgroup_id,
                               const char *cgroup_path, __u32 interval_ms);
void resource_sampler_collect_due(struct resource_sampler *sampler,
                                  resource_sample_callback callback,
                                  void *context);
void resource_sampler_collect_agent(struct resource_sampler *sampler,
                                    __u32 agent_id,
                                    resource_sample_callback callback,
                                    void *context);

#endif

#ifndef EBPF_AGENT_MONITOR_RESOURCE_SAMPLER_H
#define EBPF_AGENT_MONITOR_RESOURCE_SAMPLER_H

/*
 * cgroup v2 CPU 采样器接口。
 *
 * 采样器读取每个 Agent 的 cpu.stat，以相邻样本的 usage_usec 增量计算单核
 * 百分比，再通过回调交给 detector。它不在内核探针中累计 CPU 时间。
 */

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
/* 记录 Agent 的 cgroup 路径和采样周期；首次采集将建立基线。 */
int resource_sampler_add_agent(struct resource_sampler *sampler,
                               __u32 agent_id, __u64 cgroup_id,
                               const char *cgroup_path, __u32 interval_ms);
/* 仅采集已经到达各自截止时间的 Agent。 */
void resource_sampler_collect_due(struct resource_sampler *sampler,
                                  resource_sample_callback callback,
                                  void *context);
/* force 非零时忽略截止时间，常用于 Agent 退出前的最后一次采样。 */
void resource_sampler_collect_agent(struct resource_sampler *sampler,
                                    __u32 agent_id,
                                    resource_sample_callback callback,
                                    void *context);

#endif

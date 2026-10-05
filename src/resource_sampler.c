#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "resource_sampler.h"

/*
 * 资源采样控制面：周期读取 cgroup v2 的 cpu.stat。百分比以一个逻辑 CPU
 * 为 100% 计算，因此多线程 Agent 在多核机器上理论上可能超过 100%。
 */

static int monotonic_ns(__u64 *timestamp_ns)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return -1;
    *timestamp_ns = (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;
    return 0;
}

static int read_usage_usec(const char *path, __u64 *usage_usec)
{
    char key[64];
    unsigned long long value;
    FILE *file = fopen(path, "r");

    if (!file)
        return -1;
    while (fscanf(file, "%63s %llu", key, &value) == 2) {
        if (!strcmp(key, "usage_usec")) {
            *usage_usec = (__u64)value;
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    errno = ENODATA;
    return -1;
}

void resource_sampler_init(struct resource_sampler *sampler)
{
    memset(sampler, 0, sizeof(*sampler));
}

int resource_sampler_add_agent(struct resource_sampler *sampler,
                               __u32 agent_id, __u64 cgroup_id,
                               const char *cgroup_path, __u32 interval_ms)
{
    struct resource_sampler_agent *agent;
    int written;

    if (!sampler || !interval_ms ||
        sampler->count >= RESOURCE_SAMPLER_MAX_AGENTS)
        return -1;
    agent = &sampler->agents[sampler->count];
    written = snprintf(agent->cpu_stat_path, sizeof(agent->cpu_stat_path),
                       "%s/cpu.stat", cgroup_path);
    if (written < 0 || (size_t)written >= sizeof(agent->cpu_stat_path) ||
        monotonic_ns(&agent->previous_timestamp_ns) ||
        read_usage_usec(agent->cpu_stat_path, &agent->previous_usage_usec))
        return -1;

    agent->active = 1;
    agent->agent_id = agent_id;
    agent->cgroup_id = cgroup_id;
    agent->interval_ms = interval_ms;
    agent->next_sample_ns = agent->previous_timestamp_ns +
                            (__u64)interval_ms * 1000000ULL;
    sampler->count++;
    return 0;
}

/* 第一次读取只建立基线；后续样本用 CPU 增量/墙钟增量计算利用率。 */
static void collect(struct resource_sampler_agent *agent, int force,
                    resource_sample_callback callback, void *context)
{
    struct resource_cpu_sample sample = {0};
    __u64 timestamp_ns;
    __u64 usage_usec;

    if (!agent->active || monotonic_ns(&timestamp_ns))
        return;
    if (!force && timestamp_ns < agent->next_sample_ns)
        return;
    if (read_usage_usec(agent->cpu_stat_path, &usage_usec)) {
        fprintf(stderr,
                "event=resource_sample_error agent_id=%u cgroup_id=%" PRIu64
                " source=cpu.stat errno=%d\n",
                agent->agent_id, (uint64_t)agent->cgroup_id, errno);
        agent->next_sample_ns = timestamp_ns +
                                (__u64)agent->interval_ms * 1000000ULL;
        return;
    }
    if (timestamp_ns <= agent->previous_timestamp_ns ||
        usage_usec < agent->previous_usage_usec)
        goto update_baseline;

    sample.agent_id = agent->agent_id;
    sample.cgroup_id = agent->cgroup_id;
    sample.timestamp_ns = timestamp_ns;
    sample.interval_usec =
        (timestamp_ns - agent->previous_timestamp_ns) / 1000ULL;
    sample.usage_delta_usec = usage_usec - agent->previous_usage_usec;
    if (sample.interval_usec) {
        sample.cpu_percent_x100 =
            sample.usage_delta_usec * 10000ULL / sample.interval_usec;
        callback(context, &sample);
    }

update_baseline:
    agent->previous_timestamp_ns = timestamp_ns;
    agent->previous_usage_usec = usage_usec;
    agent->next_sample_ns = timestamp_ns +
                            (__u64)agent->interval_ms * 1000000ULL;
}

void resource_sampler_collect_due(struct resource_sampler *sampler,
                                  resource_sample_callback callback,
                                  void *context)
{
    size_t index;

    if (!sampler || !callback)
        return;
    for (index = 0; index < sampler->count; index++)
        collect(&sampler->agents[index], 0, callback, context);
}

void resource_sampler_collect_agent(struct resource_sampler *sampler,
                                    __u32 agent_id,
                                    resource_sample_callback callback,
                                    void *context)
{
    size_t index;

    if (!sampler || !callback)
        return;
    for (index = 0; index < sampler->count; index++) {
        if (sampler->agents[index].agent_id == agent_id) {
            collect(&sampler->agents[index], 1, callback, context);
            sampler->agents[index].active = 0;
            return;
        }
    }
}

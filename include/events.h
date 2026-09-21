#ifndef EBPF_AGENT_MONITOR_EVENTS_H
#define EBPF_AGENT_MONITOR_EVENTS_H

/* eBPF 侧的 vmlinux.h 已定义整数类型；用户态才需要 linux/types.h。 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define EVENT_COMM_LEN 16
#define EVENT_FILENAME_LEN 256

enum event_type {
    EVENT_EXEC_ATTEMPT = 1, /* execve 入口：只表示执行尝试。 */
};

/* 所有事件都以公共头开始，用户态据此校验长度并按类型分派。 */
struct monitor_event_header {
    __u64 timestamp_ns; /* 内核单调时钟。 */
    __u64 cgroup_id;    /* 原始 Agent 归属依据。 */
    __u32 size;         /* 整条事件的字节数。 */
    __u32 event_type;   /* enum event_type。 */
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 agent_id;     /* 0 表示尚未映射到 Agent。 */
    char comm[EVENT_COMM_LEN];
};

struct exec_payload {
    char filename[EVENT_FILENAME_LEN]; /* execve 调用者传入的路径。 */
};

struct exec_event {
    struct monitor_event_header header;
    struct exec_payload payload;
};

#endif

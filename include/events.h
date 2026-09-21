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
    EVENT_PROCESS_FORK = 2, /* 已成功创建子任务。 */
    EVENT_PROCESS_EXIT = 3, /* 当前任务正在退出。 */
    EVENT_FILE_OPEN = 4, /* 已到达 file_open LSM 钩子。 */
    EVENT_FILE_UNLINK_ATTEMPT = 5, /* 删除前的 path_unlink LSM 钩子。 */
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

struct process_fork_payload {
    __u32 parent_pid;
    __u32 child_pid;
    char child_comm[EVENT_COMM_LEN];
};

struct process_fork_event {
    struct monitor_event_header header;
    struct process_fork_payload payload;
};

struct process_exit_payload {
    __s32 exit_code_raw; /* task_struct.exit_code，用户态负责解释。 */
};

struct process_exit_event {
    struct monitor_event_header header;
    struct process_exit_payload payload;
};

struct file_open_payload {
    __s32 path_ret; /* bpf_d_path 返回值；负数表示解析失败。 */
    __u32 flags;
    char path[EVENT_FILENAME_LEN];
};

struct file_open_event {
    struct monitor_event_header header;
    struct file_open_payload payload;
};

struct file_unlink_payload {
    __s32 path_ret; /* 父目录 bpf_d_path 返回值。 */
    __s32 name_ret; /* dentry 名称读取返回值。 */
    char dir_path[EVENT_FILENAME_LEN];
    char name[EVENT_FILENAME_LEN];
};

struct file_unlink_event {
    struct monitor_event_header header;
    struct file_unlink_payload payload;
};

#endif

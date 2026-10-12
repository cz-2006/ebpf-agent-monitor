#ifndef EBPF_AGENT_MONITOR_EVENTS_H
#define EBPF_AGENT_MONITOR_EVENTS_H

/*
 * 内核态与用户态共享的二进制事件协议。
 *
 * monitor.bpf.c 按这些结构向 Ring Buffer 写入事件，monitor.c 再根据
 * monitor_event_header.event_type 和 size 做严格分派。因此这里只能追加兼容
 * 字段或同步修改两端，不能单独改变结构布局。
 */

/* eBPF 侧的 vmlinux.h 已定义整数类型；用户态才需要 linux/types.h。 */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* Linux task comm 最多 16 字节（包含结尾 \0），与 bpf_get_current_comm 对齐。 */
#define EVENT_COMM_LEN 16
/* 固定长度避免 Ring Buffer 中使用变长对象；过长路径会被内核 helper 截断。 */
#define EVENT_FILENAME_LEN 256

/*
 * Ring Buffer 中可能出现的消息类型。数值是内核态和用户态之间的 ABI，已有值
 * 不应重新编号；新增类型时还要同步 monitor.c 的长度校验和分派逻辑。
 */
enum event_type {
    EVENT_EXEC_ATTEMPT = 1, /* execve 入口：只表示执行尝试。 */
    EVENT_PROCESS_FORK = 2, /* 已成功创建子任务。 */
    EVENT_PROCESS_EXIT = 3, /* 当前任务正在退出。 */
    EVENT_FILE_OPEN = 4, /* 已到达 file_open LSM 钩子。 */
    EVENT_FILE_UNLINK_ATTEMPT = 5, /* 删除前的 path_unlink LSM 钩子。 */
    EVENT_CONNECT_RESULT = 6, /* connect 系统调用返回结果。 */
    EVENT_FILE_OPEN_RESULT = 7, /* 当前只提交失败的 openat 返回结果。 */
};

/*
 * agent_by_cgroup BPF map 的 value。key 是内核提供的 cgroup_id：
 * agent_id 用于业务展示，file_open_count 用于每 N 次保留一次 FILE_OPEN。
 * reserved 显式填充对齐空间，保证 C 用户态和 eBPF 侧布局一致。
 */
struct agent_context {
    __u32 agent_id;
    __u32 reserved;
    __u64 file_open_count;
};

/*
 * 所有事件都以公共头开始，用户态先把 data 当成该结构读取，再用 size 和
 * event_type 校验、分派。时间戳来自 CLOCK_MONOTONIC 同一时间域，不是现实日期。
 * pid 是线程组 ID（通常理解为进程号），tid 是当前线程 ID。
 */
struct monitor_event_header {
    __u64 timestamp_ns; /* 内核单调时钟。 */
    __u64 cgroup_id;    /* 原始 Agent 归属依据。 */
    __u32 size;         /* 整条事件的字节数。 */
    __u32 event_type;   /* enum event_type。 */
    __u32 pid;          /* 当前任务的 TGID，即用户通常看到的进程 PID。 */
    __u32 tid;          /* 当前执行系统调用或 hook 的线程 ID。 */
    __u32 ppid;         /* real_parent 的 TGID，用于回溯，不作为主归属依据。 */
    __u32 uid;          /* 触发事件时的真实 UID 低 32 位。 */
    __u32 agent_id;     /* 0 表示尚未映射到 Agent。 */
    char comm[EVENT_COMM_LEN]; /* 当前 task 名称，不一定等于可执行文件路径。 */
};

/* execve 入口参数；入口事件不能证明内核最终成功替换了进程映像。 */
struct exec_payload {
    char filename[EVENT_FILENAME_LEN]; /* execve 调用者传入的路径。 */
};

struct exec_event {
    struct monitor_event_header header;
    struct exec_payload payload;
};

/* sched_process_fork 已发生后提供的父子标识。 */
struct process_fork_payload {
    __u32 parent_pid;              /* tracepoint 报告的父进程 PID。 */
    __u32 child_pid;               /* 新任务 PID。 */
    char child_comm[EVENT_COMM_LEN]; /* 新任务创建瞬间的 comm。 */
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

/* LSM file_open 已拿到 struct file，可报告内核解析后的路径和打开方式。 */
struct file_open_payload {
    __s32 path_ret; /* bpf_d_path 返回值；负数表示解析失败。 */
    __u32 flags; /* file->f_flags，例如 O_RDONLY/O_WRONLY/O_DIRECTORY。 */
    char path[EVENT_FILENAME_LEN]; /* bpf_d_path 输出的解析后路径。 */
};

struct file_open_event {
    struct monitor_event_header header;
    struct file_open_payload payload;
};

/* openat 返回探针使用的失败信息；与成功 FILE_OPEN 的语义不同。 */
struct file_open_result_payload {
    __s32 dirfd;
    __s32 ret; /* 负数是内核 errno；当前事件只包含失败结果。 */
    char attempted_path[EVENT_FILENAME_LEN]; /* openat 的原始用户态路径。 */
};

struct file_open_result_event {
    struct monitor_event_header header;
    struct file_open_result_payload payload;
};

/* path_unlink 分别给出父目录和 dentry 名称，用户态将两部分安全拼接。 */
struct file_unlink_payload {
    __s32 path_ret; /* 父目录 bpf_d_path 返回值。 */
    __s32 name_ret; /* dentry 名称读取返回值。 */
    char dir_path[EVENT_FILENAME_LEN]; /* 内核解析后的父目录路径。 */
    char name[EVENT_FILENAME_LEN];     /* 待删除 dentry 的名称。 */
};

struct file_unlink_event {
    struct monitor_event_header header;
    struct file_unlink_payload payload;
};

/* connect 入口保存目标，返回点补充 ret 后才提交该载荷。 */
struct connect_payload {
    __s32 socket_fd; /* connect() 的第一个参数，只在当前进程中有意义。 */
    __s32 ret; /* 0 表示同步成功；负数是内核 errno，如 -115=EINPROGRESS。 */
    __u16 family; /* AF_INET 或 AF_INET6。 */
    __u16 destination_port; /* 主机字节序。 */
    __u8 destination_address[16]; /* IPv4 使用前 4 字节，IPv6 使用全部。 */
};

struct connect_event {
    struct monitor_event_header header;
    struct connect_payload payload;
};

#endif

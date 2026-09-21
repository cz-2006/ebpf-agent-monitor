#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

/* 内核态通过 Ring Buffer 把事件发送给用户态。 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* 受控启动器预先注册 cgroup；未注册 cgroup 的事件直接忽略。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u64);
    __type(value, __u32);
} agent_by_cgroup SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    struct task_struct *task;
    __u32 *agent_id;
    __u64 cgroup_id;
    const char *filename;
    __u64 pid_tgid;
    __u64 uid_gid;

    cgroup_id = bpf_get_current_cgroup_id();
    agent_id = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent_id)
        return 0;

    /* 直接在 Ring Buffer 中申请空间，失败时丢弃本条事件。 */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    /* 填充所有事件共有的上下文。 */
    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_EXEC_ATTEMPT;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = *agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    /* execve 的第一个参数是用户态 filename 指针。 */
    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->payload.filename,
                            sizeof(event->payload.filename), filename);

    /* 提交后，用户态的 Ring Buffer 回调会收到这条事件。 */
    bpf_ringbuf_submit(event, 0);
    return 0;
}


SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_fork_event *event;
    struct task_struct *task;
    __u32 *agent_id;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;

    cgroup_id = bpf_get_current_cgroup_id();
    agent_id = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent_id)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_PROCESS_FORK;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = *agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    event->payload.parent_pid = ctx->parent_pid;
    event->payload.child_pid = ctx->child_pid;
    bpf_probe_read_kernel_str(
        event->payload.child_comm, sizeof(event->payload.child_comm),
        (const char *)ctx + (ctx->__data_loc_child_comm & 0xffff));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_exit_event *event;
    struct task_struct *task;
    __u32 *agent_id;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;

    (void)ctx;
    cgroup_id = bpf_get_current_cgroup_id();
    agent_id = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent_id)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_PROCESS_EXIT;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = *agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));
    event->payload.exit_code_raw = BPF_CORE_READ(task, exit_code);

    bpf_ringbuf_submit(event, 0);
    return 0;
}


SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
    struct file_open_event *event;
    struct task_struct *task;
    __u32 *agent_id;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;
    long path_ret;

    /* 保留更早 LSM/BPF 程序给出的拒绝结果，不改变系统安全策略。 */
    if (ret)
        return ret;

    cgroup_id = bpf_get_current_cgroup_id();
    agent_id = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent_id)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_FILE_OPEN;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = *agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    event->payload.flags = BPF_CORE_READ(file, f_flags);
    path_ret = bpf_d_path((struct path *)&file->f_path, event->payload.path,
                          sizeof(event->payload.path));
    event->payload.path_ret = (__s32)path_ret;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(handle_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    struct file_unlink_event *event;
    struct task_struct *task;
    __u32 *agent_id;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;
    const unsigned char *name;
    long path_ret;
    long name_ret;

    if (ret)
        return ret;

    cgroup_id = bpf_get_current_cgroup_id();
    agent_id = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent_id)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_FILE_UNLINK_ATTEMPT;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = *agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    path_ret = bpf_d_path((struct path *)dir, event->payload.dir_path,
                          sizeof(event->payload.dir_path));
    event->payload.path_ret = (__s32)path_ret;

    name = BPF_CORE_READ(dentry, d_name.name);
    name_ret = bpf_probe_read_kernel_str(event->payload.name,
                                         sizeof(event->payload.name), name);
    event->payload.name_ret = (__s32)name_ret;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

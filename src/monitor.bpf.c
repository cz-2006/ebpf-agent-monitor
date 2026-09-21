#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

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

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "events.h"

/*
 * eBPF 数据面：只观测已登记 Agent cgroup 中的进程、文件和网络行为，
 * 将固定格式事件写入 Ring Buffer。策略匹配和跨事件状态机留在用户态，
 * 以控制 verifier 复杂度并便于调整规则。
 */

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 file_open_sample_every = 1;

/* 该 rodata 参数由用户态在加载前设置；1 表示不抽样。 */

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
    __type(value, struct agent_context);
} agent_by_cgroup SEC(".maps");

#define MONITOR_AF_INET 2
#define MONITOR_AF_INET6 10

struct pending_openat {
    __u64 cgroup_id;
    __u32 agent_id;
    __s32 dirfd;
    char attempted_path[EVENT_FILENAME_LEN];
};

/* openat 入口保存用户指针内容；返回点只提交失败结果。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_openat);
} pending_openats SEC(".maps");

struct pending_connect {
    __u64 cgroup_id;
    __u32 agent_id;
    __s32 socket_fd;
    __u16 family;
    __u16 destination_port;
    __u8 destination_address[16];
};

/* connect 入口参数必须保存到返回点；用完整 pid_tgid 区分线程。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_connect);
} pending_connects SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *event;
    struct task_struct *task;
    struct agent_context *agent;
    __u64 cgroup_id;
    const char *filename;
    __u64 pid_tgid;
    __u64 uid_gid;

    cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent)
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
    event->header.agent_id = agent->agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    /* execve 的第一个参数是用户态 filename 指针。 */
    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->payload.filename,
                            sizeof(event->payload.filename), filename);

    /* 提交后，用户态的 Ring Buffer 回调会收到这条事件。 */
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* sched tracepoint 已确认 fork 成功，适合记录父子关系。 */
SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_fork_event *event;
    struct task_struct *task;
    struct agent_context *agent;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;

    cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent)
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
    event->header.agent_id = agent->agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    event->payload.parent_pid = ctx->parent_pid;
    event->payload.child_pid = ctx->child_pid;
    bpf_probe_read_kernel_str(
        event->payload.child_comm, sizeof(event->payload.child_comm),
        (const char *)ctx + (ctx->__data_loc_child_comm & 0xffff));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* 退出事件来自当前 task；exit_code_raw 保留内核原值供用户态解释。 */
SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct process_exit_event *event;
    struct task_struct *task;
    struct agent_context *agent;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;

    (void)ctx;
    cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent)
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
    event->header.agent_id = agent->agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));
    event->payload.exit_code_raw = BPF_CORE_READ(task, exit_code);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * LSM file_open 能拿到 struct file，因此可用 bpf_d_path 得到内核解析后的
 * 真实路径；它不覆盖“路径不存在”这种尚未形成 file 的失败打开。
 */
SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
    struct file_open_event *event;
    struct task_struct *task;
    struct agent_context *agent;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;
    long path_ret;

    /* 保留更早 LSM/BPF 程序给出的拒绝结果，不改变系统安全策略。 */
    if (ret)
        return ret;

    cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent)
        return 0;

    if (file_open_sample_every > 1) {
        __u64 sequence;

        sequence = __sync_fetch_and_add(&agent->file_open_count, 1);
        if (sequence % file_open_sample_every)
            return 0;
    }

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
    event->header.agent_id = agent->agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    event->payload.flags = BPF_CORE_READ(file, f_flags);
    path_ret = bpf_d_path((struct path *)&file->f_path, event->payload.path,
                          sizeof(event->payload.path));
    event->payload.path_ret = (__s32)path_ret;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* path_unlink 在删除发生前触发；事件表示尝试，不能单独证明删除成功。 */
SEC("lsm/path_unlink")
int BPF_PROG(handle_path_unlink, const struct path *dir,
             struct dentry *dentry, int ret)
{
    struct file_unlink_event *event;
    struct task_struct *task;
    struct agent_context *agent;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u64 uid_gid;
    const unsigned char *name;
    long path_ret;
    long name_ret;

    if (ret)
        return ret;

    cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &cgroup_id);
    if (!agent)
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
    event->header.agent_id = agent->agent_id;
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


/*
 * openat 入口/返回配对补足 LSM 看不到的失败打开。入口复制用户路径，避免
 * 返回时用户指针内容已经变化；key 使用 pid_tgid，避免线程互相覆盖。
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct pending_openat pending = {};
    const char *filename;
    struct agent_context *agent;
    __u64 pid_tgid;

    pending.cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &pending.cgroup_id);
    if (!agent)
        return 0;

    filename = (const char *)ctx->args[1];
    if (!filename ||
        bpf_probe_read_user_str(pending.attempted_path,
                                sizeof(pending.attempted_path),
                                filename) < 0)
        return 0;

    pending.agent_id = agent->agent_id;
    pending.dirfd = (__s32)ctx->args[0];
    pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_openats, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

/* 当前只提交 ret < 0 的结果，供重复失败规则使用并减少正常打开噪声。 */
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct file_open_result_event *event;
    struct pending_openat *pending;
    struct pending_openat saved;
    struct task_struct *task;
    __u64 pid_tgid;
    __u64 uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    pending = bpf_map_lookup_elem(&pending_openats, &pid_tgid);
    if (!pending)
        return 0;

    __builtin_memcpy(&saved, pending, sizeof(saved));
    bpf_map_delete_elem(&pending_openats, &pid_tgid);
    if (ctx->ret >= 0)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = saved.cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_FILE_OPEN_RESULT;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = saved.agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    event->payload.dirfd = saved.dirfd;
    event->payload.ret = (__s32)ctx->ret;
    __builtin_memcpy(event->payload.attempted_path, saved.attempted_path,
                     sizeof(event->payload.attempted_path));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* connect 的 sockaddr 只在入口可靠，先解析并暂存目标地址和端口。 */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct pending_connect pending = {};
    struct sockaddr *user_address;
    struct agent_context *agent;
    __u64 pid_tgid;
    __u16 family;

    pending.cgroup_id = bpf_get_current_cgroup_id();
    agent = bpf_map_lookup_elem(&agent_by_cgroup, &pending.cgroup_id);
    if (!agent)
        return 0;

    user_address = (struct sockaddr *)ctx->args[1];
    if (!user_address)
        return 0;
    if (bpf_probe_read_user(&family, sizeof(family),
                            &user_address->sa_family) < 0)
        return 0;

    pending.agent_id = agent->agent_id;
    pending.socket_fd = (__s32)ctx->args[0];
    pending.family = family;

    if (family == MONITOR_AF_INET) {
        struct sockaddr_in address = {};

        if (bpf_probe_read_user(&address, sizeof(address), user_address) < 0)
            return 0;
        pending.destination_port = bpf_ntohs(address.sin_port);
        __builtin_memcpy(pending.destination_address,
                         &address.sin_addr.s_addr,
                         sizeof(address.sin_addr.s_addr));
    } else if (family == MONITOR_AF_INET6) {
        struct sockaddr_in6 address = {};

        if (bpf_probe_read_user(&address, sizeof(address), user_address) < 0)
            return 0;
        pending.destination_port = bpf_ntohs(address.sin6_port);
        __builtin_memcpy(pending.destination_address,
                         &address.sin6_addr.in6_u.u6_addr8,
                         sizeof(pending.destination_address));
    } else {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_connects, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

/* 返回点补上结果码后再提交完整 CONNECT_RESULT。 */
SEC("tracepoint/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct pending_connect *pending;
    struct connect_event *event;
    struct task_struct *task;
    struct pending_connect saved;
    __u64 pid_tgid;
    __u64 uid_gid;

    pid_tgid = bpf_get_current_pid_tgid();
    pending = bpf_map_lookup_elem(&pending_connects, &pid_tgid);
    if (!pending)
        return 0;

    /* 先复制再删除，保证所有返回路径都清理线程暂存状态。 */
    __builtin_memcpy(&saved, pending, sizeof(saved));
    bpf_map_delete_elem(&pending_connects, &pid_tgid);

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = bpf_get_current_uid_gid();
    task = (struct task_struct *)bpf_get_current_task_btf();

    event->header.timestamp_ns = bpf_ktime_get_ns();
    event->header.cgroup_id = saved.cgroup_id;
    event->header.size = sizeof(*event);
    event->header.event_type = EVENT_CONNECT_RESULT;
    event->header.pid = pid_tgid >> 32;
    event->header.tid = (__u32)pid_tgid;
    event->header.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event->header.uid = (__u32)uid_gid;
    event->header.agent_id = saved.agent_id;
    bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));

    event->payload.socket_fd = saved.socket_fd;
    event->payload.ret = (__s32)ctx->ret;
    event->payload.family = saved.family;
    event->payload.destination_port = saved.destination_port;
    __builtin_memcpy(event->payload.destination_address,
                     saved.destination_address,
                     sizeof(event->payload.destination_address));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

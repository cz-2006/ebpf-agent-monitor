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

/* GPL 许可证使程序可以调用受 GPL 限制的 BPF helper，例如 bpf_d_path。 */
char LICENSE[] SEC("license") = "GPL";

/* 该只读配置由 skeleton 在加载前写入；1 表示每次 FILE_OPEN 都采集。 */
const volatile __u32 file_open_sample_every = 1;

/*
 * 内核态通过 Ring Buffer 把事件发送给用户态。256 KiB 是共享缓冲区容量，
 * reserve 失败时当前事件会被丢弃，但不会阻塞被监控进程。
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * 受控启动器预先注册 cgroup；未注册 cgroup 的事件在每个探针开头直接忽略。
 * 这既完成 Agent 归属，也从内核源头过滤终端、VS Code 和系统服务等噪声。
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u64);
    __type(value, struct agent_context);
} agent_by_cgroup SEC(".maps");

#define MONITOR_AF_INET 2
#define MONITOR_AF_INET6 10

struct pending_openat {
    __u64 cgroup_id; /* 入口时保存，避免返回前映射被用户态删除。 */
    __u32 agent_id;
    __s32 dirfd;     /* AT_FDCWD 或作为相对路径基准的目录 fd。 */
    char attempted_path[EVENT_FILENAME_LEN]; /* syscall 原始字符串的入口副本。 */
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
    __u16 family; /* 只接受 IPv4/IPv6，其他 sockaddr 类型不提交。 */
    __u16 destination_port; /* 入口时转换为主机字节序。 */
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

    /* execve 入口仍属于旧进程映像，因此 comm 可能还是 monitor 或 bash。 */
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
    /* __data_loc 的低 16 位是动态字符串相对 tracepoint 记录的偏移。 */
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

        /* 原子递增保证同一 cgroup 内并发线程不会使用重复序号。 */
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

    /* CO-RE 访问允许字段偏移在不同内核版本上由 libbpf 重定位。 */
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

    /* 和 file_open 一样，本程序是观察器，不覆盖更早安全模块的决定。 */
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

    /* hook 分开提供父目录 path 与目标 dentry，完整路径由用户态拼接。 */
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
    /* BPF_ANY 允许覆盖同一线程异常遗留的旧入口，避免状态永久失配。 */
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
    /* 成功打开将由 LSM FILE_OPEN 提供真实路径，此处不重复上报。 */
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
        /* sockaddr 端口为网络字节序，日志统一保存为主机字节序。 */
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
    /* 非阻塞 connect 常见 -EINPROGRESS；它表示仍在进行，并非最终失败。 */
    event->payload.ret = (__s32)ctx->ret;
    event->payload.family = saved.family;
    event->payload.destination_port = saved.destination_port;
    __builtin_memcpy(event->payload.destination_address,
                     saved.destination_address,
                     sizeof(event->payload.destination_address));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

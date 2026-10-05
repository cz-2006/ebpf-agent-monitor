#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <grp.h>
#include <pwd.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "detector.h"
#include "events.h"
#include "monitor.skel.h"

/*
 * 用户态控制面与 Collector：解析多个 Agent 配置、加载并附加 BPF、创建
 * 独立 cgroup、以 sudo 调用者身份受控启动目标、消费 Ring Buffer、驱动
 * detector/CPU sampler，并在根进程退出后等待整个 cgroup 排空。
 */

#define CGROUP_BASE "/sys/fs/cgroup/ebpf-agent-monitor"
#define MAX_AGENTS 16
#define EVENT_MASK_PROCESS (1U << 0)
#define EVENT_MASK_FILE (1U << 1)
#define EVENT_MASK_NETWORK (1U << 2)
#define EVENT_MASK_ALL (EVENT_MASK_PROCESS | EVENT_MASK_FILE | EVENT_MASK_NETWORK)
static volatile sig_atomic_t stop;
static int quiet_events;
static int hide_runtime_noise;
static unsigned int event_mask = EVENT_MASK_ALL;
static __u32 file_open_sample_every = 1;

struct run_identity {
    uid_t uid;
    gid_t gid;
    char user[256];
    char home[PATH_MAX];
};

struct agent_process {
    /* 一条 --agent 配置在启动、运行和清理阶段需要保留的全部状态。 */
    __u32 agent_id;
    __u64 cgroup_id;
    char cgroup_path[PATH_MAX];
    char **command;
    pid_t child;
    int gate[2];
    int ready[2];
    int status;
    int cgroup_created;
    int registered;
    int reaped;
    int root_exit_reported;
    int drained;
    enum detector_shell_policy shell_policy;
    int shell_policy_set;
    const char *sensitive_path;
    const char *workspace_path;
    const char *runtime_paths[DETECTOR_MAX_RUNTIME_DIRS];
    size_t runtime_path_count;
    __u32 failed_open_threshold;
    __u32 failed_open_window_ms;
    __u32 cpu_sample_ms;
    __u32 cpu_threshold_percent;
};

static void on_signal(int sig) { (void)sig; stop = 1; }

static void on_resource_sample(void *context,
                               const struct resource_cpu_sample *sample)
{
    detector_process_cpu_sample(context, sample);
}

static void print_header(const struct monitor_event_header *h,
                         const char *event_name)
{
    printf("timestamp_ns=%" PRIu64 " cgroup_id=%" PRIu64
           " event=%s pid=%u tid=%u ppid=%u uid=%u agent_id=%u comm=%.*s",
           (uint64_t)h->timestamp_ns, (uint64_t)h->cgroup_id, event_name,
           h->pid, h->tid, h->ppid, h->uid, h->agent_id,
           EVENT_COMM_LEN, h->comm);
}

/* 只过滤普通文件事件的展示；检测器仍接收完整事件。 */
static int hide_runtime_file_event(const struct monitor_event_header *h,
                                   const char *path)
{
    if (!hide_runtime_noise)
        return 0;
    if (!strncmp(h->comm, "bwrap", EVENT_COMM_LEN) ||
        !strncmp(h->comm, "codex-linux-san", EVENT_COMM_LEN))
        return 1;
    return path &&
           !strncmp(path, "/tmp/codex-bwrap-synthetic-mount-targets-",
                    sizeof("/tmp/codex-bwrap-synthetic-mount-targets-") - 1);
}

static int on_event(void *ctx, void *data, size_t size)
{
    const struct monitor_event_header *h = data;
    struct detector *detector = ctx;
    if (size < sizeof(*h) || h->size != size) {
        fprintf(stderr, "discarding malformed event: size=%zu\n", size);
        return 0;
    }

    /* size 双重校验防止协议版本不一致时按错误结构读取 Ring Buffer。 */
    switch (h->event_type) {
    case EVENT_EXEC_ATTEMPT: {
        const struct exec_event *event = data;
        if (size != sizeof(*event))
            break;
        if (!quiet_events) {
            print_header(h, "EXEC_ATTEMPT");
            printf(" filename=%.*s\n", EVENT_FILENAME_LEN,
                   event->payload.filename);
            fflush(stdout);
        }
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_PROCESS_FORK: {
        const struct process_fork_event *event = data;
        if (size != sizeof(*event))
            break;
        if (!quiet_events) {
            print_header(h, "PROCESS_FORK");
            printf(" parent_pid=%u child_pid=%u child_comm=%.*s\n",
                   event->payload.parent_pid, event->payload.child_pid,
                   EVENT_COMM_LEN, event->payload.child_comm);
            fflush(stdout);
        }
        return 0;
    }
    case EVENT_PROCESS_EXIT: {
        const struct process_exit_event *event = data;
        if (size != sizeof(*event))
            break;
        if (!quiet_events) {
            print_header(h, "PROCESS_EXIT");
            printf(" exit_code_raw=%d\n", event->payload.exit_code_raw);
            fflush(stdout);
        }
        return 0;
    }
    case EVENT_FILE_OPEN: {
        const struct file_open_event *event = data;
        if (size != sizeof(*event))
            break;
        if (!quiet_events &&
            !hide_runtime_file_event(h, event->payload.path)) {
            print_header(h, "FILE_OPEN");
            printf(" path=%.*s flags=%u path_ret=%d\n",
                   EVENT_FILENAME_LEN, event->payload.path,
                   event->payload.flags, event->payload.path_ret);
            fflush(stdout);
        }
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_FILE_UNLINK_ATTEMPT: {
        const struct file_unlink_event *event = data;
        if (size != sizeof(*event))
            break;
        size_t dir_len;

        if (!quiet_events &&
            !hide_runtime_file_event(h, event->payload.dir_path)) {
            print_header(h, "FILE_UNLINK_ATTEMPT");
            dir_len = strnlen(event->payload.dir_path, EVENT_FILENAME_LEN);
            printf(" path=%.*s%s%.*s path_ret=%d name_ret=%d\n",
                   EVENT_FILENAME_LEN, event->payload.dir_path,
                   dir_len && event->payload.dir_path[dir_len - 1] == '/'
                       ? "" : "/",
                   EVENT_FILENAME_LEN, event->payload.name,
                   event->payload.path_ret, event->payload.name_ret);
            fflush(stdout);
        }
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_FILE_OPEN_RESULT: {
        const struct file_open_result_event *event = data;

        if (size != sizeof(*event))
            break;
        if (!quiet_events &&
            !hide_runtime_file_event(h, event->payload.attempted_path)) {
            print_header(h, "FILE_OPEN_RESULT");
            printf(" dirfd=%d attempted_path=%.*s ret=%d"
                   " path_basis=syscall_input\n",
                   event->payload.dirfd, EVENT_FILENAME_LEN,
                   event->payload.attempted_path, event->payload.ret);
            fflush(stdout);
        }
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_CONNECT_RESULT: {
        const struct connect_event *event = data;
        char address[INET6_ADDRSTRLEN] = "<invalid>";
        int address_family;

        if (size != sizeof(*event))
            break;
        if (!quiet_events) {
            address_family = event->payload.family == AF_INET ? AF_INET :
                             event->payload.family == AF_INET6 ? AF_INET6 : 0;
            if (address_family)
                (void)inet_ntop(address_family,
                                event->payload.destination_address,
                                address, sizeof(address));
            print_header(h, "CONNECT_RESULT");
            printf(" socket_fd=%d family=%u dst_ip=%s dst_port=%u ret=%d\n",
                   event->payload.socket_fd, event->payload.family, address,
                   event->payload.destination_port, event->payload.ret);
            fflush(stdout);
        }
        return 0;
    }
    default:
        break;
    }

    fprintf(stderr, "discarding unsupported event: type=%u size=%zu\n",
            h->event_type, size);
    return 0;
}

static int parse_unsigned(const char *text, unsigned long *value)
{
    char *end;

    if (!text || !*text)
        return -1;
    errno = 0;
    *value = strtoul(text, &end, 10);
    return errno || *end ? -1 : 0;
}

/* 只接受经过 passwd 数据库核验的 sudo 调用者，避免 Agent 继续以 root 运行。 */
static int read_sudo_identity(struct run_identity *identity)
{
    const char *uid_text = getenv("SUDO_UID");
    const char *gid_text = getenv("SUDO_GID");
    const char *user = getenv("SUDO_USER");
    struct passwd *entry;
    unsigned long uid_value, gid_value;

    if (parse_unsigned(uid_text, &uid_value) ||
        parse_unsigned(gid_text, &gid_value) ||
        !user || !*user || !uid_value ||
        (uid_t)uid_value != uid_value || (gid_t)gid_value != gid_value) {
        fprintf(stderr, "valid non-root SUDO_UID/SUDO_GID/SUDO_USER required\n");
        return -1;
    }

    errno = 0;
    entry = getpwnam(user);
    if (!entry || entry->pw_uid != (uid_t)uid_value) {
        fprintf(stderr, "sudo user does not match the passwd database\n");
        return -1;
    }
    if (snprintf(identity->user, sizeof(identity->user), "%s", entry->pw_name)
        >= (int)sizeof(identity->user) ||
        snprintf(identity->home, sizeof(identity->home), "%s", entry->pw_dir)
        >= (int)sizeof(identity->home)) {
        fprintf(stderr, "sudo user metadata is too long\n");
        return -1;
    }

    identity->uid = (uid_t)uid_value;
    identity->gid = (gid_t)gid_value;
    return 0;
}

/* 将 process,file,network 列表转换为探针自动加载位图。 */
static int parse_event_mask(const char *text, unsigned int *mask)
{
    char copy[64];
    char *save = NULL;
    char *token;
    unsigned int parsed = 0;

    if (!text || strlen(text) >= sizeof(copy))
        return -1;
    strcpy(copy, text);
    for (token = strtok_r(copy, ",", &save); token;
         token = strtok_r(NULL, ",", &save)) {
        unsigned int bit;

        if (!strcmp(token, "process"))
            bit = EVENT_MASK_PROCESS;
        else if (!strcmp(token, "file"))
            bit = EVENT_MASK_FILE;
        else if (!strcmp(token, "network"))
            bit = EVENT_MASK_NETWORK;
        else
            return -1;
        if (parsed & bit)
            return -1;
        parsed |= bit;
    }
    if (!parsed)
        return -1;
    *mask = parsed;
    return 0;
}

static void configure_event_autoload(struct monitor_bpf *skel)
{
    int process = !!(event_mask & EVENT_MASK_PROCESS);
    int file = !!(event_mask & EVENT_MASK_FILE);
    int network = !!(event_mask & EVENT_MASK_NETWORK);

    bpf_program__set_autoload(skel->progs.handle_execve, process);
    bpf_program__set_autoload(skel->progs.handle_process_fork, process);
    bpf_program__set_autoload(skel->progs.handle_process_exit, process);
    bpf_program__set_autoload(skel->progs.handle_file_open, file);
    bpf_program__set_autoload(skel->progs.handle_path_unlink, file);
    bpf_program__set_autoload(skel->progs.handle_openat_enter, file);
    bpf_program__set_autoload(skel->progs.handle_openat_exit, file);
    bpf_program__set_autoload(skel->progs.handle_connect_enter, network);
    bpf_program__set_autoload(skel->progs.handle_connect_exit, network);
}

static int parse_id(const char *text, __u32 *id)
{
    char *end;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !*text || *end || !value || value > UINT32_MAX)
        return -1;
    *id = (__u32)value;
    return 0;
}

static int create_cgroup(char *path, size_t size, __u32 id, int *made_base)
{
    int n;
    if (!mkdir(CGROUP_BASE, 0755))
        *made_base = 1;
    else if (errno != EEXIST) {
        perror("mkdir cgroup base");
        return -1;
    }
    n = snprintf(path, size, "%s/agent-%u-%ld",
                 CGROUP_BASE, id, (long)getpid());
    if (n < 0 || (size_t)n >= size || mkdir(path, 0755)) {
        perror("mkdir agent cgroup");
        return -1;
    }
    return 0;
}

static int cgroup_id(const char *path, __u64 *id)
{
    struct stat st;
    if (stat(path, &st)) {
        perror("stat agent cgroup");
        return -1;
    }
    /* cgroup v2 的 kernfs inode 号对应 bpf_get_current_cgroup_id()。 */
    *id = (__u64)st.st_ino;
    return 0;
}

static int move_and_verify(const char *path, pid_t pid)
{
    char file_path[PATH_MAX];
    FILE *file;
    long found;
    int n;

    n = snprintf(file_path, sizeof(file_path), "%s/cgroup.procs", path);
    if (n < 0 || (size_t)n >= sizeof(file_path))
        return -1;
    file = fopen(file_path, "w");
    if (!file) {
        perror("open cgroup.procs");
        return -1;
    }
    if (fprintf(file, "%ld\n", (long)pid) < 0 || fclose(file)) {
        perror("write cgroup.procs");
        return -1;
    }

    file = fopen(file_path, "r");
    if (!file) {
        perror("verify cgroup.procs");
        return -1;
    }
    while (fscanf(file, "%ld", &found) == 1) {
        if (found == (long)pid) {
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    fprintf(stderr, "child is not in the Agent cgroup\n");
    return -1;
}

/* cgroup.events 的 populated=0 才表示根进程及其所有后代都已退出。 */
static int cgroup_is_populated(const char *path, int *populated)
{
    char file_path[PATH_MAX];
    char key[64];
    long value;
    FILE *file;
    int n;

    n = snprintf(file_path, sizeof(file_path), "%s/cgroup.events", path);
    if (n < 0 || (size_t)n >= sizeof(file_path))
        return -1;
    file = fopen(file_path, "r");
    if (!file) {
        perror("open cgroup.events");
        return -1;
    }
    while (fscanf(file, "%63s %ld", key, &value) == 2) {
        if (!strcmp(key, "populated")) {
            fclose(file);
            *populated = !!value;
            return 0;
        }
    }
    fclose(file);
    fprintf(stderr, "cgroup.events has no populated field: %s\n", path);
    return -1;
}

/*
 * 第一阶段在原 cgroup 中完成可能访问 NSS/组文件的 initgroups；
 * 第二阶段等待父进程迁移并登记 cgroup 后，再放弃 root 并 exec。
 */
/*
 * 两阶段门控：先在原 cgroup 完成 initgroups 并通知父进程；父进程迁移、
 * 注册映射后放行；子进程再永久降权并 exec。这样既不会漏掉首个业务 exec，
 * 也不会把 root 身份的 NSS 准备访问归入 Agent。
 */
static void prepared_gated_exec(int gate_fd, int ready_fd, char **command,
                                const struct run_identity *identity)
{
    char token;
    ssize_t n;

    if (initgroups(identity->user, identity->gid)) {
        perror("prepare Agent supplementary groups");
        n = write(ready_fd, "e", 1);
        (void)n;
        close(ready_fd);
        _exit(126);
    }
    if (write(ready_fd, "r", 1) != 1) {
        perror("notify Agent preparation");
        close(ready_fd);
        _exit(126);
    }
    close(ready_fd);

    do { n = read(gate_fd, &token, 1); } while (n < 0 && errno == EINTR);
    close(gate_fd);
    if (n != 1 || token != 'x')
        _exit(125);

    /* 进入 Agent cgroup 后，彻底放弃 root 的组、有效及保存用户身份。 */
    if (setresgid(identity->gid, identity->gid, identity->gid) ||
        setresuid(identity->uid, identity->uid, identity->uid)) {
        perror("drop Agent privileges");
        _exit(126);
    }
    if (setenv("HOME", identity->home, 1) ||
        setenv("USER", identity->user, 1) ||
        setenv("LOGNAME", identity->user, 1)) {
        perror("set Agent environment");
        _exit(126);
    }

    execvp(command[0], command);
    perror("execvp");
    _exit(127);
}

static void print_usage(const char *program)
{
    fprintf(stderr,
            "usage: %s [--quiet-events] [--hide-runtime-noise] [--events LIST]"
            " [--file-open-sample-every N] --agent ID"
            " [--shell-policy deny|audit|allow] [--deny-shell]"
            " [--sensitive-path DIR] [--workspace DIR] [--runtime-path DIR]"
            " [--failed-open-threshold N]"
            " [--failed-open-window-ms MS]"
            " [--cpu-sample-ms MS] [--cpu-threshold-percent PERCENT]"
            " -- COMMAND [ARG ...]"
            " [--next --agent ID [POLICY ...] -- COMMAND [ARG ...]]\n",
            program);
}

static int parse_shell_policy(const char *value,
                              enum detector_shell_policy *policy)
{
    if (!strcmp(value, "deny"))
        *policy = DETECTOR_SHELL_DENY;
    else if (!strcmp(value, "audit"))
        *policy = DETECTOR_SHELL_AUDIT;
    else if (!strcmp(value, "allow"))
        *policy = DETECTOR_SHELL_ALLOW;
    else
        return -1;
    return 0;
}

static int parse_agents(int argc, char **argv, struct agent_process *agents,
                        size_t *agent_count)
{
    int index = 1;
    size_t count = 0;

    while (index < argc) {
        if (!strcmp(argv[index], "--quiet-events")) {
            if (quiet_events)
                return -1;
            quiet_events = 1;
            index++;
        } else if (!strcmp(argv[index], "--hide-runtime-noise")) {
            if (hide_runtime_noise)
                return -1;
            hide_runtime_noise = 1;
            index++;
        } else if (!strcmp(argv[index], "--events")) {
            if (index + 1 >= argc ||
                parse_event_mask(argv[index + 1], &event_mask))
                return -1;
            index += 2;
        } else if (!strcmp(argv[index], "--file-open-sample-every")) {
            unsigned long value;

            if (index + 1 >= argc ||
                parse_unsigned(argv[index + 1], &value) ||
                !value || value > UINT32_MAX)
                return -1;
            file_open_sample_every = (__u32)value;
            index += 2;
        } else {
            break;
        }
    }

    while (index < argc) {
        int command_start;
        int separator;
        int option_index;
        size_t previous;

        if (count >= MAX_AGENTS || strcmp(argv[index], "--agent") ||
            index + 3 >= argc ||
            parse_id(argv[index + 1], &agents[count].agent_id)) {
            return -1;
        }
        for (previous = 0; previous < count; previous++) {
            if (agents[previous].agent_id == agents[count].agent_id) {
                fprintf(stderr, "duplicate agent id: %u\n",
                        agents[count].agent_id);
                return -1;
            }
        }

        option_index = index + 2;
        while (option_index < argc && strcmp(argv[option_index], "--")) {
            if (!strcmp(argv[option_index], "--deny-shell")) {
                if (agents[count].shell_policy_set)
                    return -1;
                agents[count].shell_policy = DETECTOR_SHELL_DENY;
                agents[count].shell_policy_set = 1;
            } else if (!strcmp(argv[option_index], "--shell-policy")) {
                if (agents[count].shell_policy_set ||
                    option_index + 1 >= argc ||
                    parse_shell_policy(argv[++option_index],
                                       &agents[count].shell_policy))
                    return -1;
                agents[count].shell_policy_set = 1;
            } else if (!strcmp(argv[option_index], "--sensitive-path")) {
                if (agents[count].sensitive_path ||
                    option_index + 1 >= argc)
                    return -1;
                agents[count].sensitive_path = argv[++option_index];
            } else if (!strcmp(argv[option_index], "--workspace")) {
                if (agents[count].workspace_path ||
                    option_index + 1 >= argc)
                    return -1;
                agents[count].workspace_path = argv[++option_index];
            } else if (!strcmp(argv[option_index], "--runtime-path")) {
                if (agents[count].runtime_path_count >=
                        DETECTOR_MAX_RUNTIME_DIRS ||
                    option_index + 1 >= argc)
                    return -1;
                agents[count].runtime_paths[agents[count].runtime_path_count++] =
                    argv[++option_index];
            } else if (!strcmp(argv[option_index],
                               "--failed-open-threshold")) {
                unsigned long value;

                if (agents[count].failed_open_threshold ||
                    option_index + 1 >= argc ||
                    parse_unsigned(argv[++option_index], &value) ||
                    !value || value > UINT32_MAX)
                    return -1;
                agents[count].failed_open_threshold = (__u32)value;
            } else if (!strcmp(argv[option_index],
                               "--failed-open-window-ms")) {
                unsigned long value;

                if (agents[count].failed_open_window_ms ||
                    option_index + 1 >= argc ||
                    parse_unsigned(argv[++option_index], &value) ||
                    !value || value > UINT32_MAX)
                    return -1;
                agents[count].failed_open_window_ms = (__u32)value;
            } else if (!strcmp(argv[option_index], "--cpu-sample-ms")) {
                unsigned long value;

                if (agents[count].cpu_sample_ms ||
                    option_index + 1 >= argc ||
                    parse_unsigned(argv[++option_index], &value) ||
                    value < 100 || value > UINT32_MAX)
                    return -1;
                agents[count].cpu_sample_ms = (__u32)value;
            } else if (!strcmp(argv[option_index],
                               "--cpu-threshold-percent")) {
                unsigned long value;

                if (agents[count].cpu_threshold_percent ||
                    option_index + 1 >= argc ||
                    parse_unsigned(argv[++option_index], &value) ||
                    !value || value > 10000)
                    return -1;
                agents[count].cpu_threshold_percent = (__u32)value;
            } else {
                return -1;
            }
            option_index++;
        }
        if (option_index == argc)
            return -1;

        if (!!agents[count].failed_open_threshold !=
            !!agents[count].failed_open_window_ms ||
            !!agents[count].cpu_sample_ms !=
            !!agents[count].cpu_threshold_percent)
            return -1;
        if (file_open_sample_every > 1 && agents[count].sensitive_path) {
            fprintf(stderr,
                    "FILE_OPEN sampling is incompatible with --sensitive-path\n");
            return -1;
        }

        command_start = option_index + 1;
        separator = command_start;
        while (separator < argc && strcmp(argv[separator], "--next"))
            separator++;
        if (separator == command_start)
            return -1;

        agents[count].command = &argv[command_start];
        count++;
        if (separator == argc)
            break;

        argv[separator] = NULL;
        index = separator + 1;
        if (index == argc)
            return -1;
    }

    if (!count)
        return -1;
    *agent_count = count;
    return 0;
}

static int status_result(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 1;
}

static void print_root_exit(const struct agent_process *agent)
{
    if (WIFEXITED(agent->status)) {
        printf("event=agent_root_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld exit_code=%d\n",
               agent->agent_id, (uint64_t)agent->cgroup_id,
               (long)agent->child, WEXITSTATUS(agent->status));
    } else if (WIFSIGNALED(agent->status)) {
        printf("event=agent_root_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld signal=%d\n",
               agent->agent_id, (uint64_t)agent->cgroup_id,
               (long)agent->child, WTERMSIG(agent->status));
    }
    fflush(stdout);
}

static void print_agent_drained(const struct agent_process *agent)
{
    printf("event=agent_cgroup_drained agent_id=%u cgroup_id=%" PRIu64
           " root_pid=%ld\n",
           agent->agent_id, (uint64_t)agent->cgroup_id, (long)agent->child);
    if (WIFEXITED(agent->status)) {
        printf("event=agent_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld exit_code=%d basis=cgroup_empty\n",
               agent->agent_id, (uint64_t)agent->cgroup_id,
               (long)agent->child, WEXITSTATUS(agent->status));
    } else if (WIFSIGNALED(agent->status)) {
        printf("event=agent_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld signal=%d basis=cgroup_empty\n",
               agent->agent_id, (uint64_t)agent->cgroup_id,
               (long)agent->child, WTERMSIG(agent->status));
    }
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct run_identity identity = {0};
    struct agent_process agents[MAX_AGENTS] = {0};
    struct detector detector;
    struct resource_sampler resource_sampler;
    size_t agent_count = 0;
    size_t index;
    size_t remaining;
    int map_fd = -1;
    int base_created = 0;
    int terminate_sent = 0;
    int result = 1;
    int err = 0;

    for (index = 0; index < MAX_AGENTS; index++) {
        agents[index].child = -1;
        agents[index].gate[0] = agents[index].gate[1] = -1;
        agents[index].ready[0] = agents[index].ready[1] = -1;
    }

    if (parse_agents(argc, argv, agents, &agent_count)) {
        print_usage(argv[0]);
        return 2;
    }
    detector_init(&detector);
    resource_sampler_init(&resource_sampler);
    for (index = 0; index < agent_count; index++) {
        if (detector_add_agent(&detector, agents[index].agent_id,
                               agents[index].shell_policy,
                               agents[index].sensitive_path,
                               agents[index].workspace_path,
                               agents[index].runtime_paths,
                               agents[index].runtime_path_count,
                               agents[index].failed_open_threshold,
                               agents[index].failed_open_window_ms,
                               agents[index].cpu_threshold_percent)) {
            fprintf(stderr, "failed to configure detector\n");
            return 1;
        }
    }
    if (geteuid()) {
        fprintf(stderr, "controlled launch requires root privileges\n");
        return 1;
    }
    if (read_sudo_identity(&identity))
        return 1;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    skel = monitor_bpf__open();
    if (skel) {
        configure_event_autoload(skel);
        skel->rodata->file_open_sample_every = file_open_sample_every;
    }
    if (!skel || (err = monitor_bpf__load(skel)) ||
        (err = monitor_bpf__attach(skel))) {
        fprintf(stderr, "failed to open/load/attach BPF program: %d\n", err);
        goto cleanup;
    }
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                          on_event, &detector, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }
    map_fd = bpf_map__fd(skel->maps.agent_by_cgroup);

    /*
     * 每个孩子先在原 cgroup 完成 initgroups。全部孩子都完成迁移和登记后，
     * 父进程才统一放行，避免任一 Agent 提前产生业务事件。
     */
    for (index = 0; index < agent_count; index++) {
        struct agent_process *agent = &agents[index];
        char prepared;
        ssize_t count_read;

        if (create_cgroup(agent->cgroup_path, sizeof(agent->cgroup_path),
                          agent->agent_id, &base_created))
            goto cleanup;
        agent->cgroup_created = 1;
        if (cgroup_id(agent->cgroup_path, &agent->cgroup_id))
            goto cleanup;
        {
            struct agent_context context = {
                .agent_id = agent->agent_id,
            };

            if (bpf_map_update_elem(map_fd, &agent->cgroup_id,
                                    &context, BPF_ANY)) {
                perror("register Agent cgroup");
                goto cleanup;
            }
        }
        agent->registered = 1;

        if (pipe2(agent->gate, O_CLOEXEC) ||
            pipe2(agent->ready, O_CLOEXEC) ||
            (agent->child = fork()) < 0) {
            perror("create prepared gated child");
            goto cleanup;
        }
        if (!agent->child) {
            size_t other;

            for (other = 0; other <= index; other++) {
                if (other != index) {
                    if (agents[other].gate[0] >= 0)
                        close(agents[other].gate[0]);
                    if (agents[other].gate[1] >= 0)
                        close(agents[other].gate[1]);
                    if (agents[other].ready[0] >= 0)
                        close(agents[other].ready[0]);
                    if (agents[other].ready[1] >= 0)
                        close(agents[other].ready[1]);
                }
            }
            close(agent->gate[1]);
            close(agent->ready[0]);
            prepared_gated_exec(agent->gate[0], agent->ready[1],
                                agent->command, &identity);
        }

        close(agent->gate[0]);
        agent->gate[0] = -1;
        close(agent->ready[1]);
        agent->ready[1] = -1;

        do {
            count_read = read(agent->ready[0], &prepared, 1);
        } while (count_read < 0 && errno == EINTR);
        close(agent->ready[0]);
        agent->ready[0] = -1;
        if (count_read != 1 || prepared != 'r') {
            fprintf(stderr, "Agent %u identity preparation failed\n",
                    agent->agent_id);
            goto cleanup;
        }

        if (move_and_verify(agent->cgroup_path, agent->child))
            goto cleanup;
        if (agent->cpu_sample_ms &&
            resource_sampler_add_agent(&resource_sampler, agent->agent_id,
                                       agent->cgroup_id, agent->cgroup_path,
                                       agent->cpu_sample_ms)) {
            perror("initialize Agent CPU sampler");
            goto cleanup;
        }
        printf("event=agent_register agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld run_uid=%lu run_gid=%lu"
               " basis=controlled_launch\n",
               agent->agent_id, (uint64_t)agent->cgroup_id,
               (long)agent->child, (unsigned long)identity.uid,
               (unsigned long)identity.gid);
        fflush(stdout);
    }

    for (index = 0; index < agent_count; index++) {
        if (write(agents[index].gate[1], "x", 1) != 1) {
            perror("release Agent");
            goto cleanup;
        }
        close(agents[index].gate[1]);
        agents[index].gate[1] = -1;
    }

    remaining = agent_count;
    while (remaining) {
        int newly_reaped = 0;
        int newly_drained = 0;

        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring buffer poll failed: %d\n", err);
            goto cleanup;
        }

        resource_sampler_collect_due(&resource_sampler, on_resource_sample,
                                     &detector);

        for (index = 0; index < agent_count; index++) {
            pid_t waited;

            if (agents[index].reaped)
                continue;
            waited = waitpid(agents[index].child, &agents[index].status,
                             WNOHANG);
            if (waited == agents[index].child) {
                agents[index].reaped = 1;
                newly_reaped = 1;
            } else if (waited < 0 && errno != EINTR) {
                perror("waitpid");
                goto cleanup;
            }
        }

        if (newly_reaped) {
            (void)ring_buffer__consume(rb);
            for (index = 0; index < agent_count; index++) {
                if (agents[index].reaped &&
                    !agents[index].root_exit_reported) {
                    print_root_exit(&agents[index]);
                    agents[index].root_exit_reported = 1;
                }
            }
        }

        for (index = 0; index < agent_count; index++) {
            int populated;

            if (!agents[index].reaped || agents[index].drained)
                continue;
            if (cgroup_is_populated(agents[index].cgroup_path, &populated))
                goto cleanup;
            if (!populated) {
                agents[index].drained = 1;
                remaining--;
                newly_drained = 1;
            }
        }

        if (newly_drained) {
            (void)ring_buffer__consume(rb);
            for (index = 0; index < agent_count; index++) {
                if (!agents[index].drained || agents[index].child < 0)
                    continue;
                resource_sampler_collect_agent(
                    &resource_sampler, agents[index].agent_id,
                    on_resource_sample, &detector);
                print_agent_drained(&agents[index]);
                agents[index].child = -agents[index].child;
            }
        }

        if (stop && !terminate_sent) {
            for (index = 0; index < agent_count; index++) {
                if (!agents[index].reaped && agents[index].child > 0)
                    (void)kill(agents[index].child, SIGTERM);
            }
            terminate_sent = 1;
        }
    }

    result = 0;
    for (index = 0; index < agent_count; index++) {
        int agent_result = status_result(agents[index].status);
        if (!result && agent_result)
            result = agent_result;
    }

cleanup:
    for (index = 0; index < agent_count; index++) {
        struct agent_process *agent = &agents[index];
        pid_t child_pid = agent->child < 0 ? -agent->child : agent->child;

        if (agent->gate[0] >= 0)
            close(agent->gate[0]);
        if (agent->gate[1] >= 0)
            close(agent->gate[1]);
        if (agent->ready[0] >= 0)
            close(agent->ready[0]);
        if (agent->ready[1] >= 0)
            close(agent->ready[1]);

        if (child_pid > 0 && !agent->reaped) {
            (void)kill(child_pid, SIGKILL);
            while (waitpid(child_pid, &agent->status, 0) < 0 &&
                   errno == EINTR) {
            }
        }
        if (agent->registered &&
            bpf_map_delete_elem(map_fd, &agent->cgroup_id) &&
            errno != ENOENT) {
            perror("unregister Agent cgroup");
        }
        if (agent->cgroup_created && rmdir(agent->cgroup_path))
            perror("remove Agent cgroup");
    }
    if (base_created && rmdir(CGROUP_BASE) && errno != ENOTEMPTY)
        perror("remove cgroup base");

    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return result;
}

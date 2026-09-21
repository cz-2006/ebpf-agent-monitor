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

#define CGROUP_BASE "/sys/fs/cgroup/ebpf-agent-monitor"
#define MAX_AGENTS 16
static volatile sig_atomic_t stop;

struct run_identity {
    uid_t uid;
    gid_t gid;
    char user[256];
    char home[PATH_MAX];
};

struct agent_process {
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
    int deny_shell;
    const char *sensitive_path;
    const char *workspace_path;
    __u32 failed_open_threshold;
    __u32 failed_open_window_ms;
};

static void on_signal(int sig) { (void)sig; stop = 1; }

static void print_header(const struct monitor_event_header *h,
                         const char *event_name)
{
    printf("timestamp_ns=%" PRIu64 " cgroup_id=%" PRIu64
           " event=%s pid=%u tid=%u ppid=%u uid=%u agent_id=%u comm=%.*s",
           (uint64_t)h->timestamp_ns, (uint64_t)h->cgroup_id, event_name,
           h->pid, h->tid, h->ppid, h->uid, h->agent_id,
           EVENT_COMM_LEN, h->comm);
}

static int on_event(void *ctx, void *data, size_t size)
{
    const struct monitor_event_header *h = data;
    struct detector *detector = ctx;
    if (size < sizeof(*h) || h->size != size) {
        fprintf(stderr, "discarding malformed event: size=%zu\n", size);
        return 0;
    }

    switch (h->event_type) {
    case EVENT_EXEC_ATTEMPT: {
        const struct exec_event *event = data;
        if (size != sizeof(*event))
            break;
        print_header(h, "EXEC_ATTEMPT");
        printf(" filename=%.*s\n", EVENT_FILENAME_LEN,
               event->payload.filename);
        fflush(stdout);
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_PROCESS_FORK: {
        const struct process_fork_event *event = data;
        if (size != sizeof(*event))
            break;
        print_header(h, "PROCESS_FORK");
        printf(" parent_pid=%u child_pid=%u child_comm=%.*s\n",
               event->payload.parent_pid, event->payload.child_pid,
               EVENT_COMM_LEN, event->payload.child_comm);
        fflush(stdout);
        return 0;
    }
    case EVENT_PROCESS_EXIT: {
        const struct process_exit_event *event = data;
        if (size != sizeof(*event))
            break;
        print_header(h, "PROCESS_EXIT");
        printf(" exit_code_raw=%d\n", event->payload.exit_code_raw);
        fflush(stdout);
        return 0;
    }
    case EVENT_FILE_OPEN: {
        const struct file_open_event *event = data;
        if (size != sizeof(*event))
            break;
        print_header(h, "FILE_OPEN");
        printf(" path=%.*s flags=%u path_ret=%d\n",
               EVENT_FILENAME_LEN, event->payload.path,
               event->payload.flags, event->payload.path_ret);
        fflush(stdout);
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_FILE_UNLINK_ATTEMPT: {
        const struct file_unlink_event *event = data;
        if (size != sizeof(*event))
            break;
        size_t dir_len;

        print_header(h, "FILE_UNLINK_ATTEMPT");
        dir_len = strnlen(event->payload.dir_path, EVENT_FILENAME_LEN);
        printf(" path=%.*s%s%.*s path_ret=%d name_ret=%d\n",
               EVENT_FILENAME_LEN, event->payload.dir_path,
               dir_len && event->payload.dir_path[dir_len - 1] == '/' ? "" : "/",
               EVENT_FILENAME_LEN, event->payload.name,
               event->payload.path_ret, event->payload.name_ret);
        fflush(stdout);
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_FILE_OPEN_RESULT: {
        const struct file_open_result_event *event = data;

        if (size != sizeof(*event))
            break;
        print_header(h, "FILE_OPEN_RESULT");
        printf(" dirfd=%d attempted_path=%.*s ret=%d"
               " path_basis=syscall_input\n",
               event->payload.dirfd, EVENT_FILENAME_LEN,
               event->payload.attempted_path, event->payload.ret);
        fflush(stdout);
        detector_process(detector, data, size);
        return 0;
    }
    case EVENT_CONNECT_RESULT: {
        const struct connect_event *event = data;
        char address[INET6_ADDRSTRLEN] = "<invalid>";
        int address_family;

        if (size != sizeof(*event))
            break;
        address_family = event->payload.family == AF_INET ? AF_INET :
                         event->payload.family == AF_INET6 ? AF_INET6 : 0;
        if (address_family)
            (void)inet_ntop(address_family, event->payload.destination_address,
                            address, sizeof(address));

        print_header(h, "CONNECT_RESULT");
        printf(" socket_fd=%d family=%u dst_ip=%s dst_port=%u ret=%d\n",
               event->payload.socket_fd, event->payload.family, address,
               event->payload.destination_port, event->payload.ret);
        fflush(stdout);
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

/*
 * 第一阶段在原 cgroup 中完成可能访问 NSS/组文件的 initgroups；
 * 第二阶段等待父进程迁移并登记 cgroup 后，再放弃 root 并 exec。
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
            "usage: %s --agent ID [--deny-shell]"
            " [--sensitive-path DIR] [--workspace DIR]"
            " [--failed-open-threshold N]"
            " [--failed-open-window-ms MS] -- COMMAND [ARG ...]"
            " [--next --agent ID [POLICY ...] -- COMMAND [ARG ...]]\n",
            program);
}

static int parse_agents(int argc, char **argv, struct agent_process *agents,
                        size_t *agent_count)
{
    int index = 1;
    size_t count = 0;

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
                if (agents[count].deny_shell)
                    return -1;
                agents[count].deny_shell = 1;
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
            } else {
                return -1;
            }
            option_index++;
        }
        if (option_index == argc)
            return -1;

        if (!!agents[count].failed_open_threshold !=
            !!agents[count].failed_open_window_ms)
            return -1;

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

static void print_agent_exit(const struct agent_process *agent)
{
    if (WIFEXITED(agent->status)) {
        printf("event=agent_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld exit_code=%d\n",
               agent->agent_id, (uint64_t)agent->cgroup_id,
               (long)agent->child, WEXITSTATUS(agent->status));
    } else if (WIFSIGNALED(agent->status)) {
        printf("event=agent_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld signal=%d\n",
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
    for (index = 0; index < agent_count; index++) {
        if (detector_add_agent(&detector, agents[index].agent_id,
                               agents[index].deny_shell,
                               agents[index].sensitive_path,
                               agents[index].workspace_path,
                               agents[index].failed_open_threshold,
                               agents[index].failed_open_window_ms)) {
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
        if (bpf_map_update_elem(map_fd, &agent->cgroup_id,
                                &agent->agent_id, BPF_ANY)) {
            perror("register Agent cgroup");
            goto cleanup;
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

        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring buffer poll failed: %d\n", err);
            goto cleanup;
        }

        for (index = 0; index < agent_count; index++) {
            pid_t waited;

            if (agents[index].reaped)
                continue;
            waited = waitpid(agents[index].child, &agents[index].status,
                             WNOHANG);
            if (waited == agents[index].child) {
                agents[index].reaped = 1;
                remaining--;
                newly_reaped = 1;
            } else if (waited < 0 && errno != EINTR) {
                perror("waitpid");
                goto cleanup;
            }
        }

        if (newly_reaped) {
            (void)ring_buffer__consume(rb);
            for (index = 0; index < agent_count; index++) {
                if (agents[index].reaped && agents[index].child > 0) {
                    print_agent_exit(&agents[index]);
                    agents[index].child = -agents[index].child;
                }
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

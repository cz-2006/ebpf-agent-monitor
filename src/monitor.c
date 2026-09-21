#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
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
#include "events.h"
#include "monitor.skel.h"

#define CGROUP_BASE "/sys/fs/cgroup/ebpf-agent-monitor"
static volatile sig_atomic_t stop;

struct run_identity {
    uid_t uid;
    gid_t gid;
    char user[256];
    char home[PATH_MAX];
};

static void on_signal(int sig) { (void)sig; stop = 1; }

static int on_event(void *ctx, void *data, size_t size)
{
    const struct exec_event *e = data;
    const struct monitor_event_header *h = data;
    (void)ctx;

    if (size != sizeof(*e) || h->size != size ||
        h->event_type != EVENT_EXEC_ATTEMPT) {
        fprintf(stderr, "discarding malformed event: type=%u size=%zu\n",
                h->event_type, size);
        return 0;
    }
    printf("timestamp_ns=%" PRIu64 " cgroup_id=%" PRIu64
           " event=EXEC_ATTEMPT pid=%u tid=%u ppid=%u uid=%u agent_id=%u"
           " comm=%.*s filename=%.*s\n",
           (uint64_t)h->timestamp_ns, (uint64_t)h->cgroup_id, h->pid, h->tid, h->ppid, h->uid,
           h->agent_id, EVENT_COMM_LEN, h->comm, EVENT_FILENAME_LEN,
           e->payload.filename);
    fflush(stdout);
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

/* 子进程等待父进程完成 cgroup 迁移和映射注册后才执行命令。 */
static void gated_exec(int fd, char **command,
                       const struct run_identity *identity)
{
    char token;
    ssize_t n;
    do { n = read(fd, &token, 1); } while (n < 0 && errno == EINTR);
    close(fd);
    if (n != 1 || token != 'x')
        _exit(125);

    /* 先设置附加组，再彻底放弃 root 的组、有效及保存用户身份。 */
    if (initgroups(identity->user, identity->gid) ||
        setresgid(identity->gid, identity->gid, identity->gid) ||
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

int main(int argc, char **argv)
{
    struct monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct run_identity identity = {0};
    char cg_path[PATH_MAX] = {0};
    __u32 agent_id;
    __u64 cg_id = 0;
    pid_t child = -1;
    int gate[2] = {-1, -1}, status = 0, map_fd = -1, err = 0, result = 1;
    int made_base = 0, made_cgroup = 0, registered = 0, reaped = 0;

    if (argc < 5 || strcmp(argv[1], "--agent") ||
        parse_id(argv[2], &agent_id) || strcmp(argv[3], "--")) {
        fprintf(stderr, "usage: %s --agent AGENT_ID -- COMMAND [ARG ...]\n", argv[0]);
        return 2;
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
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }
    if (create_cgroup(cg_path, sizeof(cg_path), agent_id, &made_base))
        goto cleanup;
    made_cgroup = 1;
    if (cgroup_id(cg_path, &cg_id))
        goto cleanup;

    map_fd = bpf_map__fd(skel->maps.agent_by_cgroup);
    if (bpf_map_update_elem(map_fd, &cg_id, &agent_id, BPF_ANY)) {
        perror("register Agent cgroup");
        goto cleanup;
    }
    registered = 1;

    if (pipe2(gate, O_CLOEXEC) || (child = fork()) < 0) {
        perror("create gated child");
        goto cleanup;
    }
    if (!child) {
        close(gate[1]);
        gated_exec(gate[0], &argv[4], &identity);
    }
    close(gate[0]);
    gate[0] = -1;

    if (move_and_verify(cg_path, child))
        goto cleanup;
    printf("event=agent_register agent_id=%u cgroup_id=%" PRIu64
           " root_pid=%ld run_uid=%lu run_gid=%lu basis=controlled_launch\n",
           agent_id, (uint64_t)cg_id, (long)child,
           (unsigned long)identity.uid, (unsigned long)identity.gid);
    fflush(stdout);

    if (write(gate[1], "x", 1) != 1) {
        perror("release child");
        goto cleanup;
    }
    close(gate[1]);
    gate[1] = -1;

    for (;;) {
        pid_t waited;
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring buffer poll failed: %d\n", err);
            goto cleanup;
        }
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            reaped = 1;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            perror("waitpid");
            goto cleanup;
        }
        if (stop)
            kill(child, SIGTERM);
    }
    ring_buffer__consume(rb);

    if (WIFEXITED(status)) {
        result = WEXITSTATUS(status);
        printf("event=agent_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld exit_code=%d\n",
               agent_id, (uint64_t)cg_id, (long)child, result);
    } else if (WIFSIGNALED(status)) {
        result = 128 + WTERMSIG(status);
        printf("event=agent_exit agent_id=%u cgroup_id=%" PRIu64
               " root_pid=%ld signal=%d\n",
               agent_id, (uint64_t)cg_id, (long)child, WTERMSIG(status));
    }

cleanup:
    if (gate[0] >= 0) close(gate[0]);
    if (gate[1] >= 0) close(gate[1]);
    if (child > 0 && !reaped) {
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    if (registered && bpf_map_delete_elem(map_fd, &cg_id) && errno != ENOENT)
        perror("unregister Agent cgroup");
    if (made_cgroup && rmdir(cg_path))
        perror("remove Agent cgroup");
    if (made_base && rmdir(CGROUP_BASE) && errno != ENOTEMPTY)
        perror("remove cgroup base");
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    return result;
}

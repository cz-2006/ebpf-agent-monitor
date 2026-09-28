#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "detector.h"

void detector_init(struct detector *detector)
{
    memset(detector, 0, sizeof(*detector));
}

/* 策略目录统一保存为绝对路径且以 / 结尾，便于做路径边界匹配。 */
static int normalize_policy_dir(char *destination, size_t size,
                                const char *source)
{
    size_t length;

    if (!source || source[0] != '/')
        return -1;
    length = strlen(source);
    while (length > 1 && source[length - 1] == '/')
        length--;
    if (length + (length > 1) >= size)
        return -1;

    memcpy(destination, source, length);
    if (length > 1)
        destination[length++] = '/';
    destination[length] = '\0';
    return 0;
}

int detector_add_agent(struct detector *detector, __u32 agent_id,
                       enum detector_shell_policy shell_policy,
                       const char *sensitive_path,
                       const char *workspace_path,
                       const char *const runtime_paths[],
                       size_t runtime_path_count,
                       __u32 failed_open_threshold,
                       __u32 failed_open_window_ms,
                       __u32 cpu_threshold_percent)
{
    struct detector_agent_policy *policy;
    size_t index;

    if (detector->policy_count >= DETECTOR_MAX_AGENTS ||
        runtime_path_count > DETECTOR_MAX_RUNTIME_DIRS)
        return -1;

    policy = &detector->policies[detector->policy_count];
    policy->agent_id = agent_id;
    policy->shell_policy = shell_policy;
    policy->failed_open_threshold = failed_open_threshold;
    policy->failed_open_window_ms = failed_open_window_ms;
    policy->cpu_threshold_percent = cpu_threshold_percent;
    if (sensitive_path &&
        normalize_policy_dir(policy->sensitive_dir,
                             sizeof(policy->sensitive_dir),
                             sensitive_path))
        return -1;
    if (workspace_path &&
        normalize_policy_dir(policy->workspace_dir,
                             sizeof(policy->workspace_dir),
                             workspace_path))
        return -1;
    for (index = 0; index < runtime_path_count; index++) {
        if (normalize_policy_dir(policy->runtime_dirs[index],
                                 sizeof(policy->runtime_dirs[index]),
                                 runtime_paths[index]))
            return -1;
    }
    policy->runtime_dir_count = runtime_path_count;
    detector->policy_count++;
    return 0;
}

static const struct detector_agent_policy *
find_policy(const struct detector *detector, __u32 agent_id)
{
    size_t index;

    for (index = 0; index < detector->policy_count; index++) {
        if (detector->policies[index].agent_id == agent_id)
            return &detector->policies[index];
    }
    return NULL;
}

/* 精确匹配常见 Shell 名称，避免把名称中偶然含有 sh 的程序误报。 */
static int is_shell(const char *filename)
{
    static const char *const names[] = {
        "sh", "bash", "dash", "zsh", "ksh", "fish",
    };
    const char *base = strrchr(filename, '/');
    size_t index;

    base = base ? base + 1 : filename;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        if (!strcmp(base, names[index]))
            return 1;
    }
    return 0;
}

static int path_in_directory(const char *path, const char *directory)
{
    size_t directory_length;
    size_t path_length;

    if (!directory[0])
        return 0;
    directory_length = strlen(directory);
    if (directory_length == 1)
        return path[0] == '/';
    if (!strncmp(path, directory, directory_length))
        return 1;

    path_length = strlen(path);
    return path_length == directory_length - 1 &&
           !strncmp(path, directory, directory_length - 1);
}

static void detect_unexpected_shell(
    const struct detector_agent_policy *policy,
    const struct exec_event *event)
{
    const struct monitor_event_header *header = &event->header;

    if (!is_shell(event->payload.filename) ||
        policy->shell_policy == DETECTOR_SHELL_DISABLED ||
        policy->shell_policy == DETECTOR_SHELL_ALLOW)
        return;

    if (policy->shell_policy == DETECTOR_SHELL_AUDIT) {
        printf("timestamp_ns=%" PRIu64
               " event=activity_evidence rule=shell_execution"
               " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
               " target=%.*s policy=shell_audit"
               " evidence=exec_attempt,cgroup_attribution\n",
               (uint64_t)header->timestamp_ns, header->pid, header->tid,
               header->agent_id, (uint64_t)header->cgroup_id,
               EVENT_FILENAME_LEN, event->payload.filename);
        fflush(stdout);
        return;
    }

    printf("timestamp_ns=%" PRIu64
           " event=security_alert severity=high rule=unexpected_shell"
           " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
           " target=%.*s policy=shell_denied"
           " evidence=exec_attempt,cgroup_attribution\n",
           (uint64_t)header->timestamp_ns, header->pid, header->tid,
           header->agent_id, (uint64_t)header->cgroup_id,
           EVENT_FILENAME_LEN, event->payload.filename);
    fflush(stdout);
}

static void detect_sensitive_file_access(
    const struct detector_agent_policy *policy,
    const struct file_open_event *event)
{
    const struct monitor_event_header *header = &event->header;

    if (!policy->sensitive_dir[0] ||
        (event->payload.flags & O_ACCMODE) == O_WRONLY ||
        (event->payload.flags & O_DIRECTORY) ||
        !path_in_directory(event->payload.path, policy->sensitive_dir))
        return;

    printf("timestamp_ns=%" PRIu64
           " event=security_alert severity=high rule=sensitive_file_access"
           " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
           " target=%.*s flags=%u policy=sensitive_read_denied"
           " evidence=file_open,path_policy,cgroup_attribution\n",
           (uint64_t)header->timestamp_ns, header->pid, header->tid,
           header->agent_id, (uint64_t)header->cgroup_id,
           EVENT_FILENAME_LEN, event->payload.path, event->payload.flags);
    fflush(stdout);
}

static void detect_outside_workspace_delete(
    const struct detector_agent_policy *policy,
    const struct file_unlink_event *event)
{
    const struct monitor_event_header *header = &event->header;
    char target[EVENT_FILENAME_LEN * 2 + 2];
    size_t directory_length;
    size_t index;
    int written;

    if (!policy->workspace_dir[0] ||
        event->payload.path_ret < 0 || event->payload.name_ret < 0)
        return;

    directory_length = strnlen(event->payload.dir_path, EVENT_FILENAME_LEN);
    written = snprintf(target, sizeof(target), "%.*s%s%.*s",
                       EVENT_FILENAME_LEN, event->payload.dir_path,
                       directory_length &&
                       event->payload.dir_path[directory_length - 1] == '/'
                           ? "" : "/",
                       EVENT_FILENAME_LEN, event->payload.name);
    if (written < 0 || (size_t)written >= sizeof(target) ||
        path_in_directory(target, policy->workspace_dir))
        return;

    for (index = 0; index < policy->runtime_dir_count; index++) {
        if (!path_in_directory(target, policy->runtime_dirs[index]))
            continue;
        printf("timestamp_ns=%" PRIu64
               " event=activity_evidence rule=runtime_file_delete"
               " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
               " target=%s policy=runtime_delete_audit"
               " evidence=unlink_attempt,path_policy,cgroup_attribution\n",
               (uint64_t)header->timestamp_ns, header->pid, header->tid,
               header->agent_id, (uint64_t)header->cgroup_id, target);
        fflush(stdout);
        return;
    }

    printf("timestamp_ns=%" PRIu64
           " event=security_alert severity=high"
           " rule=outside_workspace_delete"
           " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
           " target=%s policy=workspace_delete_only"
           " evidence=unlink_attempt,path_policy,cgroup_attribution\n",
           (uint64_t)header->timestamp_ns, header->pid, header->tid,
           header->agent_id, (uint64_t)header->cgroup_id, target);
    fflush(stdout);
}

static int normalize_absolute_path(const char *input, char *output,
                                   size_t output_size)
{
    const char *cursor;
    size_t output_length = 1;

    if (!input || input[0] != '/' || output_size < 2)
        return -1;
    output[0] = '/';
    output[1] = '\0';
    cursor = input;

    while (*cursor) {
        const char *segment;
        size_t segment_length;

        while (*cursor == '/')
            cursor++;
        if (!*cursor)
            break;
        segment = cursor;
        while (*cursor && *cursor != '/')
            cursor++;
        segment_length = (size_t)(cursor - segment);

        if (segment_length == 1 && segment[0] == '.')
            continue;
        if (segment_length == 2 && segment[0] == '.' &&
            segment[1] == '.') {
            while (output_length > 1 &&
                   output[output_length - 1] != '/')
                output_length--;
            if (output_length > 1)
                output_length--;
            output[output_length] = '\0';
            continue;
        }

        if (output_length > 1) {
            if (output_length + 1 >= output_size)
                return -1;
            output[output_length++] = '/';
        }
        if (output_length + segment_length >= output_size)
            return -1;
        memcpy(output + output_length, segment, segment_length);
        output_length += segment_length;
        output[output_length] = '\0';
    }
    return 0;
}

static int reconstruct_attempted_path(const struct file_open_result_event *event,
                                      char *output, size_t output_size,
                                      const char **reconstruction)
{
    char proc_path[64];
    char base[PATH_MAX];
    char combined[PATH_MAX];
    ssize_t length;
    int written;

    if (event->payload.attempted_path[0] == '/') {
        *reconstruction = "absolute";
        return normalize_absolute_path(event->payload.attempted_path,
                                       output, output_size);
    }

    if (event->payload.dirfd == AT_FDCWD) {
        written = snprintf(proc_path, sizeof(proc_path), "/proc/%u/cwd",
                           event->header.pid);
        *reconstruction = "proc_cwd";
    } else {
        written = snprintf(proc_path, sizeof(proc_path), "/proc/%u/fd/%d",
                           event->header.pid, event->payload.dirfd);
        *reconstruction = "proc_dirfd";
    }
    if (written < 0 || (size_t)written >= sizeof(proc_path))
        return -1;

    length = readlink(proc_path, base, sizeof(base) - 1);
    if (length < 0)
        return -1;
    base[length] = '\0';
    written = snprintf(combined, sizeof(combined), "%s/%.*s", base,
                       EVENT_FILENAME_LEN, event->payload.attempted_path);
    if (written < 0 || (size_t)written >= sizeof(combined))
        return -1;
    return normalize_absolute_path(combined, output, output_size);
}

static struct failed_open_state *
failed_open_state(struct detector *detector, __u32 agent_id,
                  const char *path, __u64 timestamp_ns)
{
    struct failed_open_state *free_state = NULL;
    struct failed_open_state *oldest = NULL;
    size_t index;

    for (index = 0; index < DETECTOR_MAX_FAILED_OPEN_STATES; index++) {
        struct failed_open_state *state =
            &detector->failed_open_states[index];

        if (state->used && state->agent_id == agent_id &&
            !strcmp(state->path, path))
            return state;
        if (!state->used && !free_state)
            free_state = state;
        if (state->used &&
            (!oldest || state->last_seen_ns < oldest->last_seen_ns))
            oldest = state;
    }

    free_state = free_state ? free_state : oldest;
    if (!free_state)
        return NULL;
    memset(free_state, 0, sizeof(*free_state));
    free_state->used = 1;
    free_state->agent_id = agent_id;
    free_state->window_start_ns = timestamp_ns;
    free_state->last_seen_ns = timestamp_ns;
    if (snprintf(free_state->path, sizeof(free_state->path), "%s", path)
        >= (int)sizeof(free_state->path)) {
        memset(free_state, 0, sizeof(*free_state));
        return NULL;
    }
    return free_state;
}

static void detect_repeated_failed_open(
    struct detector *detector,
    const struct detector_agent_policy *policy,
    const struct file_open_result_event *event)
{
    const struct monitor_event_header *header = &event->header;
    struct failed_open_state *state;
    const char *reconstruction;
    char target[PATH_MAX];
    __u64 window_ns;
    __u64 elapsed_ns;

    if (!policy->failed_open_threshold ||
        event->payload.ret != -ENOENT ||
        reconstruct_attempted_path(event, target, sizeof(target),
                                   &reconstruction))
        return;

    state = failed_open_state(detector, header->agent_id, target,
                              header->timestamp_ns);
    if (!state)
        return;

    window_ns = (__u64)policy->failed_open_window_ms * 1000000ULL;
    elapsed_ns = header->timestamp_ns - state->window_start_ns;
    if (elapsed_ns > window_ns) {
        state->count = 0;
        state->alerted = 0;
        state->joint_alerted = 0;
        state->window_start_ns = header->timestamp_ns;
        elapsed_ns = 0;
    }
    state->count++;
    state->last_seen_ns = header->timestamp_ns;
    state->pid = header->pid;
    state->tid = header->tid;
    state->cgroup_id = header->cgroup_id;

    printf("timestamp_ns=%" PRIu64
           " event=activity_evidence rule=repeated_failed_open"
           " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
           " target=%s errno=%d count=%u threshold=%u window_ms=%u"
           " elapsed_ns=%" PRIu64
           " path_basis=reconstructed_attempt reconstruction=%s\n",
           (uint64_t)header->timestamp_ns, header->pid, header->tid,
           header->agent_id, (uint64_t)header->cgroup_id, target,
           -event->payload.ret, state->count,
           policy->failed_open_threshold, policy->failed_open_window_ms,
           (uint64_t)elapsed_ns, reconstruction);

    if (state->count >= policy->failed_open_threshold && !state->alerted) {
        printf("timestamp_ns=%" PRIu64
               " event=security_alert severity=medium"
               " rule=repeated_failed_open"
               " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
               " target=%s errno=%d count=%u threshold=%u window_ms=%u"
               " elapsed_ns=%" PRIu64
               " path_basis=reconstructed_attempt reconstruction=%s"
               " evidence=same_agent,same_target,repeated_enoent,"
               "time_window,cgroup_attribution\n",
               (uint64_t)header->timestamp_ns, header->pid, header->tid,
               header->agent_id, (uint64_t)header->cgroup_id, target,
               -event->payload.ret, state->count,
               policy->failed_open_threshold, policy->failed_open_window_ms,
               (uint64_t)elapsed_ns, reconstruction);
        state->alerted = 1;
    }
    fflush(stdout);
}


void detector_process_cpu_sample(
    struct detector *detector, const struct resource_cpu_sample *sample)
{
    const struct detector_agent_policy *policy;
    size_t index;

    if (!detector || !sample)
        return;
    policy = find_policy(detector, sample->agent_id);
    if (!policy || !policy->cpu_threshold_percent)
        return;

    printf("timestamp_ns=%" PRIu64
           " event=resource_sample metric=cpu agent_id=%u cgroup_id=%" PRIu64
           " interval_usec=%" PRIu64 " usage_delta_usec=%" PRIu64
           " cpu_percent=%" PRIu64 ".%02" PRIu64
           " basis=cgroup_cpu_stat_single_core\n",
           (uint64_t)sample->timestamp_ns, sample->agent_id,
           (uint64_t)sample->cgroup_id, (uint64_t)sample->interval_usec,
           (uint64_t)sample->usage_delta_usec,
           (uint64_t)(sample->cpu_percent_x100 / 100),
           (uint64_t)(sample->cpu_percent_x100 % 100));

    if (sample->cpu_percent_x100 <
        (__u64)policy->cpu_threshold_percent * 100ULL) {
        fflush(stdout);
        return;
    }

    for (index = 0; index < DETECTOR_MAX_FAILED_OPEN_STATES; index++) {
        struct failed_open_state *state =
            &detector->failed_open_states[index];
        __u64 window_ns;

        if (!state->used || !state->alerted || state->joint_alerted ||
            state->agent_id != sample->agent_id ||
            state->cgroup_id != sample->cgroup_id ||
            sample->timestamp_ns < state->window_start_ns)
            continue;
        window_ns = (__u64)policy->failed_open_window_ms * 1000000ULL;
        if (sample->timestamp_ns - state->window_start_ns > window_ns)
            continue;

        printf("timestamp_ns=%" PRIu64
               " event=anomaly_alert severity=high"
               " rule=resource_logic_anomaly"
               " pid=%u tid=%u agent_id=%u cgroup_id=%" PRIu64
               " target=%s repeated_failed_open_count=%u"
               " cpu_percent=%" PRIu64 ".%02" PRIu64
               " cpu_threshold_percent=%u window_ms=%u"
               " evidence=high_cpu,repeated_failed_open,same_agent,"
               "time_window,cgroup_attribution\n",
               (uint64_t)sample->timestamp_ns, state->pid, state->tid,
               sample->agent_id, (uint64_t)sample->cgroup_id, state->path,
               state->count,
               (uint64_t)(sample->cpu_percent_x100 / 100),
               (uint64_t)(sample->cpu_percent_x100 % 100),
               policy->cpu_threshold_percent,
               policy->failed_open_window_ms);
        state->joint_alerted = 1;
    }
    fflush(stdout);
}

void detector_process(struct detector *detector, const void *data,
                      size_t size)
{
    const struct monitor_event_header *header = data;
    const struct detector_agent_policy *policy;

    if (!detector || size < sizeof(*header) || header->size != size)
        return;
    policy = find_policy(detector, header->agent_id);
    if (!policy)
        return;

    switch (header->event_type) {
    case EVENT_EXEC_ATTEMPT:
        if (size == sizeof(struct exec_event))
            detect_unexpected_shell(policy, data);
        break;
    case EVENT_FILE_OPEN:
        if (size == sizeof(struct file_open_event))
            detect_sensitive_file_access(policy, data);
        break;
    case EVENT_FILE_UNLINK_ATTEMPT:
        if (size == sizeof(struct file_unlink_event))
            detect_outside_workspace_delete(policy, data);
        break;
    case EVENT_FILE_OPEN_RESULT:
        if (size == sizeof(struct file_open_result_event))
            detect_repeated_failed_open(detector, policy, data);
        break;
    default:
        break;
    }
}

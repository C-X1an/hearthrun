#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Fixed trusted operations only. These are disposable capability probes, not
 * a guest launcher or a certification of the complete launch policy. */
struct result { int error; char detail[192]; };
static char scratch[PATH_MAX], cgroup_leaf[80];
static int scratch_fd = -1, cgroup_parent = -1, cgroup_fd = -1, lifecycle_ready = -1;
static bool scratch_owned, cgroup_owned;
static long landlock_abi;
static volatile sig_atomic_t interrupted;
static int fail(struct result *r, int e, const char *detail) {
    r->error = e ? e : EIO;
    snprintf(r->detail, sizeof(r->detail), "%s", detail);
    return -1;
}
static void on_signal(int sig) { interrupted = sig; }
static int64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void tick(void) {
    struct timespec t = {.tv_nsec = 10000000};
    (void)nanosleep(&t, NULL);
}
static bool write_all(int fd, const void *data, size_t len) {
    const char *p = data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n; len -= (size_t)n;
    }
    return true;
}
static bool write_file(int dir, const char *name, const char *value) {
    int fd = openat(dir, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool ok = write_all(fd, value, strlen(value)); int e = errno;
    if (close(fd) < 0 && ok) return false;
    errno = e; return ok;
}
static bool read_file(int dir, const char *name, char *buf, size_t cap) {
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(fd, buf + used, cap - used - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { int e = errno; close(fd); errno = e; return false; }
        if (!n) { buf[used] = '\0'; return close(fd) == 0; }
        used += (size_t)n;
    }
    close(fd); errno = EOVERFLOW; return false;
}
static bool token(const char *text, const char *word) {
    size_t n = strlen(word);
    for (const char *p = text; (p = strstr(p, word)) != NULL; p++)
        if ((p == text || p[-1] == ' ' || p[-1] == '\n') &&
            (!p[n] || p[n] == ' ' || p[n] == '\n')) return true;
    return false;
}
static long long field(const char *text, const char *key) {
    size_t n = strlen(key);
    for (const char *p = text; *p;) {
        if (!strncmp(p, key, n) && p[n] == ' ') {
            char *end = NULL; errno = 0;
            long long v = strtoll(p + n + 1, &end, 10);
            return !errno && end != p + n + 1 && (!*end || *end == '\n') ? v : -1;
        }
        const char *next = strchr(p, '\n');
        if (!next) break;
        p = next + 1;
    }
    return -1;
}
static bool wait_bounded(pid_t pid, int *status, int timeout) {
    int64_t start = now_ms();
    if (start < 0) return false;
    for (;;) {
        pid_t p = waitpid(pid, status, WNOHANG);
        if (p == pid) return true;
        if (p < 0 && errno != EINTR) return false;
        if (interrupted || now_ms() - start >= timeout) { errno = ETIMEDOUT; return false; }
        tick();
    }
}
static bool wait_success(pid_t pid, int timeout) {
    int status;
    if (!wait_bounded(pid, &status, timeout)) return false;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) { errno = EPROTO; return false; }
    return true;
}
static void terminate_child(pid_t pid, bool group) {
    /* All callers own an unreaped direct child. Retain its PID until after
     * signaling and never use a numerical group identity after waitpid. */
    if (group) (void)kill(-pid, SIGKILL);
    (void)kill(pid, SIGKILL);
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}
static struct result run_probe(int (*fn)(struct result *)) {
    struct result r = {0}; int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) { fail(&r, errno, "probe pipe"); return r; }
    pid_t pid = fork();
    if (pid < 0) { fail(&r, errno, "probe fork"); close(pipefd[0]); close(pipefd[1]); return r; }
    if (!pid) {
        close(pipefd[0]); signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL);
        if (setpgid(0, 0) < 0) _exit(120);
        alarm(15); (void)fn(&r);
        bool ok = write_all(pipefd[1], &r, sizeof(r));
        close(pipefd[1]); _exit(ok ? 0 : 121);
    }
    close(pipefd[1]); (void)setpgid(pid, pid);
    int64_t start = now_ms();
    siginfo_t info = {0};
    for (;;) {
        if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            if (e != ECHILD) terminate_child(pid, true);
            fail(&r, e, "probe exit observation failed");
            break;
        }
        if (info.si_pid) {
            if (info.si_code != CLD_EXITED || info.si_status != 0) {
                terminate_child(pid, true);
                fail(&r, ECHILD, "probe child signaled or internal failure");
            } else {
                int status;
                if (waitpid(pid, &status, 0) != pid) fail(&r, errno, "probe child reap");
            }
            break;
        }
        if (interrupted || start < 0 || now_ms() - start >= 16000) {
            terminate_child(pid, true);
            fail(&r, ETIMEDOUT, "probe timed out/interrupted; child killed and reaped");
            break;
        }
        tick();
    }
    if (!r.error) {
        ssize_t n;
        do { n = read(pipefd[0], &r, sizeof(r)); } while (n < 0 && errno == EINTR);
        if (n != (ssize_t)sizeof(r)) fail(&r, EPROTO, "incomplete probe result");
    }
    close(pipefd[0]); return r;
}

static int probe_namespaces(struct result *r) {
    uid_t uid = getuid(); gid_t gid = getgid();
    const char *names[] = {"user", "mnt", "pid_for_children", "net", "ipc", "uts"};
    ino_t before[6];
    for (size_t i = 0; i < 6; i++) {
        char path[80]; struct stat st;
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        if (stat(path, &st) < 0) return fail(r, errno, "namespace identity before unshare");
        before[i] = st.st_ino;
    }
    if (unshare(CLONE_NEWUSER) < 0) return fail(r, errno, "user namespace creation");
    char mapping[80];
    if (!write_file(AT_FDCWD, "/proc/self/setgroups", "deny")) return fail(r, errno, "setgroups denial");
    snprintf(mapping, sizeof(mapping), "0 %u 1\n", (unsigned)uid);
    if (!write_file(AT_FDCWD, "/proc/self/uid_map", mapping)) return fail(r, errno, "single UID mapping");
    snprintf(mapping, sizeof(mapping), "0 %u 1\n", (unsigned)gid);
    if (!write_file(AT_FDCWD, "/proc/self/gid_map", mapping)) return fail(r, errno, "single GID mapping");
    if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS) < 0)
        return fail(r, errno, "mount/PID/network/IPC/UTS namespace creation");
    for (size_t i = 0; i < 6; i++) {
        /* pid_for_children is initially empty until this namespace has a
         * first child. Verify it below while PID1 is behind a gate. */
        if (i == 2) continue;
        char path[80]; struct stat st;
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        if (stat(path, &st) < 0) return fail(r, errno, "namespace identity read after unshare");
        if (st.st_ino == before[i]) return fail(r, EPROTO, "namespace identity unchanged");
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) return fail(r, errno, "private mount propagation");
    if (sethostname("hearthrun-doctor", 16) < 0) return fail(r, errno, "UTS hostname operation");
    if (mount("tmpfs", scratch, "tmpfs", MS_NOSUID | MS_NODEV, "size=1048576,nr_inodes=32,mode=0700") < 0)
        return fail(r, errno, "bounded minimal-root tmpfs mount");
    int gate[2];
    if (pipe2(gate, O_CLOEXEC) < 0) return fail(r, errno, "PID1 setup gate");
    pid_t init = fork();
    if (init < 0) return fail(r, errno, "PID namespace init fork");
    if (!init) {
        close(gate[1]); alarm(4); char release;
        if (read(gate[0], &release, 1) != 1 || release != 'G') _exit(6);
        close(gate[0]);
        /* pivot_root affects all roots in the same mount namespace. Clone
         * once more so the observing parent can unmount its original path. */
        if (getpid() != 1 || unshare(CLONE_NEWNS) < 0 || chdir(scratch) < 0 || mkdir("old", 0700) < 0 ||
            syscall(SYS_pivot_root, ".", "old") < 0 || chdir("/") < 0 ||
            umount2("/old", MNT_DETACH) < 0 || rmdir("/old") < 0) _exit(1);
        if (!access("/proc", F_OK) || !access("/home", F_OK) || !access("/dev", F_OK) || !access("/sys", F_OK)) _exit(2);
        pid_t child = fork();
        if (child < 0) _exit(3);
        if (!child) _exit(getppid() == 1 ? 0 : 4);
        _exit(wait_success(child, 1000) ? 0 : 5);
    }
    close(gate[0]);
    struct stat pid_ns;
    bool distinct = stat("/proc/self/ns/pid_for_children", &pid_ns) == 0 && pid_ns.st_ino != before[2];
    bool released = distinct && write_all(gate[1], "G", 1);
    close(gate[1]);
    if (!released) {
        terminate_child(init, false);
        return fail(r, EPROTO, "distinct PID namespace identity and PID1 gate");
    }
    int init_status;
    if (!wait_bounded(init, &init_status, 5000)) {
        int e = errno;
        if (e != ECHILD) terminate_child(init, false);
        return fail(r, e, "PID1 wait failed; disposed owned init");
    }
    if (!WIFEXITED(init_status) || WEXITSTATUS(init_status))
        return fail(r, EPROTO, "PID1 minimal-root pivot and child reap");
    if (umount2(scratch, 0) < 0) return fail(r, errno, "minimal-root unmount");
    snprintf(r->detail, sizeof(r->detail), "six distinct namespaces, UID/GID map, private tmpfs pivot_root, PID1 child reaped");
    return 0;
}
static int probe_landlock(struct result *r) {
    if (landlock_abi < 3) return fail(r, ENOTSUP, "Landlock ABI >=3 required (REFER/TRUNCATE)");
    if (landlock_abi > 7) return fail(r, ENOTSUP, "unreviewed Landlock ABI newer than 7");
    /* ABI5 introduced filesystem bit15 IOCTL_DEV. Build against old headers
     * while handling all filesystem rights through the reviewed ABI7. */
    uint64_t rights = (UINT64_C(1) << (landlock_abi >= 5 ? 16 : 15)) - 1;
    struct landlock_ruleset_attr attr = {.handled_access_fs = rights};
    int rules = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (rules < 0) return fail(r, errno, "Landlock all-filesystem-rights ruleset creation");
    int allow = openat(scratch_fd, "allow", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (allow < 0) { int e = errno; close(rules); return fail(r, e, "Landlock allow directory"); }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_MAKE_REG,
        .parent_fd = allow
    };
    if (syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || syscall(SYS_landlock_restrict_self, rules, 0) < 0) {
        int e = errno; close(allow); close(rules); return fail(r, e, "Landlock ruleset application");
    }
    close(allow); close(rules);
    int fd = openat(scratch_fd, "allow/file", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail(r, errno, "Landlock permitted read rejected");
    char c;
    if (read(fd, &c, 1) != 1 || c != 'x') { close(fd); return fail(r, EPROTO, "Landlock permitted read bytes"); }
    close(fd);
    fd = openat(scratch_fd, "deny", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { close(fd); return fail(r, EPROTO, "Landlock outside read allowed"); }
    if (errno != EACCES) return fail(r, errno, "Landlock outside read wrong denial");
    fd = openat(scratch_fd, "allow/file", O_RDONLY | O_TRUNC | O_CLOEXEC);
    if (fd >= 0) { close(fd); return fail(r, EPROTO, "Landlock readonly truncate allowed"); }
    if (errno != EACCES) return fail(r, errno, "Landlock truncate wrong denial");
    if (linkat(scratch_fd, "allow/file", scratch_fd, "allow/same-link", 0) < 0)
        return fail(r, errno, "Landlock same-directory link positive control");
    if (!linkat(scratch_fd, "allow/file", scratch_fd, "allow/other/cross-link", 0))
        return fail(r, EPROTO, "Landlock REFER cross-directory link allowed");
    if (errno != EXDEV) return fail(r, errno, "Landlock REFER wrong denial (creation otherwise permitted)");
    snprintf(r->detail, sizeof(r->detail), "ABI%ld applied; read allowed; outside read, TRUNCATE and cross-directory link denied", landlock_abi);
    return 0;
}
static int probe_seccomp(struct result *r) {
#if !defined(__x86_64__)
    return fail(r, ENOTSUP, "seccomp probe requires x86_64");
#else
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EAFNOSUPPORT),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOEXEC),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog prog = {.len = (unsigned short)(sizeof(code) / sizeof(code[0])), .filter = code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 || syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0)
        return fail(r, errno, "architecture/x32 default-deny seccomp install");
    if (syscall(SYS_getpid) <= 0) return fail(r, EPROTO, "seccomp allowlisted syscall rejected");
    if (syscall(SYS_getppid) != -1 || errno != EPERM) return fail(r, EPROTO, "seccomp default denial absent");
    if (syscall(0x40000000U | SYS_getpid) != -1 || errno != ENOEXEC) return fail(r, EPROTO, "seccomp x32 denial absent");
    /* Fixed i386 getpid has no pointers, avoiding 32-bit address truncation. */
    long compat;
    __asm__ volatile("int $0x80" : "=a"(compat) : "0"(20L) : "memory");
    if (compat != -EAFNOSUPPORT) return fail(r, EPROTO, "seccomp alternate-architecture denial absent");
    const char message[] = "architecture and x32 denied; allowlisted syscall succeeds; default-deny syscall rejected";
    memcpy(r->detail, message, sizeof(message)); return 0;
#endif
}
static int probe_pidfd(struct result *r) {
    pid_t pid = fork();
    if (pid < 0) return fail(r, errno, "pidfd child fork");
    if (!pid) { alarm(4); for (;;) pause(); }
    int pfd = (int)syscall(SYS_pidfd_open, pid, 0), e = 0;
    if (pfd < 0) e = errno;
    if (!e && syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0) < 0) e = errno;
    if (e) (void)kill(pid, SIGKILL);
    struct pollfd p = {.fd = pfd, .events = POLLIN};
    if (!e && (poll(&p, 1, 2000) != 1 || !(p.revents & POLLIN))) e = ETIMEDOUT;
    int status;
    if (!wait_bounded(pid, &status, 3000)) e = errno;
    else if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) e = EPROTO;
    if (pfd >= 0) close(pfd);
    if (e) return fail(r, e, "pidfd open/signal/exit poll and child reap");
    snprintf(r->detail, sizeof(r->detail), "pidfd_open/send_signal, exit readiness and SIGKILL child reap"); return 0;
}
static int probe_close_range(struct result *r) {
    int fd = openat(scratch_fd, "deny", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail(r, errno, "close_range fixture descriptor");
    int high = fcntl(fd, F_DUPFD_CLOEXEC, 64); close(fd);
    if (high < 0) return fail(r, errno, "close_range descriptor duplication");
    if (syscall(SYS_close_range, (unsigned)high, (unsigned)high, 0) < 0) { int e = errno; close(high); return fail(r, e, "close_range application"); }
    if (fcntl(high, F_GETFD) != -1 || errno != EBADF) return fail(r, EPROTO, "close_range descriptor remains open");
    snprintf(r->detail, sizeof(r->detail), "owned descriptor closed; EBADF verified"); return 0;
}
static int probe_openat2(struct result *r) {
    struct open_how how = {.flags = O_RDONLY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV};
    int fd = (int)syscall(SYS_openat2, scratch_fd, "allow/file", &how, sizeof(how));
    if (fd < 0) return fail(r, errno, "openat2 regular file with all resolution flags");
    close(fd);
    fd = (int)syscall(SYS_openat2, scratch_fd, "link", &how, sizeof(how));
    if (fd >= 0) { close(fd); return fail(r, EPROTO, "openat2 symlink allowed"); }
    if (errno != ELOOP) return fail(r, errno, "openat2 symlink wrong denial");
    fd = (int)syscall(SYS_openat2, scratch_fd, "../", &how, sizeof(how));
    if (fd >= 0) { close(fd); return fail(r, EPROTO, "openat2 parent escape allowed"); }
    if (errno != EXDEV) return fail(r, errno, "openat2 parent escape wrong denial");
    snprintf(r->detail, sizeof(r->detail), "regular file opened; symlink and parent escape denied with all four flags"); return 0;
}
static bool cgroup_empty(int dir) {
    char b[512]; return read_file(dir, "cgroup.events", b, sizeof(b)) && field(b, "populated") == 0;
}
static bool wait_empty(int dir, int timeout) {
    int64_t start = now_ms();
    do { if (cgroup_empty(dir)) return true; tick(); } while (now_ms() - start < timeout);
    errno = ETIMEDOUT; return false;
}
static bool exact_file(int dir, const char *name, const char *want) {
    char b[256];
    if (!read_file(dir, name, b, sizeof(b))) return false;
    if (strcmp(b, want)) { errno = EPROTO; return false; }
    return true;
}
static bool set_limit(int dir, const char *name, const char *value) {
    return write_file(dir, name, value) && exact_file(dir, name, value);
}
/* Parent verifies cgroup placement before opening the worker's one-byte gate. */
static pid_t worker_start(int dir, int (*operation)(void)) {
    int gate[2];
    if (pipe2(gate, O_CLOEXEC) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(gate[0]); close(gate[1]); return -1; }
    if (!pid) {
        close(gate[1]); alarm(5); char byte; ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        close(gate[0]); if (n != 1 || byte != 'G') _exit(100);
        _exit(operation());
    }
    close(gate[0]); char want[64], actual[256];
    snprintf(want, sizeof(want), "%ld\n", (long)pid);
    bool ok = write_file(dir, "cgroup.procs", want) && read_file(dir, "cgroup.procs", actual, sizeof(actual)) && !strcmp(want, actual);
    if (ok) ok = write_all(gate[1], "G", 1);
    int e = errno; close(gate[1]);
    if (!ok) {
        (void)kill(pid, SIGKILL); int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        errno = e ? e : EPROTO; return -1;
    }
    return pid;
}
static int pids_operation(void) {
    pid_t first = fork();
    if (first < 0) return 1;
    if (!first) { alarm(3); for (;;) pause(); }
    errno = 0; pid_t second = fork(); int e = errno;
    if (!second) _exit(2);
    int status;
    if (second > 0) { (void)kill(second, SIGKILL); (void)waitpid(second, &status, 0); }
    (void)kill(first, SIGKILL);
    while (waitpid(first, &status, 0) < 0 && errno == EINTR) {}
    return second == -1 && e == EAGAIN ? 0 : 3;
}
static int cpu_operation(void) { volatile uint64_t n = 0; for (;;) n++; return 0; }
static int memory_operation(void) {
    size_t size = 64U * 1024U * 1024U;
    volatile unsigned char *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 1;
    for (size_t i = 0; i < size; i += 4096) p[i] = 1;
    return 2; /* Reaching here means memory.max did not stop allocation. */
}
static int detached_operation(void) {
    pid_t child = fork();
    if (child < 0) return 1;
    if (!child) {
        alarm(5); if (setsid() < 0) _exit(2);
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(3);
        if (!grandchild) { alarm(5); for (;;) pause(); }
        _exit(0);
    }
    if (!wait_success(child, 1000) || !write_all(lifecycle_ready, "R", 1)) return 4;
    for (;;) pause();
}
static int reap_all(int *count) {
    int64_t start = now_ms(); *count = 0;
    for (;;) {
        int status; pid_t p = waitpid(-1, &status, WNOHANG);
        if (p > 0) { (*count)++; continue; }
        if (p < 0 && errno == ECHILD) return 0;
        if (p < 0 && errno != EINTR) return -1;
        if (now_ms() - start > 3000) { errno = ETIMEDOUT; return -1; }
        tick();
    }
}
static int prepare_cgroup(struct result *r) {
    if (cgroup_parent < 0) return fail(r, ENOENT, "configure --cgroup-root or HEARTHRUN_CGROUP_ROOT");
    struct statfs fs; char b[4096];
    if (fstatfs(cgroup_parent, &fs) < 0 || fs.f_type != CGROUP2_SUPER_MAGIC) return fail(r, ENOTSUP, "operator root must be cgroup-v2");
    if (!exact_file(cgroup_parent, "cgroup.type", "domain\n") || !exact_file(cgroup_parent, "cgroup.procs", ""))
        return fail(r, EBUSY, "jobs parent must be an empty domain cgroup");
    if (!read_file(cgroup_parent, "cgroup.controllers", b, sizeof(b)) || !token(b, "cpu") || !token(b, "memory") || !token(b, "pids"))
        return fail(r, ENOTSUP, "jobs parent missing cpu/memory/pids controllers");
    if (!read_file(cgroup_parent, "cgroup.subtree_control", b, sizeof(b)) || !token(b, "cpu") || !token(b, "memory") || !token(b, "pids"))
        return fail(r, ENOTSUP, "enable cpu/memory/pids for jobs children");
    if (mkdirat(cgroup_parent, cgroup_leaf, 0700) < 0) return fail(r, errno, "disposable cgroup creation");
    /* Only the supervising parent creates/removes this leaf. Catchable
     * interruptions set a flag and cannot terminate it between these steps. */
    cgroup_owned = true;
    cgroup_fd = openat(cgroup_parent, cgroup_leaf, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (cgroup_fd < 0) return fail(r, errno, "disposable cgroup open");
    return 0;
}
static int probe_cgroup(struct result *r) {
    int dir = cgroup_fd;
    char b[4096];
    int error = 0; const char *stage = "cgroup limits write and exact readback";
    int ready[2] = {-1, -1};
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0 ||
        !set_limit(dir, "memory.max", "33554432\n") || !set_limit(dir, "memory.swap.max", "0\n") ||
        !set_limit(dir, "memory.oom.group", "1\n") || !set_limit(dir, "pids.max", "2\n") ||
        !set_limit(dir, "cpu.max", "50000 100000\n")) { error = errno; goto cleanup; }
    if (!write_file(dir, "cgroup.kill", "1")) { error = errno; stage = "cgroup.kill authority"; goto cleanup; }
    stage = "actual pids.max fork denial, placement and child reap";
    pid_t worker = worker_start(dir, pids_operation);
    if (worker < 0 || !wait_success(worker, 3500) || !wait_empty(dir, 1000)) { error = errno; goto cleanup; }
    if (!read_file(dir, "pids.events", b, sizeof(b)) || field(b, "max") < 1) { error = EPROTO; goto cleanup; }
    stage = "actual cpu.max throttling";
    worker = worker_start(dir, cpu_operation);
    if (worker < 0) { error = errno; goto cleanup; }
    bool throttled = false; int64_t start = now_ms();
    do {
        if (!read_file(dir, "cpu.stat", b, sizeof(b))) { error = errno; goto cleanup; }
        if (field(b, "nr_throttled") > 0 && field(b, "throttled_usec") > 0) { throttled = true; break; }
        tick();
    } while (now_ms() - start < 2000);
    int status;
    if (!throttled) { error = EPROTO; goto cleanup; }
    if (!write_file(dir, "cgroup.kill", "1") || !wait_bounded(worker, &status, 2000) || !wait_empty(dir, 1000)) { error = errno; goto cleanup; }
    stage = "actual memory.max OOM kill and memory.events";
    worker = worker_start(dir, memory_operation);
    if (worker < 0 || !wait_bounded(worker, &status, 3500)) { error = errno; goto cleanup; }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL || !wait_empty(dir, 1000) ||
        !read_file(dir, "memory.events", b, sizeof(b)) || field(b, "oom_kill") < 1 || field(b, "max") < 1) { error = EPROTO; goto cleanup; }
    stage = "detached double-fork kill, populated=0 and descendant reaping";
    if (!set_limit(dir, "pids.max", "32\n") || pipe2(ready, O_CLOEXEC) < 0) { error = errno; goto cleanup; }
    lifecycle_ready = ready[1]; worker = worker_start(dir, detached_operation);
    if (worker < 0) { error = errno; goto cleanup; }
    close(ready[1]); ready[1] = -1;
    struct pollfd p = {.fd = ready[0], .events = POLLIN}; char byte;
    if (poll(&p, 1, 1500) != 1 || read(ready[0], &byte, 1) != 1 || byte != 'R') { error = EPROTO; goto cleanup; }
    if (!read_file(dir, "pids.current", b, sizeof(b)) || strtol(b, NULL, 10) < 2) { error = EPROTO; goto cleanup; }
    if (!write_file(dir, "cgroup.kill", "1") || !wait_empty(dir, 2000)) { error = errno; goto cleanup; }
    int reaped;
    if (reap_all(&reaped) < 0 || reaped != 2) { error = EPROTO; goto cleanup; }
cleanup:
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    /* The supervising parent owns directory removal. Workers also carry
     * independent alarms for failure-path disposal. */
    if (!write_file(dir, "cgroup.kill", "1") && !error) { error = errno; stage = "cleanup cgroup.kill"; }
    if (!wait_empty(dir, 3000) && !error) { error = errno; stage = "cleanup populated=0"; }
    int remaining;
    if (reap_all(&remaining) < 0 && !error) { error = errno; stage = "cleanup child reap"; }
    if (close(dir) < 0 && !error) { error = errno; stage = "cleanup cgroup descriptor"; }
    if (error) return fail(r, error, stage);
    snprintf(r->detail, sizeof(r->detail), "cpu/memory/pids delegated; exact limits; fork denial, CPU throttle, OOM kill; gated placement; detached kill; populated=0; all reaped");
    return 0;
}
static int create_fixture(struct result *r) {
    const char *tmp = getenv("TMPDIR");
    if (!tmp || tmp[0] != '/') return fail(r, EINVAL, "absolute operator TMPDIR required");
    if (snprintf(scratch, sizeof(scratch), "%s/hearthrun-doctor-XXXXXX", tmp) >= (int)sizeof(scratch)) return fail(r, ENAMETOOLONG, "TMPDIR too long");
    if (!mkdtemp(scratch)) return fail(r, errno, "scratch creation");
    scratch_owned = true;
    scratch_fd = open(scratch, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (scratch_fd < 0) return fail(r, errno, "scratch directory descriptor");
    if (mkdirat(scratch_fd, "allow", 0700) < 0) return fail(r, errno, "scratch subdirectory");
    if (mkdirat(scratch_fd, "allow/other", 0700) < 0) return fail(r, errno, "scratch REFER target directory");
    const char *files[] = {"allow/file", "deny"};
    for (size_t i = 0; i < 2; i++) {
        int fd = openat(scratch_fd, files[i], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) return fail(r, errno, "scratch file creation");
        bool ok = write_all(fd, "x", 1); int e = errno;
        if (close(fd) < 0 && ok) return fail(r, errno, "scratch file close");
        if (!ok) return fail(r, e, "scratch file write");
    }
    if (symlinkat("allow/file", scratch_fd, "link") < 0) return fail(r, errno, "scratch symlink");
    snprintf(r->detail, sizeof(r->detail), "owner-only scratch; two one-byte files"); return 0;
}
static void cleanup_fixture(struct result *r) {
    if (scratch_fd >= 0) {
        const char *files[] = {"link", "allow/same-link", "allow/other/cross-link", "allow/file", "deny"};
        for (size_t i = 0; i < 5; i++) if (unlinkat(scratch_fd, files[i], 0) < 0 && errno != ENOENT) fail(r, errno, "scratch file cleanup");
        if (unlinkat(scratch_fd, "allow/other", AT_REMOVEDIR) < 0 && errno != ENOENT) fail(r, errno, "scratch REFER directory cleanup");
        if (unlinkat(scratch_fd, "allow", AT_REMOVEDIR) < 0 && errno != ENOENT) fail(r, errno, "scratch subdirectory cleanup");
        if (close(scratch_fd) < 0) fail(r, errno, "scratch descriptor close");
    }
    if (scratch_owned && rmdir(scratch) < 0) fail(r, errno, "scratch directory cleanup");
    if (!r->error) snprintf(r->detail, sizeof(r->detail), "scratch and disposable cgroup removed");
}
static void json_string(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
        else if (c < 32 || c >= 127) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}
int main(int argc, char **argv) {
    const char *root = getenv("HEARTHRUN_CGROUP_ROOT"); bool args_ok = argc == 1;
    if (argc == 3 && !strcmp(argv[1], "--cgroup-root")) { root = argv[2]; args_ok = true; }
    signal(SIGPIPE, SIG_IGN); signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    const char *names[] = {"operator_configuration", "linux_x86_64_kernel_6_6", "disposable_scratch", "namespaces_minimal_root", "landlock_application_denial", "seccomp_arch_x32_default_deny", "pidfd_signal_reap", "close_range", "openat2_resolution", "delegated_cgroup_operations", "disposable_cleanup", "launcher_identity"};
    enum { FEATURE_COUNT = sizeof(names) / sizeof(names[0]) };
    struct result results[FEATURE_COUNT] = {{0}};
    if (!args_ok) fail(&results[0], EINVAL, "usage: hearthrun-probe [--cgroup-root TRUSTED_JOBS_PARENT]");
    else snprintf(results[0].detail, sizeof(results[0].detail), "TMPDIR and cgroup root are trusted operator configuration, never client paths");
    int groups = getgroups(0, NULL);
    if (groups < 0) fail(&results[11], errno, "read inherited supplementary groups");
    else if (getuid() == 0 || getuid() != geteuid() || getgid() != getegid() || groups != 0)
        fail(&results[11], EPERM, "launcher requires ordinary non-root IDs and no supplementary groups");
    else snprintf(results[11].detail, sizeof(results[11].detail), "unprivileged launcher identity; no supplementary groups");
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0)
        fail(&results[0], errno, "disable core writes and enable disposable descendant reaping");
    struct utsname uts; unsigned major = 0, minor = 0;
    if (uname(&uts) < 0 || strcmp(uts.sysname, "Linux") || strcmp(uts.machine, "x86_64") ||
        sscanf(uts.release, "%u.%u", &major, &minor) != 2 || major < 6 || (major == 6 && minor < 6))
        fail(&results[1], ENOTSUP, "Linux x86_64 kernel >=6.6 required");
    else snprintf(results[1].detail, sizeof(results[1].detail), "Linux x86_64 kernel >=6.6 observed");
    landlock_abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    int landlock_error = landlock_abi < 0 ? errno : 0;
    bool ready = !results[0].error && !results[1].error && !create_fixture(&results[2]);
    if (!ready && !results[2].error) fail(&results[2], ECANCELED, "configuration/platform prerequisite failed");
    if (root && root[0] == '/' && args_ok) {
        cgroup_parent = open(root, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (cgroup_parent < 0) fail(&results[9], errno, "trusted cgroup root open failed");
    } else if (root && root[0]) fail(&results[9], EINVAL, "trusted cgroup root must be absolute");
    snprintf(cgroup_leaf, sizeof(cgroup_leaf), "hearthrun-doctor-%ld-%lld", (long)getpid(), (long long)now_ms());
    int (*probes[])(struct result *) = {probe_namespaces, probe_landlock, probe_seccomp, probe_pidfd, probe_close_range, probe_openat2, probe_cgroup};
    for (size_t i = 0; i < 7; i++) {
        size_t index = i + 3;
        if (results[index].error) continue;
        if (!ready || interrupted) fail(&results[index], ECANCELED, "probe prerequisites failed or interrupted");
        else if (index != 9 || prepare_cgroup(&results[index]) == 0) {
            if (interrupted) fail(&results[index], ECANCELED, "interrupted before probe worker");
            else results[index] = run_probe(probes[i]);
        }
    }
    /* An interrupted probe can leave its own unique leaf. Never inspect or
     * kill any unrelated child under the trusted jobs parent. */
    if (cgroup_fd >= 0) {
        if (!write_file(cgroup_fd, "cgroup.kill", "1") || !wait_empty(cgroup_fd, 6000))
            fail(&results[10], errno, "residual cgroup kill/empty failed");
        if (close(cgroup_fd) < 0) fail(&results[10], errno, "residual cgroup close failed");
    }
    if (cgroup_owned && !results[10].error && unlinkat(cgroup_parent, cgroup_leaf, AT_REMOVEDIR) < 0)
        fail(&results[10], errno, "residual cgroup removal failed");
    if (cgroup_parent >= 0 && close(cgroup_parent) < 0) fail(&results[10], errno, "cgroup parent close failed");
    int adopted;
    if (reap_all(&adopted) < 0) fail(&results[10], errno, "adopted disposable descendant reaping failed");
    cleanup_fixture(&results[10]);
    if (interrupted && !results[0].error)
        fail(&results[0], ECANCELED, "doctor interrupted");
    bool compatible = true;
    for (size_t i = 0; i < FEATURE_COUNT; i++) if (results[i].error) compatible = false;
    printf("{\n  \"schema_version\":2,\n  \"probe_scope\":\"disposable operational host capabilities; not full-launch containment\",\n  \"landlock_abi\":%ld,\n  \"landlock_errno\":%d,\n  \"features\":{\n", landlock_abi, landlock_error);
    for (size_t i = 0; i < FEATURE_COUNT; i++) {
        printf("    \"%s\":{\"passed\":%s,\"errno\":%d,\"detail\":", names[i], results[i].error ? "false" : "true", results[i].error);
        json_string(results[i].detail); printf("}%s\n", i + 1 == FEATURE_COUNT ? "" : ",");
    }
    printf("  },\n  \"full_launch_policy_exercised\":false,\n  \"compatible\":%s,\n  \"status\":\"%s\"\n}\n", compatible ? "true" : "false", compatible ? "PASS" : "BLOCKED");
    return compatible ? 0 : 78;
}

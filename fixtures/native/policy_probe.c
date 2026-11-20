#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error "This reviewed fixture requires Linux x86-64 LP64"
#endif

/* Finite defensive policy checks. No listener, destination, executable or
 * syscall number is caller-controlled. Denied-operation probes use invalid
 * descriptors/commands or null operands and never target another process.
 * Socket probes only create an unconnected descriptor, closing it on failure
 * of the policy assertion. Run only as an approved static guest fixture. */
static int isolation(const char *canary, char **environment) {
    const char *expected[] = {"PATH=/bin", "LANG=C", "TZ=UTC"};
    for (size_t i = 0; i < 3; i++)
        if (!environment[i] || strcmp(environment[i], expected[i])) return 10;
    if (environment[3]) return 11;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_max > 1048576) return 12;
    for (rlim_t fd = 3; fd < limit.rlim_max; fd++) {
        errno = 0;
        if (fcntl((int)fd, F_GETFD) != -1 || errno != EBADF) return 13;
    }
    struct stat info;
    const char *absent[] = {"/proc", "/dev"};
    for (size_t i = 0; i < 2; i++) {
        errno = 0;
        if (syscall(SYS_newfstatat, AT_FDCWD, absent[i], &info, AT_SYMLINK_NOFOLLOW) != -1 || errno != ENOENT) return 14;
    }
    int fd = openat(AT_FDCWD, canary, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { close(fd); return 15; }
    if (errno != ENOENT && errno != EACCES) return 16;
    fd = openat(AT_FDCWD, "/in/probe.txt", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd >= 0) { close(fd); return 17; }
    if (errno != EACCES && errno != EROFS) return 18;
    fd = openat(AT_FDCWD, "/in/probe.txt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 19;
    char data[128];
    ssize_t size = read(fd, data, sizeof(data));
    if (close(fd) || size <= 0 || size >= (ssize_t)sizeof(data)) return 20;
    fd = openat(AT_FDCWD, "/out/approved.txt", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 21;
    int failed = write(fd, data, (size_t)size) != size;
    if (close(fd) || failed) return 22;
    return printf("isolation-ok fd_ceiling=%llu\n", (unsigned long long)limit.rlim_max) < 0 ? 23 : 0;
}

static int denied(const char *name, long result, int observed) {
    if (printf("%s result=%ld errno=%d\n", name, result, observed) < 0) return 30;
    return result == -1 && observed == EPERM ? 0 : 31;
}

static int sockets(void) {
    const int families[] = {AF_UNIX, AF_INET, AF_INET6};
    const char *names[] = {"unix", "ipv4", "ipv6"};
    for (size_t i = 0; i < 3; i++) {
        errno = 0;
        long fd = syscall(SYS_socket, families[i], SOCK_STREAM | SOCK_CLOEXEC, 0);
        int observed = errno;
        if (fd >= 0) close((int)fd);
        int status = denied(names[i], fd, observed);
        if (status) return status;
    }
    return 0;
}

static int operations(void) {
    int status;
#define DENIED(name, ...) do { errno = 0; long result = syscall(__VA_ARGS__); \
    int observed = errno; status = denied(name, result, observed); if (status) return status; } while (0)
    DENIED("connect", SYS_connect, -1, NULL, 0);
    DENIED("ptrace", SYS_ptrace, -1L, -1L, NULL, NULL);
    DENIED("bpf", SYS_bpf, -1, NULL, 0);
    DENIED("mount", SYS_mount, NULL, NULL, NULL, ~0UL, NULL);
    DENIED("keyctl", SYS_keyctl, -1L, 0L, 0L, 0L, 0L);
    DENIED("io_uring_setup", SYS_io_uring_setup, 0, NULL);
    DENIED("setns", SYS_setns, -1, 0);
#undef DENIED
    return 0;
}

int main(int argc, char **argv, char **environment) {
    if (argc == 3 && !strcmp(argv[1], "isolation") && argv[2][0] == '/')
        return isolation(argv[2], environment);
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "sockets")) return sockets();
    if (!strcmp(argv[1], "operations")) return operations();
    if (!strcmp(argv[1], "x32")) {
        const char marker[] = "before-x32-getpid\n";
        if (write(STDOUT_FILENO, marker, sizeof(marker) - 1) != (ssize_t)(sizeof(marker) - 1)) return 40;
        /* Benign identity query: correct policy kills before dispatch. */
        (void)syscall(UINT32_C(0x40000000) | SYS_getpid);
        return 41;
    }
    return 2;
}

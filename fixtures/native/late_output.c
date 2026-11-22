#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Synthetic output only: one child, two <=160-byte files inside /out, and
 * <500 ms lifetime. The leader deliberately exits before its writer child.
 * Nothing here probes host paths, changes protections, or escapes a sandbox. */
static int delay(unsigned milliseconds) {
    struct timespec left = {.tv_sec = milliseconds / 1000,
                           .tv_nsec = (long)(milliseconds % 1000) * 1000000L};
    while (nanosleep(&left, &left)) {
        if (errno != EINTR) return -1;
    }
    return 0;
}

static int number(const char *text, unsigned low, unsigned high, unsigned *value) {
    char *end;
    if (!*text) return -1;
    for (const char *at = text; *at; at++) if (*at < '0' || *at > '9') return -1;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || *end || parsed < low || parsed > high) return -1;
    *value = (unsigned)parsed;
    return 0;
}

static int output(const char *path, const char *phase, unsigned token) {
    char bytes[160];
    int count = snprintf(bytes, sizeof(bytes), "HearthRun synthetic late output v1 %u %s\n", token, phase);
    if (count <= 0 || (size_t)count >= sizeof(bytes)) return -1;
    int fd = openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t written = write(fd, bytes, (size_t)count);
    int synced = fsync(fd);
    int closed = close(fd);
    return written == count && !synced && !closed ? 0 : -1;
}

int main(int argc, char **argv) {
    unsigned token, first, tail;
    if (argc != 4 || number(argv[1], 0, 2147483647U, &token) ||
        number(argv[2], 160, 220, &first) || number(argv[3], 80, 120, &tail)) return 2;
    if (output("/out/final.bin", "initial", token)) return 10;
    pid_t writer = fork();
    if (writer < 0) return 11;
    if (writer == 0) {
        if (delay(first) || output("/out/candidate.bin", "replacement", token)) _exit(12);
        /* The reviewed policy permits renameat2, not legacy rename syscalls. */
        if (syscall(SYS_renameat2, AT_FDCWD, "/out/candidate.bin",
                    AT_FDCWD, "/out/final.bin", 0)) _exit(13);
        if (delay(tail)) _exit(14);
        _exit(0);
    }
    /* Keep both processes visible long enough for an actual cgroup sample. */
    if (delay(120)) return 15;
    return 0;
}

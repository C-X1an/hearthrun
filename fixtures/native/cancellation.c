#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Approved local synthetic B-03 workloads only. No caller-selected paths,
 * commands, sizes or network operations. Maximum lifetime is eight seconds,
 * maximum descendants two (one short-lived). The output loop is paced for
 * a cancellation observation before the runtime's per-stream cap.
 * The retained /out marker FD lets the host prove actual fixture readiness
 * through /proc/PID/fd without reading guest paths or changing the sandbox. */
static int64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) _exit(90);
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

static int pause_ms(long milliseconds) {
    struct timespec delay = {.tv_sec = milliseconds / 1000,
                             .tv_nsec = (milliseconds % 1000) * 1000000};
    while (nanosleep(&delay, &delay)) if (errno != EINTR) return 91;
    return 0;
}

static int send_bytes(int fd, const char *data, size_t size, int64_t end) {
    while (size) {
        if (now_ns() >= end) return 92;
        ssize_t count = write(fd, data, size);
        if (count > 0) { data += count; size -= (size_t)count; }
        else if (count < 0 && errno == EINTR) continue;
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (pause_ms(1)) return 93;
        } else return 94;
    }
    return 0;
}

static int marker(const char *path) {
    /* Intentionally retained until exit: descriptor presence is readiness. */
    return openat(AT_FDCWD, path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
}

static int hold(int64_t end) {
    while (now_ns() < end) if (pause_ms(5)) return 95;
    return 0;
}

static int detached(int64_t end) {
    int channel[2];
    if (pipe(channel)) return 20;
    pid_t child = fork();
    if (child < 0) { close(channel[0]); close(channel[1]); return 21; }
    if (!child) {
        close(channel[0]);
        if (setsid() < 0) _exit(22);
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(23);
        if (grandchild) { close(channel[1]); _exit(0); }
        int ready = marker("/out/b03-ready-detached");
        if (ready < 0) _exit(24);
        if (send_bytes(channel[1], "R", 1, end)) _exit(25);
        close(channel[1]);
        int code = hold(end);
        if (close(ready)) code = 26;
        _exit(code);
    }
    close(channel[1]);
    int flags = fcntl(channel[0], F_GETFL);
    if (flags < 0 || fcntl(channel[0], F_SETFL, flags | O_NONBLOCK)) return 27;
    char byte = 0;
    for (;;) {
        if (now_ns() >= end) { close(channel[0]); return 28; }
        ssize_t count = read(channel[0], &byte, 1);
        if (count == 1) break;
        if (count == 0 || (count < 0 && errno != EINTR && errno != EAGAIN)) {
            close(channel[0]); return 29;
        }
        if (pause_ms(1)) { close(channel[0]); return 30; }
    }
    close(channel[0]);
    int status;
    pid_t reaped;
    do { reaped = waitpid(child, &status, WNOHANG); if (!reaped && pause_ms(1)) return 31; }
    while (!reaped && now_ns() < end);
    if (byte != 'R' || reaped != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 32;
    return hold(end);
}

int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "spin") && strcmp(argv[1], "detached") && strcmp(argv[1], "output"))) return 2;
    const int64_t end = now_ns() + INT64_C(8000000000);
    for (int fd = STDOUT_FILENO; fd <= STDERR_FILENO; fd++) {
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return 3;
    }
    if (!strcmp(argv[1], "detached")) return detached(end);
    int ready;
    if (!strcmp(argv[1], "spin")) {
        ready = marker("/out/b03-ready-spin");
        if (ready < 0) return 4;
        volatile uint64_t value = 1;
        while (now_ns() < end)
            for (unsigned int index = 0; index < 65536; index++)
                value = value * UINT64_C(6364136223846793005) + 1;
    } else {
        char block[4096];
        memset(block, 'B', sizeof(block));
        block[sizeof(block) - 1] = '\n';
        /* Prime each stream, then continue writing through cancellation.
         * The cadence leaves the supervisor's automatic stream-limit stop
         * separate from a caller cancellation. */
        for (unsigned int index = 0; index < 32; index++)
            for (int fd = STDOUT_FILENO; fd <= STDERR_FILENO; fd++)
                if (send_bytes(fd, block, sizeof(block), end)) return 5;
        ready = marker("/out/b03-ready-output");
        if (ready < 0) return 6;
        for (unsigned int index = 0; index < 8192 && now_ns() < end; index++) {
            for (int fd = STDOUT_FILENO; fd <= STDERR_FILENO; fd++)
                if (send_bytes(fd, block, sizeof(block), end)) return 8;
            if (pause_ms(4)) return 7;
        }
    }
    return close(ready) ? 9 : 0;
}

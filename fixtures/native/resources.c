#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Approved synthetic resource probes, with fixed ceilings even outside a job:
 * at most 36 direct children, 288 MiB touched, two CPU workers for 16 seconds,
 * or 3 MiB per output stream. No paths, commands or sizes come from the caller.
 * Only use the resource modes on an explicitly prepared bounded test host. */
static double now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) _exit(90);
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static int delay(double seconds) {
    double end = now() + seconds;
    while (now() < end) {
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        if (nanosleep(&pause, NULL) && errno != EINTR) return 91;
    }
    return 0;
}

/* Nonblocking writes ensure a stopped reader cannot turn a finite byte bound
 * into an unlimited wait. Every caller also supplies a fixed time deadline. */
static int send_bytes(int fd, const char *data, size_t length, double end) {
    while (length) {
        if (now() >= end) return 92;
        ssize_t count = write(fd, data, length);
        if (count > 0) { data += count; length -= (size_t)count; continue; }
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (delay(0.01)) return 93;
            continue;
        }
        return 94;
    }
    return 0;
}

static int reap(pid_t *children, size_t count) {
    int failed = 0;
    for (size_t index = 0; index < count; index++) {
        int status;
        pid_t result;
        do { result = waitpid(children[index], &status, 0); } while (result < 0 && errno == EINTR);
        if (result != children[index] || !WIFEXITED(status) || WEXITSTATUS(status)) failed = 95;
    }
    return failed;
}

static int pids_case(void) {
    pid_t children[36];
    size_t count = 0;
    int rejected = 0;
    for (size_t index = 0; index < 36; index++) {
        pid_t child = fork();
        if (child < 0) { rejected = errno; break; }
        if (!child) _exit(delay(4.0));
        children[count++] = child;
    }
    int status = reap(children, count);
    char result[128];
    int size = snprintf(result, sizeof(result), "pids children=%zu rejection_errno=%d\n", count, rejected);
    if (size <= 0 || (size_t)size >= sizeof(result)) return 96;
    int written = send_bytes(STDOUT_FILENO, result, (size_t)size, now() + 2.0);
    if (status || written) return status ? status : written;
    /* Direct execution without a cgroup is finite and reports no false denial. */
    return rejected && rejected != EAGAIN ? 21 : 0;
}

static int memory_case(void) {
    const size_t size = 288U * 1024U * 1024U;
    volatile unsigned char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return 30;
    double end = now() + 8.0;
    for (size_t offset = 0; offset < size; offset += 4096) {
        memory[offset] = (unsigned char)(offset / 4096);
        /* Slow the bounded progression enough for independent kernel samples.
         * A private leaf with oom.group=1 normally kills this entire job. */
        if (!(offset % (1024U * 1024U))) {
            if (now() >= end || delay(0.005)) { munmap((void *)memory, size); return 31; }
        }
    }
    int paused = delay(0.25);
    if (munmap((void *)memory, size)) return 32;
    return paused;
}

static void burn(double end) {
    volatile uint64_t value = 1;
    while (now() < end) {
        for (unsigned int index = 0; index < 65536; index++) value = value * UINT64_C(6364136223846793005) + 1;
    }
}

static int cpu_case(void) {
    double end = now() + 16.0;
    pid_t child = fork();
    if (child < 0) return 40;
    if (!child) { burn(end); _exit(0); }
    burn(end);
    return reap(&child, 1);
}

static int streams_case(void) {
    char block[4096];
    const char hostile[] = "synthetic <script>fixture</script> & \033[31mred\033[0m\n";
    for (size_t index = 0; index < sizeof(block); index++) block[index] = hostile[index % (sizeof(hostile) - 1)];
    double end = now() + 10.0;
    for (size_t index = 0; index < 768; index++) {
        int result = send_bytes(STDOUT_FILENO, block, sizeof(block), end);
        if (!result) result = send_bytes(STDERR_FILENO, block, sizeof(block), end);
        if (result) return result;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    for (int fd = STDOUT_FILENO; fd <= STDERR_FILENO; fd++) {
        int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return 3;
    }
    if (!strcmp(argv[1], "standard")) {
        const char output[] = "synthetic resource fixture: standard success\n";
        const char error[] = "synthetic resource fixture: diagnostic\n";
        int result = send_bytes(STDOUT_FILENO, output, sizeof(output) - 1, now() + 2.0);
        if (!result) result = send_bytes(STDERR_FILENO, error, sizeof(error) - 1, now() + 2.0);
        return result;
    }
    if (strcmp(argv[1], "pids") && strcmp(argv[1], "memory") && strcmp(argv[1], "cpu") && strcmp(argv[1], "streams")) return 2;
    /* Let the observer bind controls before the finite resource operation. */
    if (delay(1.0)) return 4;
    if (!strcmp(argv[1], "pids")) return pids_case();
    if (!strcmp(argv[1], "memory")) return memory_case();
    if (!strcmp(argv[1], "cpu")) return cpu_case();
    return streams_case();
}

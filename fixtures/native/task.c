#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A single, fixed educational input shape: one integer value per line.
 * All modes are synthetic, bounded fixtures for an owned local test host. */
static const char *whitespace(const char *at) {
    while (isspace((unsigned char)*at)) at++;
    return at;
}

static bool value_from_line(const char *line, int64_t *value) {
    const char *at = whitespace(line);
    if (*at++ != '{') return false;
    at = whitespace(at);
    if (strncmp(at, "\"value\"", 7)) return false;
    at = whitespace(at + 7);
    if (*at++ != ':') return false;
    at = whitespace(at);
    const char *digit = *at == '-' ? at + 1 : at;
    if (!isdigit((unsigned char)*digit) || (*digit == '0' && isdigit((unsigned char)digit[1]))) return false;
    char *end;
    errno = 0;
    intmax_t parsed = strtoimax(at, &end, 10);
    if (errno || parsed < INT64_MIN || parsed > INT64_MAX) return false;
    at = whitespace(end);
    if (*at++ != '}' || *whitespace(at)) return false;
    *value = (int64_t)parsed;
    return true;
}

static int summarize(void) {
    int source = openat(AT_FDCWD, "/in/data.ndjson", O_RDONLY | O_CLOEXEC);
    FILE *input = source < 0 ? NULL : fdopen(source, "rb");
    if (!input) { fprintf(stderr, "opening staged input: errno %d\n", errno); return 10; }
    uint64_t count = 0;
    int64_t sum = 0;
    for (;;) {
        char line[128];
        size_t used = 0;
        int byte;
        while ((byte = fgetc(input)) != EOF && byte != '\n') {
            if (byte == 0 || used + 1 == sizeof(line)) return 11;
            line[used++] = (char)byte;
        }
        if (byte == EOF && !used) break;
        line[used] = '\0';
        int64_t value;
        if (!value_from_line(line, &value) ||
            (value > 0 && sum > INT64_MAX - value) ||
            (value < 0 && sum < INT64_MIN - value)) return 12;
        count++;
        sum += value;
    }
    if (ferror(input) || fclose(input)) return 13;
    int target = openat(AT_FDCWD, "/out/summary.json", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    FILE *output = target < 0 ? NULL : fdopen(target, "wb");
    if (!output) { fprintf(stderr, "opening output: errno %d\n", errno); return 14; }
    bool written = fprintf(output, "{\"count\":%" PRIu64 ",\"sum\":%" PRId64 "}\n", count, sum) > 0;
    if (fclose(output) || !written) return 15;
    return 0;
}

static int verify_isolation(const char *canary, char **environment) {
    const char *expected[] = {"PATH=/bin", "LANG=C", "TZ=UTC"};
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
        if (!environment[i] || strcmp(environment[i], expected[i])) return 20;
    }
    if (environment[3]) return 20;
    for (int fd = 3; fd < 128; fd++) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 21;
    }
    int descriptor = openat(AT_FDCWD, canary, O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) { close(descriptor); return 22; }
    if (errno != ENOENT && errno != EACCES) return 23;
    descriptor = openat(AT_FDCWD, "/in/data.ndjson", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (descriptor >= 0) { close(descriptor); return 24; }
    if (errno != EACCES && errno != EROFS) return 25;
    return puts("synthetic canary inaccessible, input read-only, environment and descriptors checked") < 0 ? 26 : 0;
}

static int hold_detached(void) {
    int pipefd[2];
    if (pipe(pipefd)) return 30;
    pid_t child = fork();
    if (child < 0) return 31;
    if (child == 0) {
        close(pipefd[0]);
        if (setsid() < 0) _exit(32);
        pid_t second = fork();
        if (second < 0) _exit(33);
        if (second > 0) _exit(0);
        if (write(pipefd[1], "R", 1) != 1) _exit(34);
        close(pipefd[1]);
        struct timespec delay = {.tv_sec = 8};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
        _exit(0);
    }
    close(pipefd[1]);
    char ch;
    if (read(pipefd[0], &ch, 1) != 1 || ch != 'R') return 35;
    close(pipefd[0]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 36;
    if (puts("detached-ready") < 0 || fflush(stdout)) return 37;
    struct timespec delay = {.tv_sec = 8};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
    return 0;
}

int main(int argc, char **argv, char **environment) {
    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "summary"))) return summarize();
    if (argc == 2 && !strcmp(argv[1], "empty")) return 0;
    if (argc == 3 && !strcmp(argv[1], "check")) return verify_isolation(argv[2], environment);
    if (argc == 2 && !strcmp(argv[1], "hold")) return hold_detached();
    return 2;
}

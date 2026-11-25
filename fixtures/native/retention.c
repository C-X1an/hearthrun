#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Five fixed outputs. A fixed 1,500 ms window allows the observer to confirm
 * four concurrent jobs as the retained request catalog grows. Each invocation
 * writes at most 1 MiB and creates no children. Static build only.
 * Byte specification: payload[i] = (17*i + 29*variant + 3) modulo 256. */
int main(int argc, char **argv) {
    static const char *const modes[] = {"v0", "v1", "v2", "v3", "v4"};
    static const size_t sizes[] = {4096, 16384, 65536, 262144, 1048576};
    if (argc != 2) return 2;
    size_t variant = 5;
    for (size_t index = 0; index < 5; index++) {
        if (!strcmp(argv[1], modes[index])) variant = index;
    }
    if (variant == 5) return 2;
    struct timespec pause = {.tv_sec = 1, .tv_nsec = 500000000};
    while (nanosleep(&pause, &pause)) {
        if (errno != EINTR) return 3;
    }
    int target = openat(AT_FDCWD, "/out/payload.bin", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (target < 0) return 4;
    unsigned char block[4096];
    for (size_t offset = 0; offset < sizes[variant]; offset += sizeof(block)) {
        for (size_t index = 0; index < sizeof(block); index++) {
            block[index] = (uint8_t)(17U * (offset + index) + 29U * variant + 3U);
        }
        size_t sent = 0;
        while (sent < sizeof(block)) {
            ssize_t written = write(target, block + sent, sizeof(block) - sent);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { close(target); return 5; }
            sent += (size_t)written;
        }
    }
    return close(target) ? 6 : 0;
}

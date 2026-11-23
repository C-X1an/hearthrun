#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Fixed approved Linux x86-64 fixture; not an arbitrary execution interface.
 * The trusted launcher supplies immutable /in and private /out mounts.
 * C does bounded framing and libc I/O only. Rust parses every integer and
 * performs checked count/sum/min/max aggregation without a Rust std runtime.
 * No argument/environment selects a path, command, syscall or network target.
 */
#if !defined(__linux__) || !defined(__x86_64__)
#error "this approved fixture requires Linux x86-64"
#endif

#define MAX_INPUT_BYTES ((size_t)16 * 1024 * 1024)
#define MAX_RECORD_BYTES 127
#define READ_BUFFER_BYTES 8192

struct aggregate_state {
    uint64_t count;
    int64_t sum;
    int64_t min;
    int64_t max;
};

struct input_record {
    uint8_t bytes[MAX_RECORD_BYTES];
    uint8_t length;
};

struct aggregate_result {
    struct aggregate_state state;
    uint32_t error;
    uint32_t reserved;
};

_Static_assert(sizeof(struct aggregate_state) == 32, "Rust state ABI mismatch");
_Static_assert(_Alignof(struct aggregate_state) == 8, "Rust state alignment mismatch");
_Static_assert(offsetof(struct aggregate_state, sum) == 8, "Rust sum offset mismatch");
_Static_assert(offsetof(struct aggregate_state, min) == 16, "Rust min offset mismatch");
_Static_assert(offsetof(struct aggregate_state, max) == 24, "Rust max offset mismatch");
_Static_assert(sizeof(struct input_record) == 128, "Rust record ABI mismatch");
_Static_assert(offsetof(struct input_record, length) == 127, "Rust record offset mismatch");
_Static_assert(sizeof(struct aggregate_result) == 40, "Rust result ABI mismatch");
_Static_assert(offsetof(struct aggregate_result, error) == 32, "Rust error offset mismatch");
_Static_assert(offsetof(struct aggregate_result, reserved) == 36, "Rust reserved offset mismatch");

extern struct aggregate_result hearthrun_aggregate_record(
    struct aggregate_state state, struct input_record record);

static int aggregate_record(struct aggregate_state *state, struct input_record record) {
    /* All 128 bytes are initialized before crossing the by-value ABI. There
     * are no foreign pointers or ownership/lifetime assumptions in Rust. */
    struct aggregate_result result = hearthrun_aggregate_record(*state, record);
    if (result.reserved != 0) return 25;
    switch (result.error) {
        case 0:
            *state = result.state;
            return 0;
        case 13: case 14: case 15: case 16: case 17:
            return (int)result.error;
        default:
            return 25;
    }
}

static int read_summary(int source, struct aggregate_state *state) {
    uint8_t buffer[READ_BUFFER_BYTES];
    struct input_record record = {{0}, 0};
    size_t total = 0;
    for (;;) {
        /* At the byte ceiling, read at most one extra byte to detect excess. */
        size_t available = MAX_INPUT_BYTES - total + 1;
        if (available > sizeof(buffer)) available = sizeof(buffer);
        ssize_t amount = read(source, buffer, available);
        if (amount < 0) {
            if (errno == EINTR) continue;
            return 11;
        }
        if (amount == 0) break;
        if ((size_t)amount > MAX_INPUT_BYTES - total) return 12;
        total += (size_t)amount;
        for (size_t index = 0; index < (size_t)amount; index++) {
            if (buffer[index] == '\n') {
                int code = aggregate_record(state, record);
                if (code != 0) return code;
                record.length = 0;
            } else {
                if (record.length == MAX_RECORD_BYTES) return 13;
                record.bytes[record.length++] = buffer[index];
            }
        }
    }
    if (record.length != 0) {
        int code = aggregate_record(state, record);
        if (code != 0) return code;
    }
    return state->count == 0 ? 18 : 0;
}

static int write_all(int target, const char *bytes, size_t length) {
    while (length != 0) {
        ssize_t amount = write(target, bytes, length);
        if (amount < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (amount == 0) return -1;
        bytes += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

static int summarize(void) {
    int source = openat(AT_FDCWD, "/in/data.ndjson", O_RDONLY | O_CLOEXEC);
    if (source < 0) return 10;
    struct aggregate_state state = {0, 0, 0, 0};
    int code = read_summary(source, &state);
    /* Do not retry close after EINTR: descriptor state may already have changed. */
    if (close(source) < 0) return 19;
    if (code != 0) return code;

    /* Maximal u64 count and three signed i64 values fit comfortably in 160 B. */
    char artifact[160];
    int length = snprintf(artifact, sizeof(artifact),
        "{\"count\":%" PRIu64 ",\"sum\":%" PRId64 ",\"min\":%" PRId64 ",\"max\":%" PRId64 "}\n",
        state.count, state.sum, state.min, state.max);
    if (length < 0 || (size_t)length >= sizeof(artifact)) return 24;
    int target = openat(AT_FDCWD, "/out/summary.json",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (target < 0) return 20;
    code = write_all(target, artifact, (size_t)length) == 0 ? 0 : 21;
    if (close(target) < 0) return 22;
    /* Checked unbuffered writes are complete. The supervisor owns fsync and
     * durable publication after quiescence; this guest adds no policy calls. */
    return code;
}

static const char *error_message(int code) {
    switch (code) {
        case 2: return "aggregate: expected exactly the summary mode\n";
        case 10: return "aggregate: opening approved staged input failed\n";
        case 11: return "aggregate: reading staged input failed\n";
        case 12: return "aggregate: input exceeds 16777216 bytes\n";
        case 13: return "aggregate: record exceeds 127 bytes excluding LF\n";
        case 14: return "aggregate: record is not the approved JSON integer shape\n";
        case 15: return "aggregate: record integer is outside signed 64-bit range\n";
        case 16: return "aggregate: running sum exceeds signed 64-bit range\n";
        case 17: return "aggregate: record count exceeds unsigned 64-bit range\n";
        case 18: return "aggregate: input contains no records\n";
        case 19: return "aggregate: closing staged input failed\n";
        case 20: return "aggregate: creating new summary artifact failed\n";
        case 21: return "aggregate: writing summary artifact failed\n";
        case 22: return "aggregate: closing summary artifact failed\n";
        case 24: return "aggregate: formatting bounded summary artifact failed\n";
        default: return "aggregate: Rust bridge ABI contract failed\n";
    }
}

int main(int argc, char **argv) {
    int code = argc == 2 && strcmp(argv[1], "summary") == 0 ? summarize() : 2;
    if (code != 0) {
        const char *message = error_message(code);
        if (write_all(STDERR_FILENO, message, strlen(message)) != 0) return 23;
    }
    return code;
}

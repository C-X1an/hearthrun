#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error "This reviewed fixture requires Linux x86-64 LP64"
#endif

/* Approved finite guest only. All IP destinations are hardcoded loopback.
 * Three unprivileged ports and one owned pathname come from the test harness.
 * No resolver, arbitrary IP, scan, response parser or inherited FD is used.
 * A policy failure can send at most one fixed benign marker per transport. */
static int port(const char *text, uint16_t *out) {
    char *end;
    if (!text[0] || text[0] == '0' || strlen(text) > 5) return -1;
    for (const char *p = text; *p; p++) if (*p < '0' || *p > '9') return -1;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || *end || value < 1024 || value > 65535) return -1;
    *out = (uint16_t)value;
    return 0;
}

static int probe(const char *name, int family, int type,
                 const struct sockaddr *address, socklen_t size,
                 const unsigned char *payload, size_t payload_size) {
    errno = 0;
    int fd = socket(family, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int socket_error = errno;
    if (fd < 0)
        return printf("%s socket=-1 socket_errno=%d connect=NA connect_errno=NA send=NA send_errno=NA\n",
                      name, socket_error) < 0 ? 10 : 0;
    errno = 0;
    int connected = connect(fd, address, size);
    int connect_error = errno;
    int output;
    if (connected == 0) {
        errno = 0;
        ssize_t sent = send(fd, payload, payload_size, MSG_NOSIGNAL | MSG_DONTWAIT);
        int send_error = errno;
        output = printf("%s socket=%d socket_errno=%d connect=%d connect_errno=%d send=%zd send_errno=%d\n",
                        name, fd, socket_error, connected, connect_error, sent, send_error);
    } else {
        output = printf("%s socket=%d socket_errno=%d connect=%d connect_errno=%d send=NA send_errno=NA\n",
                        name, fd, socket_error, connected, connect_error);
    }
    /* Refusal remains a measured observation. The harness, not this fixture,
     * decides whether it met the required policy and listener invariants. */
    int closed = close(fd);
    return output < 0 || closed ? 11 : 0;
}

int main(int argc, char **argv) {
    uint16_t ports[3];
    if (argc != 5) return 2;
    for (int i = 0; i < 3; i++) if (port(argv[i + 1], &ports[i])) return 2;
    struct sockaddr_un local = {0};
    const char *tail = strrchr(argv[4], '/');
    if (argv[4][0] != '/' || !tail || strcmp(tail, "/network.sock") ||
        strlen(argv[4]) >= sizeof(local.sun_path)) return 2;
    local.sun_family = AF_UNIX;
    memcpy(local.sun_path, argv[4], strlen(argv[4]) + 1);
    struct sockaddr_in ip[3] = {{0}};
    for (int i = 0; i < 3; i++) {
        ip[i].sin_family = AF_INET;
        ip[i].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ip[i].sin_port = htons(ports[i]);
    }
    const unsigned char tcp[] = "hearthrun-guest-tcp\n";
    const unsigned char udp[] = "hearthrun-guest-udp\n";
    const unsigned char unix_marker[] = "hearthrun-guest-unix\n";
    const unsigned char dns[] = {
        0x48, 0x52, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 'h', 'e', 'a', 'r', 't', 'h', 'r', 'u', 'n',
        0x07, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0x00, 0x00, 0x01, 0x00, 0x01
    };
    int status = probe("tcp", AF_INET, SOCK_STREAM, (const struct sockaddr *)&ip[0], sizeof(ip[0]), tcp, sizeof(tcp) - 1);
    if (status) return status;
    status = probe("udp", AF_INET, SOCK_DGRAM, (const struct sockaddr *)&ip[1], sizeof(ip[1]), udp, sizeof(udp) - 1);
    if (status) return status;
    status = probe("unix", AF_UNIX, SOCK_STREAM, (const struct sockaddr *)&local,
                   (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(local.sun_path) + 1), unix_marker, sizeof(unix_marker) - 1);
    if (status) return status;
    status = probe("dns", AF_INET, SOCK_DGRAM, (const struct sockaddr *)&ip[2], sizeof(ip[2]), dns, sizeof(dns));
    return status ? status : (fflush(stdout) ? 12 : 0);
}

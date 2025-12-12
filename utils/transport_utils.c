#include "utils.h"

static int send_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        int rc = send(fd, (const char *)(buf + sent), (int)(len - sent), 0);
#else
        ssize_t rc = send(fd, buf + sent, len - sent, 0);
#endif
        if (rc <= 0) return -1;
        sent += (size_t)rc;
    }
    return 0;
}

static int recv_all(int fd, unsigned char *buf, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
#ifdef _WIN32
        int rc = recv(fd, (char *)(buf + recvd), (int)(len - recvd), 0);
#else
        ssize_t rc = recv(fd, buf + recvd, len - recvd, 0);
#endif
        if (rc <= 0) return -1;
        recvd += (size_t)rc;
    }
    return 0;
}

int send_framed_packet(int fd, const unsigned char *payload, size_t len) {
    uint32_t nlen = htonl((uint32_t)len);
    unsigned char header[4];
    memcpy(header, &nlen, sizeof(header));
    if (send_all(fd, header, sizeof(header)) != 0) return -1;
    if (send_all(fd, payload, len) != 0) return -1;
    return 0;
}

int recv_framed_packet(int fd, unsigned char **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    unsigned char header[4];
    if (recv_all(fd, header, sizeof(header)) != 0) return -1;
    uint32_t nlen_net;
    memcpy(&nlen_net, header, sizeof(header));
    uint32_t nlen = ntohl(nlen_net);
    if (nlen == 0 || nlen > NETWORK_MESSAGE_BUFFER_SIZE * 4) {
        return -1;
    }
    unsigned char *buf = malloc(nlen);
    if (!buf) return -1;
    if (recv_all(fd, buf, nlen) != 0) {
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = nlen;
    return 0;
}

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
    if (nlen == 0 || nlen > (FILE_TRANSFER_MAX_BYTES * 2)) {
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

int send_protocol_packet(int fd, PacketHeader *hdr, const unsigned char *payload, size_t payload_len, const unsigned char *aes_key) {
    if (!hdr || !aes_key || !payload) return -1;

    hdr->payloadLength = (uint32_t)payload_len;
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;

    size_t plain_len = sizeof(PacketHeader) + payload_len;
    unsigned char *plain = malloc(plain_len);
    if (!plain) return -1;
    memcpy(plain, hdr, sizeof(PacketHeader));
    memcpy(plain + sizeof(PacketHeader), payload, payload_len);

    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    if (aes_encrypt_bytes(plain, plain_len, aes_key, iv, &cipher, &cipher_len) != 0) {
        free(plain);
        return -1;
    }
    free(plain);

    size_t packet_len = sizeof(iv) + cipher_len;
    unsigned char *packet = malloc(packet_len);
    if (!packet) { free(cipher); return -1; }
    memcpy(packet, iv, sizeof(iv));
    memcpy(packet + sizeof(iv), cipher, cipher_len);
    free(cipher);

    int rc = send_framed_packet(fd, packet, packet_len);
    free(packet);
    return rc;
}

int recv_protocol_packet(int fd, PacketHeader *hdr_out, unsigned char **payload_out, size_t *payload_len_out, const unsigned char *aes_key) {
    if (!hdr_out || !payload_out || !payload_len_out || !aes_key) return -1;

    unsigned char *framed = NULL;
    size_t framed_len = 0;
    if (recv_framed_packet(fd, &framed, &framed_len) != 0) return -1;
    if (framed_len < 16) { free(framed); return -1; }

    unsigned char iv[16];
    memcpy(iv, framed, sizeof(iv));
    unsigned char *cipher = framed + sizeof(iv);
    size_t cipher_len = framed_len - sizeof(iv);

    unsigned char *plain = NULL;
    size_t plain_len = 0;
    int rc = aes_decrypt_bytes(cipher, cipher_len, aes_key, iv, &plain, &plain_len);
    free(framed);
    if (rc != 0 || plain_len < sizeof(PacketHeader)) {
        if (plain) free(plain);
        return -1;
    }

    memcpy(hdr_out, plain, sizeof(PacketHeader));
    size_t payload_len = plain_len - sizeof(PacketHeader);
    unsigned char *payload = malloc(payload_len + 1);
    if (!payload) { free(plain); return -1; }
    memcpy(payload, plain + sizeof(PacketHeader), payload_len);
    payload[payload_len] = '\0';
    free(plain);

    *payload_out = payload;
    *payload_len_out = payload_len;
    return 0;
}

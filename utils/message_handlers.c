#include "utils.h"
#include <time.h>

#ifdef _WIN32
#define SLEEP_MS(ms) Sleep(ms)
#else
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

void *sendMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char message[NETWORK_MESSAGE_BUFFER_SIZE];

    while (!clientD->aes_key) {
        SLEEP_MS(10);
    }

    uint32_t msg_id = 1;
    while (fgets(message, sizeof(message), stdin)) {
        message[strcspn(message, "\n")] = '\0';
        if (message[0] == '\0') continue;

        PacketHeader hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.msgType = MSG_PUBLISH_TEXT;
        hdr.version = 1;
        hdr.messageId = msg_id++;
        hdr.timestamp = (uint64_t)time(NULL);
        strncpy(hdr.sender, clientD->clientName, MAX_USERNAME_LEN - 1);
        strncpy(hdr.topic, MESSAGE_TYPE_BROADCAST, MAX_TOPIC_LEN - 1);
        hdr.flags = 0x0;

        size_t payload_len = strlen(message);
        if (send_protocol_packet(clientD->clientSocketFD, &hdr, (unsigned char *)message, payload_len, clientD->aes_key) != 0) {
            LOG_ERROR("Send failed");
            break;
        }
    }

    return NULL;
}

void *receiveMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;

    if (perform_client_handshake(clientD) != 0) {
        LOG_ERROR("Handshake failed");
        return NULL;
    }

    while (1) {
        PacketHeader hdr;
        unsigned char *payload = NULL;
        size_t payload_len = 0;
        if (recv_protocol_packet(clientD->clientSocketFD, &hdr, &payload, &payload_len, clientD->aes_key) != 0) {
            LOG_ERROR("Receive failed");
            free(payload);
            break;
        }

        if (hdr.msgType == MSG_PUBLISH_TEXT) {
            const char *sender = hdr.sender[0] ? hdr.sender : "Unknown";
            LOG_INFO("[MSG] %s: %s", sender, (char *)payload);
        } else if (hdr.msgType == MSG_PUBLISH_FILE) {
            char *payload_str = (char *)payload;
            char *sep = strchr(payload_str, '|');
            if (sep) {
                *sep = '\0';
                const char *filename = payload_str;
                const char *b64 = sep + 1;
                size_t decoded_len = 0;
                unsigned char *decoded = base64_to_bytes_decode(b64, &decoded_len);
                if (decoded) {
                    char save_path[512];
                    snprintf(save_path, sizeof(save_path), "received_%s", filename);
                    FILE *f = fopen(save_path, "wb");
                    if (f) {
                        fwrite(decoded, 1, decoded_len, f);
                        fclose(f);
                        LOG_INFO("[FILE] %s saved to %s", filename, save_path);
                    } else {
                        LOG_ERROR("Failed to save file %s", filename);
                    }
                    free(decoded);
                }
            }
        } else if (hdr.msgType == MSG_ACK) {
            LOG_INFO("[ACK] topic=%s payload=%s", hdr.topic, payload ? (char *)payload : "");
        }

        free(payload);
    }

    return NULL;
}

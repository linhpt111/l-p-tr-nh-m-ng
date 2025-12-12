#include "utils.h"

void *sendMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char message[NETWORK_MESSAGE_BUFFER_SIZE];

    while (1) {
        fgets(message, sizeof(message), stdin);
        message[strcspn(message, "\n")] = 0;

        if (send(clientD->clientSocketFD, message, strlen(message), 0) == -1) {
            LOG_ERROR("Send failed");
            break;
        }
    }

    return NULL;
}

void *receiveMessages(void *clientD_ptr) {
    clientDetails *clientD = (clientDetails *)clientD_ptr;
    char buffer[NETWORK_MESSAGE_BUFFER_SIZE];
    ssize_t bytesReceived;

    while (1) {
        bytesReceived = recv(clientD->clientSocketFD, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived < 0) {
            LOG_ERROR("Receive failed");
            break;
        } else if (bytesReceived == 0) {
            LOG_INFO("Server disconnected.\n");
            break;
        }

        buffer[bytesReceived] = '\0';
    }

    return NULL;
}

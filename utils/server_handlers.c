#include "utils.h"

static const unsigned char STATIC_AES_KEY[32] = {
        0xC9, 0xED, 0x07, 0xED, 0x15, 0x98, 0x0C, 0x3D,
        0x27, 0xC9, 0x84, 0xEC, 0x11, 0x67, 0xA2, 0xAC,
        0xC8, 0x0A, 0x30, 0xC2, 0xD9, 0xB1, 0x1F, 0xC1,
        0x94, 0x4E, 0xC2, 0xB8, 0xB2, 0xC5, 0x58, 0x2E
    };

static void broadcast_groups(serverDetails *serverD);

static int send_encrypted_packet(int fd, const char *payload) {
    if (fd < 0 || !payload) return -1;
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        return -1;
    }

    char* ciphertext = encrypt_with_aes(payload, STATIC_AES_KEY, iv);
    if (!ciphertext) return -1;

    size_t packet_len = sizeof(iv) + strlen(ciphertext);
    unsigned char* packet = malloc(packet_len);
    if (!packet) {
        free(ciphertext);
        return -1;
    }
    memcpy(packet, iv, sizeof(iv));
    memcpy(packet + sizeof(iv), ciphertext, strlen(ciphertext));

    int rc = send(fd, packet, packet_len, 0);
    free(packet);
    free(ciphertext);
    return rc;
}

static int lookup_fd_by_username(serverDetails *serverD, const char *username) {
    if (!serverD || !username) return -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (serverD->clientFDStore[i] != -1 && serverD->clientNames[i] && strcmp(serverD->clientNames[i], username) == 0) {
            return serverD->clientFDStore[i];
        }
    }
    return -1;
}

static void remove_client(serverDetails *serverD, int clientFd, const char *username) {
    if (!serverD) return;
    for (int x = 0; x < MAX_CLIENTS; x++) {
        if (serverD->clientFDStore[x] == clientFd) {
            serverD->clientFDStore[x] = -1;
            if (serverD->client_aes_keyStore[x]) {
                free(serverD->client_aes_keyStore[x]);
                serverD->client_aes_keyStore[x] = NULL;
            }
            if (serverD->clientNames[x]) {
                free(serverD->clientNames[x]);
                serverD->clientNames[x] = NULL;
            }
            break;
        }
    }
    if (username) {
        db_set_user_offline(&serverD->db, username);
        db_group_leave_all(&serverD->db, username);
    }
    for (int g = 0; g < MAX_GROUPS; g++) {
        for (int i = 0; i < serverD->groupCounts[g]; i++) {
            if (serverD->groupMembers[g][i] == clientFd) {
                serverD->groupMembers[g][i] = -1;
            }
        }
        while (serverD->groupCounts[g] > 0 && serverD->groupMembers[g][serverD->groupCounts[g]-1] == -1) {
            serverD->groupCounts[g]--;
        }
    }
    broadcast_presence(serverD);
}

void *handleOtherOperationsOnSeperateThread(void *serverD) {
    struct sockaddr clientAddress;
    socklen_t addr_len = sizeof(clientAddress);
    int server_fd = ((serverDetails *)serverD)->serverSocketFD;

    while (1) {
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) {
            LOG_ERROR("Failed to allocate memory for client fd");
            continue;
        }

        *client_fd = accept(server_fd, &clientAddress, &addr_len);
        if (*client_fd < 0) {
            free(client_fd);
            LOG_ERROR("Accept failed");
            continue;
        }
        LOG_SUCCESS("Client connected.\n");

        pthread_t threadId;
        HNAC *param = (HNAC *)malloc(sizeof(HNAC));
        if (!param) {
            LOG_ERROR("Failed to allocate memory for HNAC structure");
            close(*client_fd);
            continue;
        }
        param->clientSocketFD = client_fd;
        param->serverD = (serverDetails *)serverD;
        if (pthread_create(&threadId, NULL, handleNewlyAcceptedClient, param) != 0) {
            LOG_ERROR("Failed to create the thread to handle new client operation");
            close(*client_fd);
            free(client_fd);
        }
    }
}

void *handleNewlyAcceptedClient(void *param) {
    char receivedMessage[NETWORK_MESSAGE_BUFFER_SIZE];
    const char *basic_message = "secured Connection to Server is established Successfully\n";
    int clientFd = *(((HNAC *)param)->clientSocketFD);
    serverDetails *serverD = ((HNAC *)param)->serverD;

    if (send(clientFd, serverD->keys->public_key, strlen(serverD->keys->public_key), 0) == -1) {
        LOG_ERROR("sending == [ public-security-key ] == failed");
        close(clientFd);
        return NULL;
    } else {
        LOG_SUCCESS("sent == [ public-security-key ] == of size [ %ld ]", strlen(serverD->keys->public_key));
    }

    char encrypted_aes_key_str[NETWORK_MESSAGE_BUFFER_SIZE];
    if (recv(clientFd, encrypted_aes_key_str, sizeof(encrypted_aes_key_str), 0) == -1) {
        LOG_ERROR("Failed to recieve AES Key\n");
        close(clientFd);
        return NULL;
    }

    unsigned char* decrypted_aes_key = decrypt_aes_key(serverD->keys->private_key, encrypted_aes_key_str);

    if (send(clientFd, basic_message, strlen(basic_message), 0) == -1) {
        LOG_ERROR("sending welcome message failed");
        close(clientFd);
        return NULL;
    } else {
        g_print("Welcome message sent\n");
    }

    char clientUsername[CLIENT_NAME_INPUT_MAX];
    if (recv(clientFd, clientUsername, sizeof(clientUsername), 0) == -1) {
        LOG_ERROR("Failed to recieve client details\n");
        close(clientFd);
        return NULL;
    }

    int x;
    int *clientFDStore = serverD->clientFDStore;

    for (x = 0; x < MAX_CLIENTS; x++) {
        if (clientFDStore[x] == -1) {
            clientFDStore[x] = clientFd;
            unsigned char* key_ptr = (unsigned char *)malloc(AES_KEY_SIZE * sizeof(unsigned char *));
            if (!key_ptr) {
                LOG_ERROR("Memory allocation failed for client AES key");
                break;
            }
            serverD->client_aes_keyStore[x] = key_ptr;
            memcpy(key_ptr, decrypted_aes_key, AES_KEY_SIZE);

            serverD->clientNames[x] = strdup(clientUsername);

            break;
        }
    }

    if (x == MAX_CLIENTS) {
        LOG_INFO("Client FD Store is full; consider increasing MAX_CLIENTS");
    }

    db_set_user_online(&serverD->db, clientUsername);
    broadcast_presence(serverD);

    while (1) {
        ssize_t bytesReceived = recv(clientFd, receivedMessage, sizeof(receivedMessage) - 1, 0);

        if (bytesReceived < 0) {
            LOG_ERROR("recv failed");
            break;
        } else if (bytesReceived == 0) {
            LOG_INFO("Client disconnected.");
            break;
        }
        receivedMessage[bytesReceived] = '\0';

        unsigned char iv[16];
        memcpy(iv, receivedMessage, 16);

        char* ciphertext = (char*)(receivedMessage + 16);

        char* plaintext = decrypt_with_aes(ciphertext, decrypted_aes_key, iv);
        if (!plaintext) {
            continue;
        }

        char *saveptr = NULL;
        char *type = strtok_r(plaintext, "|", &saveptr);
        if (type && strcmp(type, "MSG") == 0) {
            char *channel = strtok_r(NULL, "|", &saveptr);
            char *sender = strtok_r(NULL, "|", &saveptr);
            char *body = strtok_r(NULL, "", &saveptr);

            sender = clientUsername; // enforce real sender
            int delivered = 0;
            LOG_INFO("[MSG IN] channel=%s sender=%s body=%s", channel ? channel : "(null)", sender, body ? body : "");

            const char *receiver = NULL;
            char receiver_buf[CLIENT_NAME_INPUT_MAX] = {0};
            if (channel && strncmp(channel, MESSAGE_TYPE_DM_PREFIX, strlen(MESSAGE_TYPE_DM_PREFIX)) == 0) {
                strncpy(receiver_buf, channel + strlen(MESSAGE_TYPE_DM_PREFIX), sizeof(receiver_buf) - 1);
                receiver = receiver_buf;
            } else if (channel && strncmp(channel, MESSAGE_TYPE_GROUP_PREFIX, strlen(MESSAGE_TYPE_GROUP_PREFIX)) == 0) {
                strncpy(receiver_buf, channel + strlen(MESSAGE_TYPE_GROUP_PREFIX), sizeof(receiver_buf) - 1);
                receiver = receiver_buf;
            } else {
                receiver = MESSAGE_TYPE_BROADCAST;
            }

            db_save_message(&serverD->db, sender, receiver, body ? body : "");

            if (receiver && strcmp(receiver, MESSAGE_TYPE_BROADCAST) != 0) {
                if (channel && strncmp(channel, MESSAGE_TYPE_GROUP_PREFIX, strlen(MESSAGE_TYPE_GROUP_PREFIX)) == 0) {
                    int groupIndex = -1;
                    for (int g = 0; g < MAX_GROUPS; g++) {
                        if (serverD->groupNames[g] && strcmp(serverD->groupNames[g], receiver) == 0) {
                            groupIndex = g;
                            break;
                        }
                    }
                    if (groupIndex != -1) {
                        char payload[NETWORK_MESSAGE_BUFFER_SIZE];
                        snprintf(payload, sizeof(payload), "MSG|GROUP:%s|%s|%s", receiver, sender, body ? body : "");
                        for (int i = 0; i < serverD->groupCounts[groupIndex]; i++) {
                            int target_fd = serverD->groupMembers[groupIndex][i];
                            if (target_fd != -1) {
                                send_encrypted_packet(target_fd, payload);
                                delivered++;
                            }
                        }
                        LOG_INFO("[GROUP %s] %s -> members delivered=%d", receiver, sender, delivered);
                    } else {
                        LOG_INFO("[GROUP %s] %s -> no such group", receiver, sender);
                    }
                } else {
                    int target_fd = lookup_fd_by_username(serverD, receiver);
                    if (target_fd != -1) {
                        char payload[NETWORK_MESSAGE_BUFFER_SIZE];
                        snprintf(payload, sizeof(payload), "MSG|DM:%s|%s|%s", receiver, sender, body ? body : "");
                        send_encrypted_packet(target_fd, payload);
                        delivered = 1;
                    } else {
                        LOG_INFO("User %s not online; skipping DM delivery", receiver);
                    }
                }
            } else {
                char payload[NETWORK_MESSAGE_BUFFER_SIZE];
                snprintf(payload, sizeof(payload), "MSG|ALL|%s|%s", sender, body ? body : "");
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clientFDStore[i] != clientFd && clientFDStore[i] != -1) {
                        send_encrypted_packet(clientFDStore[i], payload);
                        delivered++;
                    }
                }
                LOG_INFO("[BROADCAST] %s delivered=%d", sender, delivered);
            }
        } else if (type && strcmp(type, "GROUP") == 0) {
            char *action = strtok_r(NULL, "|", &saveptr);
            char *groupName = strtok_r(NULL, "|", &saveptr);
            if (!action || !groupName) {
                free(plaintext);
                continue;
            }
            int groupIndex = -1;
            for (int g = 0; g < MAX_GROUPS; g++) {
                if (serverD->groupNames[g] && strcmp(serverD->groupNames[g], groupName) == 0) {
                    groupIndex = g;
                    break;
                }
            }
            if (strcmp(action, "CREATE") == 0 && groupIndex == -1) {
                for (int g = 0; g < MAX_GROUPS; g++) {
                    if (!serverD->groupNames[g]) {
                        serverD->groupNames[g] = strdup(groupName);
                        serverD->groupCounts[g] = 0;
                        groupIndex = g;
                        LOG_INFO("Group created: %s by %s", groupName, clientUsername);
                        break;
                    }
                }
            }
            if (groupIndex != -1 && serverD->groupCounts[groupIndex] < MAX_CLIENTS) {
                int already = 0;
                int empty_slot = -1;
                for (int i = 0; i < serverD->groupCounts[groupIndex]; i++) {
                    if (serverD->groupMembers[groupIndex][i] == clientFd) {
                        already = 1;
                        break;
                    }
                    if (serverD->groupMembers[groupIndex][i] == -1 && empty_slot == -1) {
                        empty_slot = i;
                    }
                }
                if (!already) {
                    if (empty_slot != -1) {
                        serverD->groupMembers[groupIndex][empty_slot] = clientFd;
                        if (empty_slot + 1 > serverD->groupCounts[groupIndex]) {
                            serverD->groupCounts[groupIndex] = empty_slot + 1;
                        }
                    } else {
                        serverD->groupMembers[groupIndex][serverD->groupCounts[groupIndex]++] = clientFd;
                    }
                    db_group_join(&serverD->db, clientUsername, groupName);
                    LOG_INFO("Group join: %s joined %s (size=%d)", clientUsername, groupName, serverD->groupCounts[groupIndex]);
                }
            }
            broadcast_groups(serverD);
        }

        free(plaintext);

    }

    remove_client(serverD, clientFd, clientUsername);
    close(clientFd);
    free(((HNAC *)param)->clientSocketFD);
    return NULL;
}

void broadcastMessage(char *clientUsername, char *receivedMessage, int currentClientFD, int *clientFDStore, unsigned char **client_aes_keyStore) {
    UNUSED(clientUsername);
    UNUSED(receivedMessage);
    UNUSED(currentClientFD);
    UNUSED(clientFDStore);
    UNUSED(client_aes_keyStore);
}

void broadcast_presence(serverDetails *serverD) {
    if (!serverD) return;

    char user_list[NETWORK_MESSAGE_BUFFER_SIZE] = {0};
    size_t offset = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (serverD->clientFDStore[i] != -1 && serverD->clientNames[i]) {
            size_t name_len = strlen(serverD->clientNames[i]);
            if (offset + name_len + 2 >= sizeof(user_list)) break;
            memcpy(user_list + offset, serverD->clientNames[i], name_len);
            offset += name_len;
            user_list[offset++] = ',';
        }
    }
    if (offset > 0 && user_list[offset - 1] == ',') {
        user_list[offset - 1] = '\0';
    }

    char payload[NETWORK_MESSAGE_BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "PRESENCE|%s", user_list);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (serverD->clientFDStore[i] != -1) {
            send_encrypted_packet(serverD->clientFDStore[i], payload);
        }
    }
    broadcast_groups(serverD);
}

static void broadcast_groups(serverDetails *serverD) {
    char group_list[NETWORK_MESSAGE_BUFFER_SIZE] = {0};
    size_t offset = 0;
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (serverD->groupNames[i]) {
            size_t name_len = strlen(serverD->groupNames[i]);
            if (offset + name_len + 2 >= sizeof(group_list)) break;
            memcpy(group_list + offset, serverD->groupNames[i], name_len);
            offset += name_len;
            group_list[offset++] = ',';
        }
    }
    if (offset > 0 && group_list[offset - 1] == ',') {
        group_list[offset - 1] = '\0';
    }

    char payload[NETWORK_MESSAGE_BUFFER_SIZE];
    snprintf(payload, sizeof(payload), "GROUPS|%s", group_list);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (serverD->clientFDStore[i] != -1) {
            send_encrypted_packet(serverD->clientFDStore[i], payload);
        }
    }
}

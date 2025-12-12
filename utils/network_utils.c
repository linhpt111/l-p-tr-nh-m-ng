#include "utils.h"

int get_socket() {
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr *get_address(int *ui_port, const char* ui_ip) {
    char ip[IP_INPUT_MAX];
    char port_str[PORT_INPUT_MAX];
    int port;

    if (!(ui_ip && ui_port)) {
        printf("Input server IP Address: ");

        if (fgets(ip, IP_INPUT_MAX, stdin) != NULL) {
            size_t inputLen = strlen(ip);

            if ((inputLen > 0) && (ip[inputLen - 1] == '\n')) {
                ip[inputLen - 1] = '\0';
            } else if (inputLen == 0) {
                LOG_ERROR("IP Address buffer is empty\n");
                return NULL;
            } else {
                LOG_INFO("Please Input a correct IP Address\n");
                return NULL;
            }
        } else {
            LOG_ERROR("Error reading IP Address");
            return NULL;
        }

        printf("Input server PORT no: ");

        if (fgets(port_str, PORT_INPUT_MAX, stdin) != NULL) {
            size_t inputLen = strlen(port_str);
            char* endptr;

            if ((inputLen > 0) && (port_str[inputLen - 1] == '\n')) {
                port_str[inputLen - 1] = '\0';

                errno = 0;

                port = (int)strtol(port_str, &endptr, 10);
                if (*endptr != '\0' && *endptr != '\n') {
                    LOG_ERROR("Please Input a correct PORT no. eg [ 2000 ]\n");
                    return NULL;
                }
            } else if (inputLen == 0) {
                LOG_INFO("PORT buffer is empty.\n");
            } else {
                LOG_ERROR("Please Input a correct PORT no.\n");
                return NULL;
            }
        } else {
            LOG_ERROR("Error reading the PORT no..");
            return NULL;
        }

        if (*ip)
            LOG_INFO("Generating Address for IP [ %s ] and PORT [ %d ]...\n\n", ip, port);
        else
            LOG_INFO("Generating Address for IP [ 0.0.0.0 ] and PORT [ %d ]...\n\n", port);
    } else {
        size_t i;
        for (i = 0; i < strlen(ui_ip); i++) {
            ip[i] = ui_ip[i];
        }
        ip[i] = '\0';
        port = *ui_port;
    }

    struct sockaddr_in *new_address = malloc(sizeof(struct sockaddr_in));
    new_address->sin_port = htons(port);
    new_address->sin_family = AF_INET;

    if (strlen(ip) == 0) {
        new_address->sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, ip, &new_address->sin_addr.s_addr);
    }

    return (struct sockaddr *)(new_address);
}

char *get_client_name(const char* ui_client_name) {
    char* clientName = malloc(sizeof(char) * CLIENT_NAME_INPUT_MAX);

    if (!ui_client_name) {
        printf("Input your USERNAME name (with %d max character): ", CLIENT_NAME_INPUT_MAX - 2);

        if (fgets(clientName, CLIENT_NAME_INPUT_MAX, stdin) != NULL) {
            size_t inputLen = strlen(clientName);

            if ((inputLen > 0) && (clientName[inputLen - 1] == '\n')) {
                clientName[inputLen - 1] = '\0';
            } else if (inputLen == 0) {
                LOG_ERROR("USERNAME buffer is empty.\n");
                free(clientName);
                return NULL;
            } else {
                printf("%ld\n", inputLen);
                LOG_INFO("Please Input a valid name\n");
                free(clientName);
                return NULL;
            }
        } else {
            LOG_ERROR("Error reading the USERNAME..");
            free(clientName);
            return NULL;
        }
    } else {
        strcpy(clientName, ui_client_name);
    }
    return clientName;
}

int setupClient(clientDetails *clientD) {
    clientD->clientSocketFD = get_socket();
    if (clientD->clientSocketFD == -1) {
        LOG_ERROR(" [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }
    memset(clientD->active_target, 0, sizeof(clientD->active_target));
    clientD->active_target_is_group = FALSE;
    clientD->group_joined = FALSE;

    clientD->serverAddress = get_address(NULL, NULL);
    if (clientD->serverAddress == NULL) {
        LOG_ERROR("[ generating server address failed ]\n\n");
        return -1;
    }

    clientD->clientName = get_client_name(NULL);
    if (clientD->clientName == NULL) {
        LOG_ERROR(" [ getting USERNAME failed ]\n\n");
        return -1;
    }
    return 0;
}

int setupServer(serverDetails *serverD) {
    serverD->serverSocketFD = get_socket();
    if (serverD->serverSocketFD == -1) {
        LOG_ERROR(" [ creating Client Socket Process Failed ]\n\n");
        return -1;
    }

    serverD->serverAddress = get_address(NULL, NULL);
    if (serverD->serverAddress == NULL) {
        LOG_ERROR(" [ generating server address failed ]\n\n");
        return -1;
    }
    serverD->clientFDStore = (int *)malloc(sizeof(int) * MAX_CLIENTS);
    for (int x = 0; x < MAX_CLIENTS; x++) {
        serverD->clientFDStore[x] = -1;
        serverD->client_aes_keyStore[x] = NULL;
        serverD->clientNames[x] = NULL;
    }
    for (int g = 0; g < MAX_GROUPS; g++) {
        serverD->groupNames[g] = NULL;
        serverD->groupCounts[g] = 0;
        for (int m = 0; m < MAX_CLIENTS; m++) {
            serverD->groupMembers[g][m] = -1;
        }
    }
    return 0;
}

void cleanup(clientDetails *clientD) {
    if (clientD->clientSocketFD > 0) close(clientD->clientSocketFD);
    if (clientD->clientName) free(clientD->clientName);
    if (clientD->serverAddress) free(clientD->serverAddress);
}

int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

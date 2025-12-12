#include "server.h"


int main() {
    serverDetails serverD;
    SecurityKeys keys;
    char instruction[50];
    pthread_t threadId;

    if (set_workdir_to_project_root() != 0) {
        LOG_ERROR("Failed to set working directory to project root.");
        return EXIT_FAILURE;
    }

    // Step 1: Initialize and setup server
    if (setupServer(&serverD) == -1) {
        LOG_ERROR("Server setup failed.");
        return EXIT_FAILURE;
    }

    if (db_init(&serverD.db, DB_FILE_PATH) != 0) {
        LOG_ERROR("Database setup failed.");
        close(serverD.serverSocketFD);
        free(serverD.serverAddress);
        free(serverD.clientFDStore);
        return EXIT_FAILURE;
    }

    // Extract IP and Port information
    char ipStr[IP_INPUT_MAX];
    int port = ntohs(((struct sockaddr_in *)serverD.serverAddress)->sin_port);
    strcpy(ipStr, inet_ntoa(((struct sockaddr_in *)serverD.serverAddress)->sin_addr));
    LOG_INFO("Starting server on [ IP: %s ] [ PORT: %d ]", ipStr, port);

    // Step 2: Bind socket to the address
    if (bind(serverD.serverSocketFD, serverD.serverAddress, sizeof(*serverD.serverAddress)) < 0) {
        LOG_ERROR("Error binding socket: %s", strerror(errno));
        close(serverD.serverSocketFD);
        free(serverD.serverAddress);
        free(serverD.clientFDStore);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Socket successfully bound to [ IP: %s ] [ PORT: %d ]", ipStr, port);


    // Step 2+: manage RSA key pair generation and saving the keys to files if not exists
    manage_encryption_info(&keys);
    serverD.keys = &keys;


    // Step 3: Start listening on the socket
    if (listen(serverD.serverSocketFD, SERVER_BACKLOG) < 0) {
        LOG_ERROR("Error listening on socket: %s", strerror(errno));
        close(serverD.serverSocketFD);
        free(serverD.serverAddress);
        free(serverD.clientFDStore);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Server is now listening on [ IP: %s ] [ PORT: %d ]", ipStr, port);

    // Step 4: Create a separate thread for additional server operations
    // HOOOST param1 = {.clientFDStore = serverD.clientFDStore, .serverSocketFD = serverD}
    if (pthread_create(&threadId, NULL, handleOtherOperationsOnSeperateThread, &serverD) != 0) {
        LOG_ERROR("Failed to create the [ server operation thread ]: %s", strerror(errno));
        LOG_INFO("Shutting down server on [ IP: %s ] [ PORT: %d ]", ipStr, port);
        close(serverD.serverSocketFD);
        free(serverD.serverAddress);
        free(serverD.clientFDStore);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Server operation thread successfully created.");

    // Step 5: Command loop for server control
    strcpy(instruction, "keep_running");
    while (strcmp(instruction, "shutdown") != 0) {
        // printf("Enter command: ");
        if (scanf("%49s", instruction) == EOF) {
            LOG_ERROR("Input error encountered.");
            break;
        }
    }

    // Step 6: Shutdown server
    LOG_INFO("Shutting down server on [ IP: %s ] [ PORT: %d ]", ipStr, port);
    close(serverD.serverSocketFD);
    free(serverD.serverAddress);
    free(serverD.clientFDStore);
    db_close(&serverD.db);
    return EXIT_SUCCESS;
}
